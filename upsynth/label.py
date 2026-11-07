"""label: flows.parquet -> labeled.parquet, and the knowledge base -> PFD JSON

Rules from kb/apps.yaml, first hit wins: TLS/QUIC SNI, HTTP Host, DNS name, JA4, ASN, nDPI's label
(if ingest ran with --ndpi), port. Names use the longest matching domain suffix across all apps.
Every flow records where its label came from and a confidence.
"""

from __future__ import annotations

import fnmatch
import json
import re
from collections import Counter
from importlib import resources
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
import yaml

from .schemas import CONFIDENCE, LABELED_SCHEMA, AppRule, KnowledgeBase

UNKNOWN = "unknown"


def load_kb(path: str | Path | None = None) -> KnowledgeBase:
    if path:
        text = Path(path).read_text(encoding="utf-8")
    else:
        text = resources.files("upsynth").joinpath("kb/apps.yaml").read_text(encoding="utf-8")
    return KnowledgeBase.model_validate(yaml.safe_load(text))


class Matcher:
    def __init__(self, kb: KnowledgeBase):
        self.apps: dict[str, AppRule] = {a.name: a for a in kb.apps}
        self.suffix: dict[str, str] = {}
        self.globs: list[tuple[str, str]] = []
        self.regex: list[tuple[re.Pattern, str]] = []
        self.asn: dict[int, str] = {}
        self.ja4: dict[str, str] = {}
        self.ports: list[tuple[int, int, int, str, list[str]]] = []
        problems = []
        for a in kb.apps:
            for d in a.domains:
                d = d.lower().strip(".")
                if d.startswith("re:"):
                    self.regex.append((re.compile(d[3:]), a.name))
                elif any(c in d for c in "*?["):
                    self.globs.append((d, a.name))
                elif d in self.suffix and self.suffix[d] != a.name:
                    problems.append(f"domain {d} in both {self.suffix[d]} and {a.name}")
                else:
                    self.suffix[d] = a.name
            for n in a.asns:
                if n in self.asn and self.asn[n] != a.name:
                    problems.append(f"ASN {n} in both {self.asn[n]} and {a.name}")
                self.asn[n] = a.name
            for j in a.ja4:
                self.ja4[j] = a.name
            for p in a.ports:
                proto, _, rng = p.partition("/")
                lo, _, hi = rng.partition("-")
                self.ports.append((6 if proto == "tcp" else 17, int(lo), int(hi or lo), a.name, a.alpn))
        if problems:
            raise ValueError("knowledge base conflicts: " + "; ".join(problems))
        self.lower_names = {n.lower().replace("_", ""): n for n in self.apps}

    def by_name(self, name: str | None) -> str | None:
        if not name:
            return None
        name = name.lower().strip(".")
        # glob and regex rules are written for one app on a shared domain (a CDN), so they go first
        for g, app in self.globs:
            if fnmatch.fnmatch(name, g):
                return app
        for r, app in self.regex:
            if r.search(name):
                return app
        labels = name.split(".")
        for i in range(max(len(labels) - 1, 1)):
            hit = self.suffix.get(".".join(labels[i:]))
            if hit:
                return hit
        return None

    def by_port(self, proto: int, port: int, alpn: str | None) -> str | None:
        for pr, lo, hi, app, alpns in self.ports:
            if pr == proto and lo <= port <= hi and (not alpns or (alpn and any(x in alpn.split(",") for x in alpns))):
                return app
        return None

    def by_ndpi(self, name: str | None) -> str | None:
        if not name:
            return None
        for part in reversed(name.split(".")):  # nDPI writes "TLS.YouTube"
            hit = self.lower_names.get(part.lower().replace("_", ""))
            if hit:
                return hit
        return None

    def label(self, row: dict) -> tuple[str, str, str, float]:
        proto, port = row["proto"], row["server_port"]
        infra = self.by_port(proto, port, row.get("alpn")) if port in (53, 123, 853) else None
        if infra:
            return self._out(infra, "port")
        for src, value in (("sni", row.get("sni")), ("http_host", row.get("http_host")), ("dns", row.get("dns_name"))):
            app = self.by_name(value)
            if app:
                return self._out(app, src)
        if row.get("ja4") and row["ja4"] in self.ja4:
            return self._out(self.ja4[row["ja4"]], "ja4")
        if row.get("asn") is not None and row["asn"] in self.asn:
            return self._out(self.asn[row["asn"]], "asn")
        app = self.by_ndpi(row.get("ndpi_app"))
        if app:
            return self._out(app, "ndpi")
        app = self.by_port(proto, port, row.get("alpn"))
        if app:
            return self._out(app, "port")
        if row.get("ndpi_app"):
            return f"ndpi:{row['ndpi_app']}", "other", "ndpi", CONFIDENCE["ndpi"] * 0.6
        return UNKNOWN, "other", "none", 0.0

    def _out(self, app: str, src: str) -> tuple[str, str, str, float]:
        return app, self.apps[app].category, src, CONFIDENCE[src]


def run(flows: str | Path, out: str | Path, *, kb_path: str | Path | None = None, pfd: str | Path | None = None) -> dict:
    kb = load_kb(kb_path)
    m = Matcher(kb)
    table = pq.read_table(flows)
    cols = ["proto", "server_port", "alpn", "sni", "http_host", "dns_name", "ja4", "asn", "ndpi_app"]
    rows = table.select([c for c in cols if c in table.column_names]).to_pylist()
    labels = [m.label(r) for r in rows]
    apps, cats, srcs, confs = (list(x) for x in zip(*labels)) if labels else ([], [], [], [])
    for name, values, typ in (("app", apps, pa.string()), ("category", cats, pa.string()),
                              ("label_source", srcs, pa.string()), ("label_conf", confs, pa.float32())):
        if name in table.column_names:
            table = table.drop_columns([name])
        table = table.append_column(pa.field(name, typ), pa.array(values, typ))
    table = table.select(LABELED_SCHEMA.names).cast(LABELED_SCHEMA)
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    pq.write_table(table, out)
    unknown_names = Counter()
    for r, (app, *_rest) in zip(rows, labels):
        if app == UNKNOWN or app.startswith("ndpi:"):
            n = r.get("sni") or r.get("http_host") or r.get("dns_name")
            if n:
                unknown_names[n] += 1
    summary = {
        "input": str(flows),
        "output": str(out),
        "flows": len(rows),
        "kb_apps": len(kb.apps),
        "labeled": sum(1 for a in apps if a != UNKNOWN),
        "by_source": dict(Counter(srcs).most_common()),
        "by_app": dict(Counter(apps).most_common(30)),
        "unknown_names": dict(unknown_names.most_common(20)),
    }
    if pfd:
        summary["pfd"] = export_pfd(kb, pfd)
    return summary


def export_pfd(kb: KnowledgeBase, out: str | Path) -> dict:
    """Write the knowledge base as PFD data (TS 29.122 PfdManagement / TS 29.551 PfdContent).

    Each app becomes a PfdData keyed by its externalAppId. Domains go into one PFD with dnProtocol
    TLS_SNI (a name also covers its subdomains, written as "*.name"); ports become IPFilterRule flow
    descriptions toward the UE ("assigned"). ASN and JA4 rules have no PFD form and are left out.
    """
    datas = {}
    skipped = []
    for a in kb.apps:
        pfds = {}
        names = []
        for d in a.domains:
            if d.startswith("re:"):
                names.append(d[3:])
            elif any(c in d for c in "*?["):
                names.append(d)
            else:
                names += [d, f"*.{d}"]
        if names:
            pid = f"{a.name}-dn"
            pfds[pid] = {"pfdId": pid, "domainNames": names, "dnProtocol": "TLS_SNI"}
        flows = []
        for p in a.ports:
            proto, _, rng = p.partition("/")
            flows.append(f"permit out {6 if proto == 'tcp' else 17} from any {rng} to assigned")
        if flows:
            pid = f"{a.name}-fd"
            pfds[pid] = {"pfdId": pid, "flowDescriptions": flows}
        if pfds:
            datas[a.name] = {"externalAppId": a.name, "pfds": pfds}
        else:
            skipped.append(a.name)
    doc = {"pfdDatas": datas}
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out).write_text(json.dumps(doc, indent=2, ensure_ascii=False), encoding="utf-8")
    return {"output": str(out), "apps": len(datas), "skipped_no_pfd_form": skipped}
