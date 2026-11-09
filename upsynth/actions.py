"""Action layer: what a person does in an app (open a video, watch, scroll comments...) and which flows
each action opens.

Two ways to find actions in labeled flows:
- log: an action log (t_start, app, action[, ue]) recorded while someone, a script or an LLM agent
  operated the phone; each flow belongs to the action whose window contains its start.
- bursts: no log (e.g. operator traffic); flows of a UE are cut into bursts at pauses and the bursts
  are clustered into action types named <dominant app>/b<k>.

Either way the model keeps only distributions: per action the flow slots it opens (app, server name,
endpoint, probability, count, start offset) and how long people stay; between actions the transitions.
"""

from __future__ import annotations

import csv
import math
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

from .schemas import SERVICE_OF_CATEGORY, ActionModel, ActionSig, FlowSlot, Script

DWELL_EDGES = [0.0] + list(np.logspace(-1, 4, 26))  # s
OFFSET_EDGES = [0.0] + list(np.logspace(-2, 3, 26))  # s
COUNT_EDGES = list(range(1, 21)) + [30, 50, 100, 1000]


def _hist(values, edges, scale):
    from .profile import hist  # profile imports this module

    return hist(values, edges, scale)


def _cat(values):
    from .profile import categorical

    return categorical(values)


def read_log(path: str | Path) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    out = []
    for r in rows:
        name = r["action"] if "/" in r["action"] else f"{r.get('app') or 'app'}/{r['action']}"
        out.append({"t": float(r["t_start"]), "name": name, "ue": r.get("ue") or None,
                    "service": r.get("service") or None})
    return sorted(out, key=lambda x: x["t"])


def _slot_key(r: dict) -> tuple[str, str | None, str]:
    named = r["label_source"] in ("sni", "http_host", "dns")
    domain = (r.get("sni") or r.get("http_host") or r.get("dns_name")) if named and r["_app"] != "other" else None
    return r.get("_slot_app") or r["_app"], domain, f"{r['_transport']}/{r['server_port']}"


def instances_from_log(rows: list[dict], log: list[dict]) -> list[dict]:
    """Action instances with their flows. rows: non-DNS labeled flows with _app/_transport set."""
    by_ue = defaultdict(list)
    for e in log:
        by_ue[e["ue"]].append(e)
    inst = []
    for ue, events in by_ue.items():
        flows = sorted((r for r in rows if ue is None or r["ue"] == ue), key=lambda r: r["start"])
        starts = [e["t"] for e in events]
        for i, e in enumerate(events):
            end = starts[i + 1] if i + 1 < len(events) else math.inf
            inst.append({"ue": ue, "name": e["name"], "t": e["t"], "service": e.get("service"),
                         "dwell": (end - e["t"]) if end != math.inf else None,
                         "flows": [r for r in flows if e["t"] <= r["start"] < end]})
    return inst


def instances_from_bursts(rows: list[dict], gap: float = 1.5, k: int = 6, seed: int = 0) -> list[dict]:
    from .profile import kmeans

    bursts = []
    by_ue = defaultdict(list)
    for r in rows:
        by_ue[r["ue"]].append(r)
    for ue, fl in by_ue.items():
        fl.sort(key=lambda r: r["start"])
        cur = [fl[0]]
        for r in fl[1:]:
            if r["start"] - cur[-1]["start"] > gap:
                bursts.append({"ue": ue, "flows": cur})
                cur = [r]
            else:
                cur.append(r)
        bursts.append({"ue": ue, "flows": cur})
    if not bursts:
        return []
    apps = sorted({r["_app"] for b in bursts for r in b["flows"]})
    x = []
    for b in bursts:
        c = Counter(r["_app"] for r in b["flows"])
        n = len(b["flows"])
        x.append([math.log1p(n), math.log1p(sum(r["bytes_down"] for r in b["flows"])) / 4,
                  math.log1p(max(r["end"] for r in b["flows"]) - b["flows"][0]["start"])]
                 + [c[a] / n for a in apps])
    centers, labels = kmeans(np.asarray(x), min(k, len(bursts)), seed)
    dominant = {}
    for j in set(labels.tolist()):
        c = Counter(r["_app"] for b, lab in zip(bursts, labels) if lab == j for r in b["flows"])
        dominant[j] = c.most_common(1)[0][0]
    order = {j: n for n, j in enumerate(sorted(set(labels.tolist())), 1)}
    inst = []
    for ue in by_ue:
        seq = [(b, lab) for b, lab in zip(bursts, labels) if b["ue"] == ue]
        for i, (b, lab) in enumerate(seq):
            t = b["flows"][0]["start"]
            nxt = seq[i + 1][0]["flows"][0]["start"] if i + 1 < len(seq) else None
            by_cat = Counter()
            for r in b["flows"]:
                by_cat[SERVICE_OF_CATEGORY.get(r["category"], "other")] += r["bytes_down"]
            inst.append({"ue": ue, "name": f"{dominant[lab]}/b{order[lab]}", "t": t,
                         "dwell": (nxt - t) if nxt is not None else None, "flows": b["flows"],
                         "service": by_cat.most_common(1)[0][0]})
    return inst


def build_model(inst: list[dict], source: str, min_instances: int = 2) -> ActionModel | None:
    by_name = defaultdict(list)
    for i in inst:
        by_name[i["name"]].append(i)
    actions = []
    for name, group in sorted(by_name.items(), key=lambda kv: -len(kv[1])):
        if len(group) < min_instances:
            continue
        per_slot = defaultdict(list)  # slot -> [(instance index, count, offsets)]
        for idx, g in enumerate(group):
            c = defaultdict(list)
            for r in g["flows"]:
                c[_slot_key(r)].append(r["start"] - g["t"])
            for key, offs in c.items():
                per_slot[key].append((idx, len(offs), offs))
        slots = []
        for (app, domain, endpoint), seen in sorted(per_slot.items(), key=lambda kv: -len(kv[1])):
            slots.append(FlowSlot(
                app=app, domain=domain, endpoint=endpoint, p=round(len(seen) / len(group), 4),
                count=_hist([n for _, n, _ in seen], COUNT_EDGES, "linear"),
                offset=_hist([o for _, _, offs in seen for o in offs], OFFSET_EDGES, "log")))
        dwells = [g["dwell"] for g in group if g["dwell"] is not None]
        services = Counter(g.get("service") for g in group if g.get("service"))
        if not services:  # burst clusters: the service of the category carrying most bytes
            for g in group:
                for r in g["flows"]:
                    services[SERVICE_OF_CATEGORY.get(r["category"], "other")] += r["bytes_down"]
        actions.append(ActionSig(name=name, service=services.most_common(1)[0][0] if services else "other",
                                 instances=len(group), slots=slots,
                                 dwell=_hist(dwells or [1.0], DWELL_EDGES, "log")))
    if not actions:
        return None
    kept = {a.name for a in actions}
    trans = defaultdict(list)
    firsts = []
    by_ue = defaultdict(list)
    for i in inst:
        by_ue[i["ue"]].append(i)
    for seq in by_ue.values():
        seq = [i for i in sorted(seq, key=lambda i: i["t"]) if i["name"] in kept]
        if seq:
            firsts.append(seq[0]["name"])
        for a, b in zip(seq, seq[1:]):
            trans[a["name"]].append(b["name"])
    return ActionModel(source=source, actions=actions, start=_cat(firsts),
                       transitions={a: _cat(v) for a, v in trans.items()})


def find_instances(rows: list[dict], *, log: str | Path | None = None, gap: float = 1.5, k: int = 6,
                   seed: int = 0) -> list[dict]:
    """Action instances, each flow tagged with its action's service (r["_svc"])."""
    inst = instances_from_log(rows, read_log(log)) if log else instances_from_bursts(rows, gap=gap, k=k, seed=seed)
    for i in inst:
        for r in i["flows"]:
            r["_svc"] = i.get("service") or "other"
    return inst


def resolve(model: ActionModel, name: str) -> str:
    """Full action name for a script step; a bare name works when exactly one action ends with it."""
    names = [a.name for a in model.actions]
    if name in names:
        return name
    hits = [n for n in names if n.split("/", 1)[-1] == name]
    if len(hits) == 1:
        return hits[0]
    raise ValueError(f"unknown action {name!r}; the profile has: {', '.join(names)}")


def check_script(model: ActionModel, script: Script) -> Script:
    for s in script.sessions:
        for step in s.steps:
            step.action = resolve(model, step.action)
    return script


def describe(model: ActionModel) -> list[dict]:
    """What an agent needs to write a script: action names, typical dwell, flows per instance."""
    out = []
    for a in model.actions:
        med = _median_of(a.dwell)
        out.append({"action": a.name, "service": a.service, "instances": a.instances, "dwell_median_s": round(med, 1),
                    "dwell_range_s": [round(a.dwell.edges[0], 1), round(a.dwell.edges[-1], 1)],
                    "flows_per_instance": round(sum(s.p * _median_of(s.count) for s in a.slots), 1),
                    "top_servers": [s.domain for s in a.slots if s.domain][:4],
                    "next": dict(zip(model.transitions[a.name].values[:4], model.transitions[a.name].probs[:4]))
                    if a.name in model.transitions else {}})
    return out


def _median_of(h) -> float:
    cum = np.cumsum(h.probs)
    i = int(np.searchsorted(cum, 0.5))
    lo, hi = h.edges[i], h.edges[i + 1]
    return math.sqrt(lo * hi) if h.scale == "log" and lo > 0 else (lo + hi) / 2

