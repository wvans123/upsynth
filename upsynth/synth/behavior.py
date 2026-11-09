"""Behaviour layer: sample UEs, sessions, flows and per-flow packet shapes from a profile.

First version as in the brief: empirical distributions plus Markov chains. The first SEQ_LEN packets
follow a sequence cluster center with noise; longer flows continue on the app's packet chain.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import numpy as np

from .. import pacing
from ..profile import CHAIN_EDGES
from ..schemas import SERVICE_OF_CATEGORY, SEQ_LEN, AppProfile, Categorical, Hist, Profile, UEProfile
from ..tls import CHROME_JA4_R, CHROME_QUIC_JA4_R, normalize_raw
from .protocols import TCP_CODECS, TLS_TCP_PORTS, fits, free_port

if TYPE_CHECKING:
    from ..schemas import Script


@dataclass
class FlowSpec:
    flow_id: int
    ue: int
    app: str
    category: str
    transport: str  # tls_tcp, quic, tcp, udp
    template: str
    start: float
    server_port: int
    domain: str | None
    ja4_r: str | None
    alpn: list[str]
    qfi: int
    ip_version: int
    shape: list[tuple[int, float]]  # (signed inner IP length, gap ms before the packet)
    dns_first: bool = False
    extras: dict = field(default_factory=dict)


@dataclass
class UE:
    index: int
    name: str
    ip4: bytes
    ip6: bytes
    teid_ul: int
    teid_dl: int
    persona: UEProfile


class Sampler:
    def __init__(self, rng: np.random.Generator):
        self.rng = rng

    def hist(self, h: Hist) -> float:
        i = self.rng.choice(len(h.probs), p=_norm(h.probs))
        lo, hi = h.edges[i], h.edges[i + 1]
        if h.scale == "log" and lo > 0:
            return float(np.exp(self.rng.uniform(np.log(lo), np.log(hi))))
        return float(self.rng.uniform(lo, hi))

    def cat(self, c: Categorical, default=None):
        if not c.values:
            return default
        return c.values[self.rng.choice(len(c.values), p=_norm(c.probs))]


def _norm(p) -> np.ndarray:
    a = np.asarray(p, dtype=float)
    return a / a.sum()


WEB_TEMPLATE_CATEGORIES = {"web", "news", "search", "travel", "shopping"}


def template_for(app: AppProfile, transport: str, kb_templates: dict[str, str]) -> str:
    if app.app in kb_templates:
        return kb_templates[app.app]
    if transport == "tls_tcp" and app.category in WEB_TEMPLATE_CATEGORIES:
        return "web_browsing"
    return transport


def _alpn_for(ja4_r: str, offered: list[str]) -> list[str]:
    chars = ja4_r[8:10]
    if chars == "00":
        return []
    if offered and (offered[0][0] + offered[0][-1]) == chars:
        return offered
    return {"h2": ["h2", "http/1.1"], "h1": ["http/1.1"], "h3": ["h3"]}.get(chars, [chars])


class Behaviour:
    def __init__(self, profile: Profile, rng: np.random.Generator, *, kb_templates: dict[str, str] | None = None,
                 mtu: int = 1500, max_flow_packets: int = 5000, registry: dict | None = None,
                 rtt_ms: float = 0.0, bw_mbps: float | None = None, cdn_region: str | None = None):
        """rtt_ms, bw_mbps, cdn_region imitate another network: extra delay before server answers, a cap on a
        flow's rate, and the region code CDN host names carry (cn-jssz-ct-01-01.bilivideo.com)."""
        self.rtt_ms = rtt_ms
        self.bw_mbps = bw_mbps
        self.cdn_region = cdn_region
        self.registry = registry or {}
        self.remapped: Counter = Counter()
        self.dwell_outside = 0  # script steps whose dwell lies outside what the profile saw
        self.p = profile
        self.s = Sampler(rng)
        self.rng = rng
        self.apps = {a.app: a for a in profile.apps}
        self.kb_templates = kb_templates or {}
        self.mtu = mtu
        self.max_flow_packets = max_flow_packets
        self.flow_id = 0

    # ------------------------------------------------------------ UEs and schedule

    def make_ues(self, n: int) -> list[UE]:
        ues = []
        personas = self.p.ues or [None]
        for i in range(n):
            persona = personas[i % len(personas)]
            ip4 = (ipaddress.IPv4Address("10.45.0.2") + i).packed
            ip6 = (ipaddress.IPv6Address("2001:db8:cafe::2") + (i << 64)).packed
            ues.append(UE(i, f"ue{i + 1}", ip4, ip6, int(self.rng.integers(1, 2**32)), int(self.rng.integers(1, 2**32)),
                          persona))
        return ues

    def schedule(self, ues: list[UE], start: float, duration: float, apps: set[str] | None = None) -> list[FlowSpec]:
        flows: list[FlowSpec] = []
        end = start + duration
        for ue in ues:
            pr = ue.persona
            t = start + self.rng.uniform(0, min(30.0, duration * 0.1))
            while t < end:
                n = max(1, int(round(self.s.hist(pr.session_flows)))) if pr else 20
                prev = None
                k = 0
                while k < n and t < end:
                    app = self._next_app(pr, prev, apps)
                    if app is None:
                        break
                    ap = self.apps[app]
                    conc = max(1, min(8, int(self.s.hist(ap.concurrency))))
                    for j in range(conc):
                        off = 0.0 if j == 0 else float(self.rng.uniform(0.005, 1.5))
                        if t + off < end:
                            flows.append(self.flow(ue, ap, t + off))
                    k += conc
                    prev = app
                    t += self.s.hist(pr.inter_flow) if pr and pr.inter_flow.probs else float(self.rng.exponential(5.0))
                sph = pr.sessions_per_hour if pr else 1.0
                t += max(pr.session_gap if pr else 300.0, float(self.rng.exponential(3600.0 / max(sph, 1e-3))))
        flows.sort(key=lambda f: f.start)
        for i, f in enumerate(flows, 1):
            f.flow_id = i
        return flows

    def schedule_actions(self, ues: list[UE], start: float, duration: float,
                         script: "Script | None" = None) -> tuple[list[FlowSpec], list[dict]]:
        """Flows driven by actions: from a script (one session per UE), or walked from the profile's action chain.

        Returns the flows and the action instances (ground truth: ue, action, start, end)."""
        model = self.p.action_model
        if model is None:
            raise ValueError("profile has no action model; build it with: upsynth profile ... --actions <log>|bursts")
        sigs = {a.name: a for a in model.actions}
        end = start + duration
        flows: list[FlowSpec] = []
        done: list[dict] = []
        sessions = list(script.sessions) if script else []
        by_name = {u.name: u for u in ues}
        plan = []
        free = [u for u in ues if not any(s.ue == u.name for s in sessions)]
        for s in sessions:
            u = by_name.get(s.ue) if s.ue else (free.pop(0) if free else None)
            if u is not None:
                plan.append((u, s))
        if not script:
            plan = [(u, None) for u in ues]
        for ue, sess in plan:
            t = start + (sess.start if sess else float(self.rng.uniform(0, min(10.0, duration * 0.05))))
            # the whole action sequence first: a page left for another service closes its connections, so
            # flows end with the run of same-service actions that opened them
            seq = []
            steps = iter(sess.steps) if sess else None
            name = None
            while t < end:
                if steps is not None:
                    step = next(steps, None)
                    if step is None:
                        break
                    name, dwell = step.action, step.dwell
                else:
                    name = self.s.cat(model.transitions[name]) if name in model.transitions else self.s.cat(model.start)
                    dwell = None
                sig = sigs[name]
                if dwell is None:
                    dwell = self.s.hist(sig.dwell)
                else:
                    if not sig.dwell.edges[0] <= dwell <= sig.dwell.edges[-1]:
                        self.dwell_outside += 1
                    dwell = min(max(dwell, 0.1), 3600.0)
                seq.append((name, t, dwell))
                t += dwell
            run_end = [0.0] * len(seq)
            for j in range(len(seq) - 1, -1, -1):
                name, t, dwell = seq[j]
                same_next = j + 1 < len(seq) and sigs[seq[j + 1][0]].service == sigs[name].service
                run_end[j] = run_end[j + 1] if same_next else min(t + dwell, end)
            for j, (name, t, dwell) in enumerate(seq):
                sig = sigs[name]
                aid = len(done) + 1
                for slot in sig.slots:
                    if self.rng.random() >= slot.p or slot.app not in self.apps:
                        continue
                    for _ in range(max(1, int(self.s.hist(slot.count)))):
                        ts = t + min(self.s.hist(slot.offset), max(dwell, 0.05))
                        if ts >= end:
                            continue
                        # bulk flows (the stream, segment fetches) close when the user leaves; small connections
                        # stay in the client's pool and are reused
                        cut = max(run_end[j] - ts, 0.2) if slot.app.endswith("+bulk") else None
                        f = self.flow(ue, self.apps[slot.app], ts, domain=slot.domain, endpoint=slot.endpoint,
                                      max_dur=cut)
                        f.extras["action"] = name
                        f.extras["action_id"] = aid
                        f.extras["service"] = sig.service
                        flows.append(f)
                done.append({"action_id": aid, "ue": ue.name, "ue_ip": str(ipaddress.ip_address(ue.ip4)), "action": name,
                             "service": sig.service, "start": t, "end": min(t + dwell, end)})
        flows.sort(key=lambda f: f.start)
        for i, f in enumerate(flows, 1):
            f.flow_id = i
        return flows, done

    def _next_app(self, pr: UEProfile | None, prev: str | None, only: set[str] | None) -> str | None:
        cands = [a for a in self.apps if "@" not in a and (only is None or a in only)]
        if not cands:
            return None
        for _ in range(8):
            app = None
            if prev and prev in self.p.app_transitions and self.rng.random() < 0.7:
                app = self.s.cat(self.p.app_transitions[prev])
            if app is None and pr is not None:
                app = self.s.cat(pr.app_mix)
            if app is None:
                shares = np.array([self.apps[a].flow_share for a in cands])
                app = cands[self.rng.choice(len(cands), p=shares / shares.sum())]
            if app in self.apps and app in cands:
                return app
        return cands[self.rng.integers(len(cands))]

    # ------------------------------------------------------------ one flow

    def flow(self, ue: UE, ap: AppProfile, start: float, *, domain: str | None = None,
             endpoint: str | None = None, max_dur: float | None = None) -> FlowSpec:
        ep = endpoint or self.s.cat(ap.endpoints)
        if ep:
            transport, _, p = ep.partition("/")
            port = int(p)
        else:
            transport = self.s.cat(ap.transport, "tls_tcp")
            port = {"quic": 443, "tls_tcp": 443, "tcp": 80}.get(transport, 50000)
        if transport == "dns":
            transport = "udp"
        if transport == "tcp" and port in TLS_TCP_PORTS:
            transport = "tls_tcp"
        elif transport == "tls_tcp" and port in TCP_CODECS:
            transport = "tcp"
        elif transport == "udp" and port == 443:
            transport = "quic"
        if self.registry and not fits(transport, port, self.registry):
            new = free_port(transport, port, self.registry)
            self.remapped[f"{'udp' if transport in ('udp', 'quic') else 'tcp'}/{port}->{new}"] += 1
            port = new
        prefix = {"tls_tcp": "t", "quic": "q"}.get(transport)
        ja4_r = None
        if prefix:
            stacks = [(v, p) for v, p in zip(ap.ja4_r.values, ap.ja4_r.probs) if v.startswith(prefix)]
            if stacks:
                ja4_r = self.s.cat(Categorical(values=[v for v, _ in stacks], probs=[p for _, p in stacks]))
            else:
                ja4_r = CHROME_JA4_R if prefix == "t" else CHROME_QUIC_JA4_R
            ja4_r = normalize_raw(ja4_r)
        domain = domain or self.s.cat(ap.domains)
        if domain and self.cdn_region:
            domain = re.sub(r"^(cn|ec)-[a-z]+-[a-z]+-", rf"\1-{self.cdn_region}-", domain)
        if domain is None and prefix:
            domain = f"{hashlib.sha1(f'{ap.app}{self.rng.integers(1 << 30)}'.encode()).hexdigest()[:10]}.example.net"
        offered = (self.s.cat(ap.alpn) or "").split(",") if ap.alpn.values else []
        offered = [a for a in offered if a]
        alpn = _alpn_for(ja4_r, offered) if ja4_r else []
        qfi = self.s.cat(ap.qfi)
        ver = self.s.cat(self.p.meta.ip_version, "4")
        dns_first = bool(domain) and not domain.endswith(".example.net") and self.rng.random() < max(self.p.meta.dns_ratio, 0.0)
        template = template_for(ap, transport, self.kb_templates)
        if template == "web_browsing" and domain and not domain.endswith(".example.net"):
            dns_first = dns_first or self.rng.random() < 0.8
        spec = FlowSpec(0, ue.index, ap.app, ap.category, transport, template, start, port, domain, ja4_r, alpn,
                        int(qfi) if qfi else 1, int(ver), self.shape(ap, max_dur), dns_first)
        spec.extras["service"] = SERVICE_OF_CATEGORY.get(ap.category, "other")
        return spec

    def shape(self, ap: AppProfile, max_dur: float | None = None) -> list[tuple[int, float]]:
        rng = self.rng
        n = self._total_packets(ap, 1)
        lens: list[int] = []
        if ap.seq_clusters:
            w = _norm([c.weight for c in ap.seq_clusters])
            c = ap.seq_clusters[rng.choice(len(w), p=w)]
            lens = self._head(ap, c)
            if len(lens) < SEQ_LEN:  # the cluster ended the flow early: a short flow
                n = max(len(lens), 1)
            elif n <= SEQ_LEN:  # it did not: take the length from the long tail of the packet counts
                n = self._total_packets(ap, SEQ_LEN + 1)
        if not lens:
            lens.append(int(self.s.hist(ap.len_up)))
        lens = lens[:n]
        st = self._state(lens[-1], CHAIN_EDGES)
        trans = [_norm(r) for r in ap.chain.trans] if ap.chain else None
        nb = len(CHAIN_EDGES) - 1
        tail_mean = {True: self.s.hist(ap.tail_len_up) if ap.tail_len_up else None,
                     False: self.s.hist(ap.tail_len_down) if ap.tail_len_down else None}
        while len(lens) < n:
            if trans is not None:
                st = int(rng.choice(len(trans), p=trans[st]))
                up = st < nb
            else:
                up = rng.random() < 0.4
            lens.append(self._tail_size(ap, up, tail_mean[up], st % nb) * (1 if up else -1))
        lens = [max(-self.mtu, min(self.mtu, v)) for v in lens]
        iats = [0.0] + [self.s.hist(ap.iat) for _ in range(len(lens) - 1)]
        if self.rtt_ms:  # server answers arrive later on a longer path
            for i in range(1, min(len(lens), SEQ_LEN)):
                if lens[i - 1] > 0 > lens[i]:
                    iats[i] += self.rtt_ms
        dur = self.s.hist(ap.duration) * 1000.0
        total = sum(iats)
        if len(lens) > SEQ_LEN and ap.on_s and ap.off_s and dur >= 3000:
            iats = self._pace(lens, iats, dur / 1000.0, ap)
        elif len(lens) > SEQ_LEN and total > 0 and dur > 0:
            k = dur / total
            iats = [x * k for x in iats]
        if max_dur is not None:  # the flow closes when the user leaves
            t, keep = 0.0, 0
            for keep, g in enumerate(iats, 1):
                t += g / 1000.0
                if t > max_dur and keep > 1:
                    keep -= 1
                    break
            lens, iats = lens[:keep], iats[:keep]
        return list(zip(lens, iats))

    def _pace(self, lens: list[int], iats: list[float], dur_s: float, ap: AppProfile) -> list[float]:
        """Place packets after the first SEQ_LEN into busy runs separated by idle runs (the app's on/off shape)."""
        head_t = sum(iats[:SEQ_LEN]) / 1000.0
        tail = lens[SEQ_LEN:]
        span = max(dur_s - head_t, 0.5)
        intervals = pacing.timeline(self.rng, lambda: self.s.hist(ap.on_s), lambda: self.s.hist(ap.off_s), span)
        if self.bw_mbps:
            need = sum(abs(v) for v in tail) * 8 / (self.bw_mbps * 1e6)
            busy_t = sum(b - a for a, b in intervals)
            if busy_t < need:
                k = need / busy_t
                intervals = [(a * k, b * k) for a, b in intervals]
        times = pacing.place(self.rng, intervals, len(tail)) + head_t
        out = list(iats[:SEQ_LEN])
        prev = head_t
        for t in times:
            out.append(max(0.0, (t - prev) * 1000.0))
            prev = t
        return out

    def _head(self, ap: AppProfile, c) -> list[int]:
        """The first SEQ_LEN packets from a cluster: per-position states when the profile has them, else the center."""
        nb = len(CHAIN_EDGES) - 1
        lens: list[int] = []
        if c.positions:
            for dist in c.positions:
                st = dist[self.rng.choice(len(dist), p=_norm([q for _, q in dist]))][0]
                if st >= 2 * nb:
                    break
                d, b = divmod(st, nb)
                size = self._size_in(ap.len_up if d == 0 else ap.len_down, CHAIN_EDGES[b], CHAIN_EDGES[b + 1])
                lens.append(size if d == 0 else -size)
            return lens
        for v in c.center:
            if v == 0:
                break
            mag = abs(v) * float(self.rng.uniform(0.9, 1.1))
            lens.append(int(np.sign(v) * max(40, min(self.mtu, mag))))
        return lens

    def _tail_size(self, ap: AppProfile, up: bool, mean: float | None, bin_: int) -> int:
        """A packet after the first SEQ_LEN. With the app's tail mean A: a full packet with probability q, else an
        ACK-sized one, q chosen so the mean is A (bulk transfer is full packets plus ACKs). Without it: the chain bin."""
        h = ap.len_up if up else ap.len_down
        if mean is None:
            return self._size_in(h, CHAIN_EDGES[bin_], CHAIN_EDGES[bin_ + 1])
        small, full = 52, self.mtu
        q = min(max((mean - small) / max(full - small, 1), 0.0), 1.0)
        if self.rng.random() < q:
            return self._size_in(h, full - 120, full + 1)
        return self._size_in(h, 40, 100)

    def _total_packets(self, ap: AppProfile, at_least: int) -> int:
        n = self._sample_in(ap.pkts, at_least, self.max_flow_packets + 1)
        return max(at_least, min(int(round(n)), self.max_flow_packets))

    def _size_in(self, h: Hist, lo: float, hi: float) -> int:
        """A packet length from the app's length histogram, limited to [lo, hi) and the MTU."""
        hi = min(hi, self.mtu + 1)
        lo = max(lo, 40)
        if lo >= hi:
            return int(min(self.mtu, max(40, lo)))
        return int(self._sample_in(h, lo, hi))

    def _sample_in(self, h: Hist, lo: float, hi: float) -> float:
        """Sample the histogram restricted to [lo, hi); uniform on [lo, hi) if it has no mass there."""
        if lo >= hi:
            return lo
        spans, weights = [], []
        for (a, b), p in zip(zip(h.edges, h.edges[1:]), h.probs):
            a2, b2 = max(a, lo), min(b, hi)
            if b2 > a2 and p > 0:
                spans.append((a2, b2))
                weights.append(p * (b2 - a2) / (b - a))
        if not spans:
            return float(self.rng.uniform(lo, hi))
        a, b = spans[self.rng.choice(len(spans), p=_norm(weights))]
        if h.scale == "log" and a > 0:
            return float(np.exp(self.rng.uniform(np.log(a), np.log(b))))
        return float(self.rng.uniform(a, b))

    @staticmethod
    def _state(v: int, edges: list[float]) -> int:
        nb = len(edges) - 1
        b = int(np.searchsorted(edges, abs(v), side="right") - 1)
        return (0 if v > 0 else 1) * nb + min(max(b, 0), nb - 1)


def server_ip(key: str, version: int) -> bytes:
    """Deterministic server address in a benchmark / documentation range (RFC 2544, RFC 3849)."""
    h = int.from_bytes(hashlib.sha256(key.encode()).digest()[:8], "big")
    if version == 6:
        return (ipaddress.IPv6Address("2001:db8:5::") + (h & ((1 << 64) - 1))).packed
    return (ipaddress.IPv4Address("198.18.0.0") + (h % ((1 << 17) - 2) + 1)).packed
