"""Data contracts between the four stages.

flows.parquet   one row per flow, written by ingest (FLOW_SCHEMA)
labeled.parquet the same rows plus label columns (LABELED_SCHEMA)
kb/apps.yaml    application knowledge base (KnowledgeBase)
profile.json    distributions only, no single records (Profile)
"""

from __future__ import annotations

from typing import Literal

import pyarrow as pa
from pydantic import BaseModel, Field, field_validator

SEQ_LEN = 32  # packets kept per flow for the length / inter-arrival sequences

FLOW_SCHEMA = pa.schema(
    [
        ("flow_id", pa.int64()),
        ("iface", pa.string()),  # "n3" (GTP-U seen) or "n6"
        ("ue", pa.string()),  # HMAC token of the UE-side IP
        ("server", pa.string()),  # HMAC token of the server-side IP
        ("ip_version", pa.int8()),
        ("proto", pa.int8()),  # 6 tcp, 17 udp
        ("ue_port", pa.int32()),
        ("server_port", pa.int32()),
        ("teid_ul", pa.string()),  # HMAC token of the uplink TEID (N3 only)
        ("teid_dl", pa.string()),
        ("qfi", pa.int8()),
        ("start", pa.float64()),  # epoch seconds
        ("end", pa.float64()),
        ("duration", pa.float64()),
        ("pkts_up", pa.int64()),
        ("pkts_down", pa.int64()),
        ("bytes_up", pa.int64()),  # inner IP bytes
        ("bytes_down", pa.int64()),
        ("seq_len", pa.list_(pa.int16())),  # signed inner IP length, + uplink, - downlink
        ("seq_iat", pa.list_(pa.float32())),  # ms since previous packet of the flow, first is 0
        ("end_reason", pa.string()),  # fin, rst, idle, eof
        ("dns_name", pa.string()),  # query name that resolved to the server IP, same UE, time window
        ("sni", pa.string()),  # TLS or QUIC server name
        ("alpn", pa.string()),  # offered ALPN list, comma separated
        ("ja4", pa.string()),
        ("ja4_r", pa.string()),  # JA4 raw form: client stack, lets synth rebuild a matching hello
        ("quic_version", pa.string()),  # hex, e.g. "0x00000001"
        ("http_host", pa.string()),  # cleartext HTTP Host header
        ("asn", pa.int64()),  # server ASN from the offline database
        ("ndpi_app", pa.string()),  # optional weak label from nfstream
    ]
)

LABEL_FIELDS = [
    ("app", pa.string()),
    ("category", pa.string()),
    ("label_source", pa.string()),  # one of LABEL_SOURCES
    ("label_conf", pa.float32()),
]

LABELED_SCHEMA = pa.schema(list(FLOW_SCHEMA) + [pa.field(n, t) for n, t in LABEL_FIELDS])

LABEL_SOURCES = ("sni", "http_host", "dns", "ja4", "asn", "port", "ndpi", "none")
CONFIDENCE = {"sni": 0.95, "http_host": 0.9, "dns": 0.85, "ja4": 0.75, "asn": 0.6, "port": 0.4, "ndpi": 0.5,
              "none": 0.0}

CATEGORIES = (
    "web",
    "video",
    "short_video",
    "live_streaming",
    "music",
    "social",
    "messaging",
    "conferencing",
    "voip",
    "gaming",
    "shopping",
    "payment",
    "maps",
    "ride_hailing",
    "travel",
    "news",
    "search",
    "email",
    "cloud_storage",
    "productivity",
    "ai",
    "app_store",
    "os_update",
    "ads_analytics",
    "cdn",
    "dns",
    "ntp",
    "vpn",
    "other",
)


class AppRule(BaseModel):
    """One application in kb/apps.yaml."""

    name: str
    category: str
    domains: list[str] = Field(default_factory=list)  # "example.com" matches it and subdomains; "*" globs; "re:" regex
    asns: list[int] = Field(default_factory=list)  # only ASNs the app owns alone
    ports: list[str] = Field(default_factory=list)  # "udp/3478", "tcp/5222", "udp/3478-3481"
    alpn: list[str] = Field(default_factory=list)  # narrows a port or ASN match
    ja4: list[str] = Field(default_factory=list)  # client fingerprints unique to the app
    template: str | None = None  # synth template name; default chosen by transport

    @field_validator("category")
    @classmethod
    def _known_category(cls, v: str) -> str:
        if v not in CATEGORIES:
            raise ValueError(f"unknown category {v!r}; use one of {', '.join(CATEGORIES)}")
        return v

    @field_validator("ports")
    @classmethod
    def _port_syntax(cls, v: list[str]) -> list[str]:
        for p in v:
            proto, _, rng = p.partition("/")
            lo, _, hi = rng.partition("-")
            if proto not in ("tcp", "udp") or not lo.isdigit() or (hi and not hi.isdigit()):
                raise ValueError(f"bad port {p!r}; use tcp/443 or udp/3478-3481")
        return v


class KnowledgeBase(BaseModel):
    version: int = 1
    apps: list[AppRule]

    @field_validator("apps")
    @classmethod
    def _unique(cls, v: list[AppRule]) -> list[AppRule]:
        seen: set[str] = set()
        for a in v:
            if a.name in seen:
                raise ValueError(f"duplicate app {a.name!r}")
            seen.add(a.name)
        return v


# ---------------------------------------------------------------- profile


class Hist(BaseModel):
    """Histogram with explicit bin edges; probs sum to 1. scale tells synth how to sample inside a bin."""

    edges: list[float]
    probs: list[float]
    scale: Literal["linear", "log"] = "linear"


class Categorical(BaseModel):
    values: list[str]
    probs: list[float]


class Cluster(BaseModel):
    weight: float
    center: list[float]  # signed lengths, SEQ_LEN entries, 0 = no packet
    # per position: [state, share] pairs over the chain states ("u:0-100"...), state == len(states) means
    # the flow has ended; keeps the two modes (full data packet or ACK) a mean would blur
    positions: list[list[tuple[int, float]]] = Field(default_factory=list)


class MarkovChain(BaseModel):
    """Packet-level chain over (direction, size bin) states, used past the first SEQ_LEN packets."""

    states: list[str]  # "u:0-100", "d:1300-1500"
    edges: list[float]  # size bin edges shared by both directions
    start: list[float]
    trans: list[list[float]]


class AppProfile(BaseModel):
    app: str
    category: str
    flow_share: float
    flows: int
    ues: int
    transport: Categorical  # tls_tcp, quic, tcp, udp
    endpoints: Categorical  # transport and server port together, "tls_tcp/443", "udp/123"
    alpn: Categorical
    domains: Categorical  # only names that matched the knowledge base
    ja4_r: Categorical  # client stacks (JA4 raw); no per-user data
    qfi: Categorical
    duration: Hist
    pkts: Hist  # both directions; up and down counts move together, so they are not summed from two samples
    pkts_up: Hist
    pkts_down: Hist
    bytes_up: Hist
    bytes_down: Hist
    len_up: Hist
    len_down: Hist
    iat: Hist
    # mean packet length after the first SEQ_LEN packets, one value per long flow; bulk transfer uses
    # bigger packets than the handshake-heavy start the chain is learned from
    tail_len_up: Hist | None = None
    tail_len_down: Hist | None = None
    seq_clusters: list[Cluster]
    chain: MarkovChain | None = None
    concurrency: Hist  # parallel flows of this app per UE at a flow start


class UEProfile(BaseModel):
    ue: str  # "ue1", "ue2"... renumbered, never the HMAC token
    active_hours: list[float]  # 24 shares, UTC
    app_mix: Categorical
    flow_rate: float  # flow starts per second inside sessions
    inter_flow: Hist  # seconds between flow starts inside a session
    session_flows: Hist  # flows per session
    session_gap: float  # gap (s) that splits activity into sessions
    sessions_per_hour: float


class ProfileMeta(BaseModel):
    tool: str = "upsynth"
    version: str
    flows: int
    ues: int
    span_seconds: float
    iface: Categorical
    ip_version: Categorical
    min_flows_per_app: int
    min_ues_per_app: int
    dns_ratio: float  # DNS flows per non-DNS flow; synth emits a lookup before a flow with this probability


class Profile(BaseModel):
    meta: ProfileMeta
    apps: list[AppProfile]
    ues: list[UEProfile]
    app_transitions: dict[str, Categorical]  # next app given previous app of the same UE
