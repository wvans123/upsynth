"""upsynth command line. Every command prints a summary; --json prints it as one JSON object."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import typer

from . import __version__

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help=(
        "Identify 5G user-plane flows by application and synthesize realistic user-plane pcaps.\n\n"
        "Pipeline: ingest (pcap -> flows.parquet) -> label (-> labeled.parquet) -> profile (-> profile.json) "
        "-> synth (-> out.pcap + labels.csv). Real captures stay on this machine: ingest replaces IPs and TEIDs "
        "with HMAC tokens and keeps no payload; profile.json holds distributions only and may be shared."
    ),
)


def _emit(result: dict, as_json: bool) -> None:
    if as_json:
        sys.stdout.write(json.dumps(result, ensure_ascii=False, default=str) + "\n")
        return
    for k, v in result.items():
        if isinstance(v, dict):
            typer.echo(f"{k}:")
            for k2, v2 in v.items():
                typer.echo(f"  {k2}: {v2}")
        elif isinstance(v, list):
            typer.echo(f"{k}: {', '.join(map(str, v)) if v else '-'}")
        else:
            typer.echo(f"{k}: {v}")


def _fail(msg: str, as_json: bool) -> None:
    if as_json:
        sys.stdout.write(json.dumps({"error": msg}, ensure_ascii=False) + "\n")
    else:
        typer.echo(f"error: {msg}", err=True)
    raise typer.Exit(1)


JSON_OPT = typer.Option(False, "--json", help="Print the result as one JSON object on stdout.")


@app.command()
def ingest(
    pcap: Path = typer.Argument(..., exists=True, dir_okay=False, help="Capture file, pcap or pcapng (N3 GTP-U or N6 plain IP)."),
    out: Path = typer.Option(Path("flows.parquet"), "--out", "-o", help="Flow table to write."),
    key: Optional[str] = typer.Option(None, "--key", help="HMAC key for IP/TEID tokens. Default: $UPSYNTH_KEY, else a random key kept in ~/.upsynth/key."),
    asn_db: Optional[Path] = typer.Option(None, "--asn-db", exists=True, dir_okay=False, envvar="UPSYNTH_ASN_DB",
                                          help="Offline IP-to-ASN file: iptoasn.com ip2asn-*.tsv(.gz), pyasn ipasn .dat, or CSV prefix,asn. Env: UPSYNTH_ASN_DB."),
    udp_idle: float = typer.Option(120.0, help="UDP / QUIC flow idle timeout, seconds."),
    tcp_idle: float = typer.Option(600.0, help="TCP flow idle timeout, seconds (TCP flows normally end on FIN or RST)."),
    dns_window: float = typer.Option(600.0, help="A DNS answer names a server IP for this many seconds, for the same UE only."),
    ndpi: bool = typer.Option(False, "--ndpi", help="Also run nDPI through nfstream for weak labels (pip install 'upsynth[ndpi]')."),
    as_json: bool = JSON_OPT,
):
    """Cut a capture into flows: pcap -> flows.parquet.

    GTP-U on N3 is unwrapped (TEID and QFI kept, direction from the PDU Session Container). Flows are
    bidirectional 5-tuples; TCP ends on FIN/RST, UDP after --udp-idle. Per flow: direction, start/end,
    packets and bytes each way, the first 32 signed packet lengths and gaps, DNS name (same UE, time
    window), TLS/QUIC SNI, ALPN, JA4, QUIC version, HTTP Host, server ASN.
    IPs and TEIDs are HMAC tokens; no payload is written.
    """
    from . import ingest as mod
    from .anon import load_key

    try:
        res = mod.run(pcap, out, key=load_key(key), asn_db=asn_db, udp_idle=udp_idle, tcp_idle=tcp_idle,
                      dns_window=dns_window, use_ndpi=ndpi)
    except (ValueError, RuntimeError, OSError) as e:
        _fail(str(e), as_json)
    _emit(res, as_json)


@app.command()
def label(
    flows: Path = typer.Argument(..., exists=True, dir_okay=False, help="flows.parquet from ingest."),
    out: Path = typer.Option(Path("labeled.parquet"), "--out", "-o", help="Labeled flow table to write."),
    kb: Optional[Path] = typer.Option(None, "--kb", exists=True, dir_okay=False, help="Knowledge base YAML. Default: the bundled upsynth/kb/apps.yaml."),
    pfd: Optional[Path] = typer.Option(None, "--pfd", help="Also write the knowledge base as PFD JSON (TS 29.122 / 29.551)."),
    as_json: bool = JSON_OPT,
):
    """Label every flow with an app and category: flows.parquet -> labeled.parquet.

    Rule order, first hit wins: SNI, HTTP Host, DNS name, JA4, ASN, nDPI weak label, port.
    Names match the longest domain suffix in the knowledge base. Adds columns app, category,
    label_source and label_conf. The summary lists the most common unmatched names so the
    knowledge base can be extended.
    """
    from . import label as mod

    try:
        res = mod.run(flows, out, kb_path=kb, pfd=pfd)
    except (ValueError, OSError) as e:
        _fail(str(e), as_json)
    _emit(res, as_json)


@app.command()
def profile(
    labeled: Path = typer.Argument(..., exists=True, dir_okay=False, help="labeled.parquet from label."),
    out: Path = typer.Option(Path("profile.json"), "--out", "-o", help="Profile to write."),
    min_flows: int = typer.Option(5, help="Apps with fewer flows are folded into 'other'."),
    min_ues: int = typer.Option(1, help="Apps seen by fewer UEs are folded into 'other'. Raise it before a profile leaves the company."),
    session_gap: float = typer.Option(300.0, help="A pause longer than this (seconds) starts a new UE session."),
    seed: int = typer.Option(0, help="Seed for sequence clustering."),
    as_json: bool = JSON_OPT,
):
    """Extract a de-identified traffic profile: labeled.parquet -> profile.json.

    Per app: flow share, transport, ports, ALPN, server names matched by the knowledge base, client
    TLS stacks (JA4 raw), QFI, and histograms of duration, packets, bytes, packet lengths per
    direction and gaps; cluster centers of the first 32 packets; a packet Markov chain; concurrency.
    Per anonymous UE (renumbered): active hours, app mix, session and flow arrival. Only
    distributions, no single flow.
    """
    from . import profile as mod

    try:
        res = mod.run(labeled, out, min_flows=min_flows, min_ues=min_ues, session_gap=session_gap, seed=seed)
    except (ValueError, OSError) as e:
        _fail(str(e), as_json)
    _emit(res, as_json)


@app.command()
def synth(
    profile_path: Path = typer.Argument(..., exists=True, dir_okay=False, metavar="PROFILE", help="profile.json from profile."),
    out: Path = typer.Option(Path("out.pcap"), "--out", "-o", help="pcap to write (Ethernet link type)."),
    labels: Optional[Path] = typer.Option(None, "--labels", help="Ground truth CSV, one row per flow. Default: <out>.labels.csv."),
    ues: int = typer.Option(10, help="Number of synthetic UEs."),
    duration: float = typer.Option(300.0, help="Seconds of traffic to generate."),
    iface: str = typer.Option("n3", help="n3: wrap in GTP-U between gNB and UPF; n6: plain IP."),
    seed: int = typer.Option(0, help="Random seed; the same seed and profile give the same pcap."),
    start: Optional[float] = typer.Option(None, help="Start time, epoch seconds. Default 2026-01-01 08:00 UTC."),
    app_filter: Optional[list[str]] = typer.Option(None, "--app", help="Only generate these apps (repeatable)."),
    kb: Optional[Path] = typer.Option(None, "--kb", exists=True, dir_okay=False, help="Knowledge base for per-app templates."),
    mtu: Optional[int] = typer.Option(None, help="Inner MTU. Default 1400 on n3, 1500 on n6."),
    max_flow_packets: int = typer.Option(5000, help="Cap on packets per flow, keeps files small."),
    check: bool = typer.Option(True, "--check/--no-check", help="Run tshark on the output and count malformed packets."),
    as_json: bool = JSON_OPT,
):
    """Generate a user-plane pcap from a profile: profile.json -> out.pcap + labels.csv.

    Samples UEs, sessions and flows from the profile, then writes valid packets per app template:
    DNS query/answer, TCP handshake + TLS 1.3 ClientHello (SNI, ALPN, JA4 from the profile) +
    ServerHello + application data, QUIC Initial with SNI (decryptable by Wireshark), RTP-like UDP.
    Server addresses come from 198.18.0.0/15 and 2001:db8::/32 so nothing points at a real host.
    The check passes when tshark reports zero malformed packets; exit code 2 if it fails.
    """
    from . import synth as mod

    try:
        res = mod.run(profile_path, out, labels, ues=ues, duration=duration, iface=iface, seed=seed, start=start,
                      apps=app_filter, kb_path=kb, mtu=mtu, max_flow_packets=max_flow_packets, check=check)
    except (ValueError, OSError) as e:
        _fail(str(e), as_json)
    _emit(res, as_json)
    if check and res.get("check", {}).get("ok") is False:
        raise typer.Exit(2)


@app.command("kb")
def kb_cmd(
    kb: Optional[Path] = typer.Option(None, "--kb", exists=True, dir_okay=False, help="Knowledge base YAML. Default: the bundled one."),
    pfd: Optional[Path] = typer.Option(None, "--pfd", help="Write the knowledge base as PFD JSON."),
    find: Optional[str] = typer.Option(None, "--find", help="Show which app a domain name matches."),
    as_json: bool = JSON_OPT,
):
    """Check the knowledge base (schema, duplicate domains or ASNs), look up a name, export PFD."""
    from . import label as mod

    try:
        kbase = mod.load_kb(kb)
        m = mod.Matcher(kbase)
    except (ValueError, OSError) as e:
        _fail(str(e), as_json)
    cats: dict[str, int] = {}
    for a in kbase.apps:
        cats[a.category] = cats.get(a.category, 0) + 1
    res: dict = {"kb": str(kb) if kb else "bundled", "apps": len(kbase.apps), "domains": len(m.suffix) + len(m.globs) + len(m.regex),
                 "asns": len(m.asn), "port_rules": len(m.ports), "by_category": dict(sorted(cats.items()))}
    if find:
        res["find"] = {"name": find, "app": m.by_name(find)}
    if pfd:
        res["pfd"] = mod.export_pfd(kbase, pfd)
    _emit(res, as_json)


@app.command()
def version():
    """Print the upsynth version."""
    typer.echo(__version__)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
