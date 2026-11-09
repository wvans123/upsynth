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
    actions: Optional[str] = typer.Option(None, "--actions", help="Also learn an action model: path of an action log CSV (t_start,app,action[,ue]) recorded while the phone was operated, or 'bursts' to find actions in the traffic itself."),
    burst_gap: float = typer.Option(1.5, help="With --actions bursts: a pause longer than this (s) between flow starts ends a burst."),
    action_types: int = typer.Option(6, help="With --actions bursts: number of action types to cluster bursts into."),
    as_json: bool = JSON_OPT,
):
    """Extract a de-identified traffic profile: labeled.parquet -> profile.json.

    Per app: flow share, transport, ports, ALPN, server names matched by the knowledge base, client
    TLS stacks (JA4 raw), QFI, and histograms of duration, packets, bytes, packet lengths per
    direction and gaps; cluster centers of the first 32 packets; a packet Markov chain; concurrency.
    Per anonymous UE (renumbered): active hours, app mix, session and flow arrival. Only
    distributions, no single flow.

    With --actions: per action (open a video, watch, scroll comments...) the flows it opens, how long
    people stay, and which action follows. synth --script then plays action scripts.
    """
    from . import profile as mod

    try:
        res = mod.run(labeled, out, min_flows=min_flows, min_ues=min_ues, session_gap=session_gap, seed=seed,
                      actions=actions, burst_gap=burst_gap, action_types=action_types)
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
    mode: str = typer.Option("flows", help="flows: sessions of flows from app mix and transitions; actions: flows opened by actions walked from the profile's action chain (needs profile --actions)."),
    script: Optional[Path] = typer.Option(None, "--script", exists=True, dir_okay=False, help="Action script JSON to play (implies --mode actions). See 'upsynth actions PROFILE' for action names and the format."),
    rtt_ms: float = typer.Option(0.0, help="Imitate a longer path: extra delay (ms) before server answers."),
    bw_mbps: Optional[float] = typer.Option(None, help="Imitate a slower network: cap on a flow's rate (Mbit/s)."),
    cdn_region: Optional[str] = typer.Option(None, help="Region code written into CDN host names that carry one, e.g. jssz-ct (cn-jssz-ct-01-01.bilivideo.com)."),
    as_json: bool = JSON_OPT,
):
    """Generate a user-plane pcap from a profile: profile.json -> out.pcap + labels.csv.

    Samples UEs, sessions and flows from the profile, then writes valid packets per app template:
    DNS query/answer, TCP handshake + TLS 1.3 ClientHello (SNI, ALPN, JA4 from the profile) +
    ServerHello + application data, QUIC Initial with SNI (decryptable by Wireshark), RTP-like UDP.
    Server addresses come from 198.18.0.0/15 and 2001:db8::/32 so nothing points at a real host.
    The check passes when tshark reports zero malformed packets; exit code 2 if it fails.
    In action mode labels.csv gets the action of every flow and <out>.actions.csv lists the actions.
    """
    from . import synth as mod

    try:
        res = mod.run(profile_path, out, labels, ues=ues, duration=duration, iface=iface, seed=seed, start=start,
                      apps=app_filter, kb_path=kb, mtu=mtu, max_flow_packets=max_flow_packets, check=check,
                      mode=mode, script=script, rtt_ms=rtt_ms, bw_mbps=bw_mbps, cdn_region=cdn_region)
    except (ValueError, OSError) as e:
        _fail(str(e), as_json)
    _emit(res, as_json)
    if check and res.get("check", {}).get("ok") is False:
        raise typer.Exit(2)


def _data_specs(data: list[str]) -> list[tuple[str, str, str | None]]:
    out = []
    for d in data:
        region, sep, rest = d.partition("=")
        if not sep:
            region, rest = "default", d
        path, _, truth = rest.partition(",")
        out.append((region, path, truth or None))
    return out


@app.command("train")
def train_cmd(
    data: list[str] = typer.Option(..., "--data", help="REGION=labeled.parquet[,truth.csv], repeatable. truth.csv: service intervals (an action log, or synth's <out>.actions.csv); without it the knowledge-base category is a weak label."),
    model: Path = typer.Option(Path("service_model.json"), "--model", "-o", help="Model file to write."),
    holdout: Optional[list[str]] = typer.Option(None, "--holdout", help="Evaluate by holding out whole groups: region, app or time (repeatable)."),
    window: float = typer.Option(30.0, help="Slice length, seconds."),
    step: float = typer.Option(15.0, help="Slice step, seconds."),
    key: Optional[str] = typer.Option(None, "--key", help="HMAC key used at ingest, to match ue_ip in truth files to UE tokens."),
    seed: int = typer.Option(0),
    as_json: bool = JSON_OPT,
):
    """Train the behaviour classifier: vod, live, short_video or other per UE, app and window.

    Features are region-independent (idle share, burst and gap lengths, rate variation, flow
    structure, packet size mix); no addresses, server names or absolute rates. Needs the 'ml' extra.
    """
    from . import classify as mod
    from .anon import load_key

    try:
        res = mod.train(_data_specs(data), model, key=load_key(key), window=window, step=step, holdout=holdout,
                        seed=seed)
    except (ValueError, RuntimeError, OSError) as e:
        _fail(str(e), as_json)
    _emit(res, as_json)


@app.command("classify")
def classify_cmd(
    labeled: Path = typer.Argument(..., exists=True, dir_okay=False, help="labeled.parquet to classify."),
    model: Path = typer.Option(..., "--model", exists=True, dir_okay=False, help="Model from upsynth train."),
    out: Path = typer.Option(Path("services.csv"), "--out", "-o", help="One row per slice with the service and probabilities."),
    truth: Optional[Path] = typer.Option(None, "--truth", exists=True, dir_okay=False, help="Service intervals to score against."),
    key: Optional[str] = typer.Option(None, "--key", help="HMAC key used at ingest (for ue_ip in the truth file)."),
    as_json: bool = JSON_OPT,
):
    """Tell per UE, app and window whether it is vod, live, short_video or other."""
    from . import classify as mod
    from .anon import load_key

    try:
        res = mod.classify(labeled, model, out, truth=truth, key=load_key(key))
    except (ValueError, RuntimeError, OSError) as e:
        _fail(str(e), as_json)
    _emit(res, as_json)


SCRIPT_EXAMPLE = {
    "sessions": [{
        "persona": "commuter, 10 minutes on Bilibili, likes food videos",
        "ue": "ue1",
        "start": 0,
        "steps": [{"action": "launch"}, {"action": "scroll_feed", "dwell": 4}, {"action": "open_video"},
                  {"action": "watch", "dwell": 35}, {"action": "back"}, {"action": "search", "query": "火锅"}],
    }]
}


@app.command("actions")
def actions_cmd(
    profile_path: Path = typer.Argument(..., exists=True, dir_okay=False, metavar="PROFILE", help="profile.json built with --actions."),
    as_json: bool = JSON_OPT,
):
    """List the actions a profile knows, for writing synth --script files.

    Per action: typical dwell, its range, flows it opens, main servers, likely next actions. Script
    format: {"sessions": [{"persona", "ue", "start", "steps": [{"action", "dwell", "query"}]}]};
    "dwell" is optional (sampled from the profile when missing; synth reports steps whose dwell lies
    outside what the profile saw), an action may be written without the "<app>/" prefix when that is
    unique.
    """
    from . import actions as act
    from .synth import load_profile

    prof = load_profile(profile_path)
    if prof.action_model is None:
        _fail("profile has no action model; build it with: upsynth profile ... --actions <log>|bursts", as_json)
    res = {"source": prof.action_model.source, "actions": act.describe(prof.action_model),
           "script_example": SCRIPT_EXAMPLE}
    if as_json:
        _emit(res, True)
        return
    typer.echo(f"source: {res['source']}")
    for a in res["actions"]:
        typer.echo(f"{a['action']:28s} dwell~{a['dwell_median_s']}s flows~{a['flows_per_instance']}  "
                   f"next: {', '.join(a['next'])}  servers: {', '.join(a['top_servers'])}")
    typer.echo("script example: " + json.dumps(SCRIPT_EXAMPLE, ensure_ascii=False))


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
