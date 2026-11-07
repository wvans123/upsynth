"""MCP server for clients that cannot run shell commands. The four stages as tools; same results as --json.

Install with the extra: pip install 'upsynth[mcp]'; run: upsynth-mcp (stdio).
"""

from __future__ import annotations


def build():
    try:
        from fastmcp import FastMCP
    except ImportError as e:  # pragma: no cover - optional
        raise SystemExit("fastmcp is not installed; pip install 'upsynth[mcp]'") from e

    from . import ingest as ingest_mod
    from . import label as label_mod
    from . import profile as profile_mod
    from . import synth as synth_mod
    from .anon import load_key

    mcp = FastMCP("upsynth")

    @mcp.tool
    def ingest(pcap: str, out: str = "flows.parquet", asn_db: str | None = None, udp_idle: float = 120.0,
               dns_window: float = 600.0) -> dict:
        """Cut a 5G user-plane capture (N3 GTP-U or N6) into de-identified flows: pcap -> flows.parquet.
        IPs and TEIDs become HMAC tokens with the local key; no payload is kept."""
        return ingest_mod.run(pcap, out, key=load_key(), asn_db=asn_db, udp_idle=udp_idle, dns_window=dns_window)

    @mcp.tool
    def label(flows: str, out: str = "labeled.parquet", kb: str | None = None, pfd: str | None = None) -> dict:
        """Label each flow with app and category from the knowledge base (SNI, HTTP Host, DNS, JA4, ASN, port).
        pfd: also write the knowledge base as 3GPP PFD JSON."""
        return label_mod.run(flows, out, kb_path=kb, pfd=pfd)

    @mcp.tool
    def profile(labeled: str, out: str = "profile.json", min_flows: int = 5, min_ues: int = 1) -> dict:
        """Extract a distribution-only traffic profile from labeled flows (safe to share)."""
        return profile_mod.run(labeled, out, min_flows=min_flows, min_ues=min_ues)

    @mcp.tool
    def synth(profile: str, out: str = "out.pcap", ues: int = 10, duration: float = 300.0, iface: str = "n3",
              seed: int = 0, apps: list[str] | None = None) -> dict:
        """Generate a user-plane pcap and labels.csv from a profile; checks it with tshark (malformed must be 0)."""
        return synth_mod.run(profile, out, None, ues=ues, duration=duration, iface=iface, seed=seed, apps=apps)

    return mcp


def main() -> None:
    build().run()


if __name__ == "__main__":
    main()
