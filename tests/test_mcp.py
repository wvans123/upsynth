import asyncio
import json

import pytest

fastmcp = pytest.importorskip("fastmcp")


def test_mcp_tools_run_the_pipeline(work, tmp_path, monkeypatch):
    from upsynth.mcp_server import build

    monkeypatch.setenv("UPSYNTH_KEY", "k")
    server = build()

    async def go():
        async with fastmcp.Client(server) as c:
            names = {t.name for t in await c.list_tools()}
            assert names == {"ingest", "label", "profile", "synth"}
            r = await c.call_tool("ingest", {"pcap": str(work / "sample_n3.pcap"), "out": str(tmp_path / "f.parquet")})
            data = r.data if getattr(r, "data", None) else json.loads(r.content[0].text)
            assert data["flows"] == 106

    asyncio.run(go())
