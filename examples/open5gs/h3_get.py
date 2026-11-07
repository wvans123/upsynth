"""Minimal HTTP/3 GET with aioquic (pip install aioquic). Usage: h3_get.py https://host/path"""

import asyncio
import sys
from urllib.parse import urlparse

from aioquic.asyncio import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration


class Client(QuicConnectionProtocol):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.h3 = H3Connection(self._quic)
        self.done = asyncio.Event()
        self.size = 0

    def quic_event_received(self, event):
        for ev in self.h3.handle_event(event):
            if isinstance(ev, (HeadersReceived, DataReceived)):
                self.size += len(getattr(ev, "data", b""))
                if ev.stream_ended:
                    self.done.set()


async def main(url: str) -> None:
    u = urlparse(url)
    cfg = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN, verify_mode=0)
    cfg.server_name = u.hostname
    async with connect(u.hostname, 443, configuration=cfg, create_protocol=Client, wait_connected=True) as c:
        sid = c._quic.get_next_available_stream_id()
        c.h3.send_headers(sid, [(b":method", b"GET"), (b":scheme", b"https"), (b":authority", u.hostname.encode()),
                                (b":path", (u.path or "/").encode()), (b"user-agent", b"aioquic")], end_stream=True)
        c.transmit()
        try:
            await asyncio.wait_for(c.done.wait(), 8)
        except asyncio.TimeoutError:
            pass
        print(url, c.size)


asyncio.run(main(sys.argv[1]))
