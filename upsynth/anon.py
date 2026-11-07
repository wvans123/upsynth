"""Stable HMAC tokens for IP addresses and TEIDs.

The key never leaves the machine: it comes from --key, UPSYNTH_KEY, or a random key created once in
~/.upsynth/key. The same key gives the same token across runs, so flows of one UE stay linked.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from pathlib import Path


def key_path() -> Path:
    return Path(os.environ.get("UPSYNTH_HOME", Path.home() / ".upsynth")) / "key"


def load_key(key: str | None = None) -> bytes:
    if key:
        return key.encode()
    env = os.environ.get("UPSYNTH_KEY")
    if env:
        return env.encode()
    p = key_path()
    if p.exists():
        return p.read_bytes().strip()
    p.parent.mkdir(parents=True, exist_ok=True)
    k = secrets.token_hex(32).encode()
    p.write_bytes(k)
    try:
        p.chmod(0o600)
    except OSError:
        pass
    return k


class Anonymizer:
    def __init__(self, key: bytes):
        self._key = key
        self._cache: dict[tuple[str, bytes], str] = {}

    def token(self, kind: str, raw: bytes) -> str:
        c = self._cache.get((kind, raw))
        if c is None:
            c = hmac.new(self._key, kind.encode() + b":" + raw, hashlib.sha256).hexdigest()[:16]
            self._cache[(kind, raw)] = c
        return c

    def ip(self, packed: bytes) -> str:
        return self.token("ip", packed)

    def teid(self, teid: int) -> str:
        return self.token("teid", teid.to_bytes(4, "big"))
