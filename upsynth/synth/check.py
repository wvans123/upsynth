"""The one validity check: tshark parses the output with zero malformed packets."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

_CANDIDATES = [
    "/Applications/Wireshark.app/Contents/MacOS/tshark",
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
]


def find_tshark() -> str | None:
    env = os.environ.get("UPSYNTH_TSHARK")
    if env and Path(env).exists():
        return env
    found = shutil.which("tshark")
    if found:
        return found
    return next((c for c in _CANDIDATES if Path(c).exists()), None)


def tshark_check(pcap: str | Path, tshark: str | None = None, *, examples: int = 5) -> dict:
    tshark = tshark or find_tshark()
    if not tshark:
        return {"ok": None, "error": "tshark not found; install Wireshark or set UPSYNTH_TSHARK"}
    fields = ["-T", "fields", "-e", "frame.number", "-e", "_ws.malformed", "-e", "_ws.expert.severity",
              "-e", "frame.protocols", "-E", "separator=\t"]
    proc = subprocess.run([tshark, "-n", "-r", str(pcap), *fields], capture_output=True, text=True, encoding="utf-8",
                          errors="replace")
    if proc.returncode != 0:
        return {"ok": False, "error": proc.stderr.strip()[-2000:]}
    frames = malformed = errors = 0
    bad = []
    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        if not parts or not parts[0]:
            continue
        frames += 1
        is_mal = len(parts) > 1 and parts[1] != ""
        sev = parts[2] if len(parts) > 2 else ""
        # severity is a bitmask value: 0x00800000 = error (malformed packets are errors too)
        is_err = any(s and int(s, 0) >= 0x00800000 for s in sev.split(",") if s.strip())
        if is_mal:
            malformed += 1
        if is_err:
            errors += 1
        if (is_mal or is_err) and len(bad) < examples:
            bad.append({"frame": int(parts[0]), "protocols": parts[3] if len(parts) > 3 else ""})
    return {"ok": malformed == 0, "tshark": tshark, "frames": frames, "malformed": malformed,
            "expert_errors": errors, "examples": bad}
