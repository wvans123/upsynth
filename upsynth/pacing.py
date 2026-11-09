"""On/off pacing of a flow over time, from its per-second byte counts.

Live streams send all the time at a steady rate; video on demand fetches a segment, idles, fetches
the next; short videos are short heavy bursts. The run lengths of busy and idle seconds keep that
shape without absolute rates, so the same model works on networks of different speed.
"""

from __future__ import annotations

import numpy as np

MIN_BUSY = 1500  # bytes in a second below which a second is idle whatever the flow's rate


def busy(series, frac: float = 0.1) -> np.ndarray:
    s = np.asarray(series, dtype=float)
    if s.size == 0:
        return np.zeros(0, dtype=bool)
    thr = max(MIN_BUSY, frac * float(np.percentile(s, 90)))
    return s >= thr


def runs(mask: np.ndarray) -> tuple[list[int], list[int]]:
    """Lengths (s) of busy runs and of idle runs between busy ones."""
    on, off = [], []
    if mask.size == 0:
        return on, off
    cur, n = bool(mask[0]), 0
    for m in mask:
        if bool(m) == cur:
            n += 1
        else:
            (on if cur else off).append(n)
            cur, n = bool(m), 1
    (on if cur else off).append(n)
    if not mask[0] and off:
        off.pop(0)  # idle before the first busy second is not a gap
    return on, off


def timeline(rng: np.random.Generator, sample_on, sample_off, total: float) -> list[tuple[float, float]]:
    """Busy intervals (start, end) in [0, total): alternate busy and idle runs starting busy."""
    out, t = [], 0.0
    for _ in range(10000):
        if t >= total:
            break
        on = max(0.2, sample_on())
        out.append((t, min(t + on, total)))
        t += on + max(0.0, sample_off())
    return out or [(0.0, total)]


def place(rng: np.random.Generator, intervals: list[tuple[float, float]], n: int) -> np.ndarray:
    """n sorted times spread over the intervals in proportion to their length."""
    lens = np.array([b - a for a, b in intervals])
    if n <= 0 or lens.sum() <= 0:
        return np.zeros(max(n, 0))
    which = rng.choice(len(intervals), size=n, p=lens / lens.sum())
    starts = np.array([intervals[i][0] for i in which])
    return np.sort(starts + rng.random(n) * lens[which])
