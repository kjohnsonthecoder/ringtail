"""Generate the extension icons (16, 32, 48, 128 px) with only the standard library.

    python scripts/make_icons.py

The mark: a ring-tailed band of alternating amber and dark stripes on a dark rounded
square, with a bright center dot (a rule that fires). Drawn at 8x and averaged down for
smooth edges. Output: extension/icons/icon-<size>.png
"""

from __future__ import annotations

import math
import struct
import zlib
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "extension" / "icons"

BG = (15, 18, 22)          # near-black navy
AMBER = (240, 160, 48)
DARK_STRIPE = (60, 44, 24)
DOT = (255, 214, 140)
SS = 8                     # supersampling factor


def _pixel(x: float, y: float) -> tuple[int, int, int, int]:
    """Color at (x, y) in unit coordinates [0, 1)."""
    # Rounded-square background with radius 0.22.
    r = 0.22
    cx = min(max(x, r), 1 - r)
    cy = min(max(y, r), 1 - r)
    if (x - cx) ** 2 + (y - cy) ** 2 > r * r:
        return (0, 0, 0, 0)
    dx, dy = x - 0.5, y - 0.5
    d = math.hypot(dx, dy)
    if d < 0.09:
        return (*DOT, 255)
    if 0.20 < d < 0.40:
        # Eight stripes around the ring, alternating amber and dark.
        a = (math.atan2(dy, dx) + math.pi) / (2 * math.pi)
        return (*(AMBER if int(a * 8) % 2 == 0 else DARK_STRIPE), 255)
    return (*BG, 255)


def render(size: int) -> bytes:
    rows = []
    n = size * SS
    for py in range(size):
        row = bytearray([0])  # filter: none
        for px in range(size):
            acc = [0, 0, 0, 0]
            for sy in range(SS):
                for sx in range(SS):
                    c = _pixel((px * SS + sx + 0.5) / n, (py * SS + sy + 0.5) / n)
                    a = c[3]
                    acc[0] += c[0] * a
                    acc[1] += c[1] * a
                    acc[2] += c[2] * a
                    acc[3] += a
            alpha = acc[3] / (SS * SS)
            if acc[3]:
                row += bytes([round(acc[0] / acc[3]), round(acc[1] / acc[3]), round(acc[2] / acc[3]), round(alpha)])
            else:
                row += bytes([0, 0, 0, 0])
        rows.append(bytes(row))
    raw = b"".join(rows)

    def chunk(tag: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)  # 8-bit RGBA
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b"")


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for size in (16, 32, 48, 128):
        (OUT / f"icon-{size}.png").write_bytes(render(size))
        print(f"wrote extension/icons/icon-{size}.png")


if __name__ == "__main__":
    main()
