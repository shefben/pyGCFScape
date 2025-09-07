"""Utilities for working with BSP map files.

This module exposes helpers used by the GUI preview widget to detect whether
an arbitrary ``.bsp`` file belongs to the classic Goldsource engine or the
newer Source engine.  The detection is intentionally lightweight so it can be
performed on in-memory data extracted from Steam cache files without writing to
disk.
"""

from __future__ import annotations

import struct
from typing import Literal

Engine = Literal["goldsource", "source"]


def detect_engine(data: bytes) -> Engine:
    """Return the engine family for ``data`` representing a BSP file.

    Goldsource maps begin directly with a 32-bit integer version (30).  Source
    maps prefix the header with the magic string ``VBSP`` followed by a
    version number.  Any unrecognised headers default to ``"source"`` so that
    more modern BSP flavours still render using the Source path.
    """

    if data[:4] == b"VBSP":
        return "source"

    version, = struct.unpack("<I", data[:4])
    if version == 30:
        return "goldsource"
    return "source"
