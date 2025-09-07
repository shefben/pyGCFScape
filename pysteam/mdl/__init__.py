"""Utilities for Valve MDL model files.

This module provides a small helper to detect whether a given MDL file was
built for the Goldsource or Source engine.  The logic is intentionally light
weight and only inspects the header magic and version which is sufficient for
preview purposes.
"""

from __future__ import annotations

import struct
from typing import Literal

EngineType = Literal["Goldsrc", "Source", "Unknown"]

def detect_engine(data: bytes) -> EngineType:
    """Return the engine type for ``data`` representing an MDL file.

    Both Goldsource and Source engine models begin with the magic ``IDST``.
    Goldsource models use version ``10`` (and below) while Source engine models
    typically start at version ``44`` and above.  Any other combination is
    reported as ``Unknown``.
    """
    if len(data) < 8:
        return "Unknown"
    magic, version = struct.unpack_from("<4sI", data)
    if magic != b"IDST":
        return "Unknown"
    if version <= 10:
        return "Goldsrc"
    return "Source"
