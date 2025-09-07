"""Pure Python VTF (Valve Texture Format) reader."""
from __future__ import annotations

import io
import struct
from dataclasses import dataclass
from typing import BinaryIO, Tuple

from .dxt import decode_dxt


@dataclass
class VTFHeader:
    sig: bytes
    version: Tuple[int, int]
    header_size: int
    width: int
    height: int
    flags: int
    frame_count: int
    first_frame: int
    reflectivity: Tuple[float, float, float]
    bumpmap_scale: float
    high_fmt: int
    mipmap_count: int
    low_fmt: int
    low_width: int
    low_height: int
    depth: int
    resource_count: int


def _read_uint(fp: BinaryIO) -> int:
    return struct.unpack('<I', fp.read(4))[0]


def _read_ushort(fp: BinaryIO) -> int:
    return struct.unpack('<H', fp.read(2))[0]


def _read_byte(fp: BinaryIO) -> int:
    return struct.unpack('<B', fp.read(1))[0]


def read_header(fp: BinaryIO) -> VTFHeader:
    sig = fp.read(4)
    if sig != b"VTF\0":
        raise ValueError("Invalid VTF signature")
    version = struct.unpack('<II', fp.read(8))
    header_size = _read_uint(fp)
    width = _read_ushort(fp)
    height = _read_ushort(fp)
    flags = _read_uint(fp)
    frame_count = _read_ushort(fp) or 1
    first_frame = _read_ushort(fp)
    fp.seek(4, 1)
    reflectivity = struct.unpack('<fff', fp.read(12))
    fp.seek(4, 1)
    bumpmap_scale = struct.unpack('<f', fp.read(4))[0]
    high_fmt = _read_uint(fp)
    mipmap_count = _read_byte(fp)
    low_fmt = _read_uint(fp)
    low_width = _read_byte(fp)
    low_height = _read_byte(fp)
    depth = _read_ushort(fp)
    fp.seek(3, 1)
    resource_count = _read_uint(fp)
    fp.seek(8, 1)
    return VTFHeader(
        sig=sig,
        version=version,
        header_size=header_size,
        width=width,
        height=height,
        flags=flags,
        frame_count=frame_count,
        first_frame=first_frame,
        reflectivity=reflectivity,
        bumpmap_scale=bumpmap_scale,
        high_fmt=high_fmt,
        mipmap_count=mipmap_count,
        low_fmt=low_fmt,
        low_width=low_width,
        low_height=low_height,
        depth=depth,
        resource_count=resource_count,
    )


def ruf(x: int) -> int:
    return x + ((4 - (x & 3)) & 3)


def byte_size_fmt(fmt: int, w: int, h: int) -> int:
    if fmt in (0x0, 0x1, 0x0B, 0x0C):
        return w * h * 4
    if fmt in (0x2, 0x3):
        return w * h * 3
    if fmt == 0x0D:
        return ruf(w) * ruf(h) // 2
    if fmt in (0x0E, 0x0F):
        return ruf(w) * ruf(h)
    raise ValueError(f"Unsupported format {fmt:#x}")


def fmt_mip_offset(fmt: int, w: int, h: int, mpm_ct: int, frame_ct: int, mip: int) -> int:
    offset = 0
    for i in range(mip + 1, mpm_ct):
        offset += byte_size_fmt(fmt, w >> i, h >> i) * frame_ct
    return offset


def get_hri_location(fp: BinaryIO, header: VTFHeader) -> int:
    if header.version[1] == 1:
        return 0x40 + byte_size_fmt(header.low_fmt, header.low_width, header.low_height)
    if header.version[1] == 2:
        return (
            0x40
            + byte_size_fmt(header.low_fmt, header.low_width, header.low_height)
            + 0x10 * header.frame_count
        )
    fp.seek(0x50)
    for _ in range(10):
        b = fp.read(1)
        if not b:
            break
        if b[0] == 0x30:
            fp.seek(3, 1)
            return _read_uint(fp)
        fp.seek(7, 1)
    return 0xE8


def _decode_raw(data: bytes, fmt: int, w: int, h: int) -> bytes:
    out = bytearray(w * h * 4)
    if fmt == 0x0:  # RGBA
        out[:] = data
    elif fmt == 0x1:  # ABGR
        for i in range(w * h):
            a, b, g, r = data[i * 4 : i * 4 + 4]
            out[i * 4 : i * 4 + 4] = bytes([r, g, b, a])
    elif fmt == 0x2:  # RGB
        for i in range(w * h):
            r, g, b = data[i * 3 : i * 3 + 3]
            out[i * 4 : i * 4 + 4] = bytes([r, g, b, 255])
    elif fmt == 0x3:  # BGR
        for i in range(w * h):
            b, g, r = data[i * 3 : i * 3 + 3]
            out[i * 4 : i * 4 + 4] = bytes([r, g, b, 255])
    elif fmt == 0x0B:  # ARGB
        for i in range(w * h):
            a, r, g, b = data[i * 4 : i * 4 + 4]
            out[i * 4 : i * 4 + 4] = bytes([r, g, b, a])
    elif fmt == 0x0C:  # BGRA
        for i in range(w * h):
            b, g, r, a = data[i * 4 : i * 4 + 4]
            out[i * 4 : i * 4 + 4] = bytes([r, g, b, a])
    else:
        raise ValueError(f"Unsupported raw format {fmt:#x}")
    return bytes(out)


class VTFFile:
    """Reader for Valve Texture Format data."""

    def __init__(self, data: bytes) -> None:
        fp = io.BytesIO(data)
        self.header = read_header(fp)
        self.hri_offset = get_hri_location(fp, self.header)
        fp.seek(0)
        self.data = fp.read()

    def get_image(self, frame: int = 0, mip: int = 0) -> Tuple[int, int, bytes]:
        h = self.header
        if frame >= h.frame_count:
            raise IndexError("frame out of range")
        if mip >= h.mipmap_count:
            raise IndexError("mip level out of range")
        w = h.width >> mip
        ht = h.height >> mip
        offset = self.hri_offset + fmt_mip_offset(h.high_fmt, h.width, h.height, h.mipmap_count, h.frame_count, mip)
        offset += byte_size_fmt(h.high_fmt, w, ht) * frame
        size = byte_size_fmt(h.high_fmt, w, ht)
        block = self.data[offset : offset + size]
        if h.high_fmt in (0x0D, 0x0F):
            pixels = decode_dxt(block, h.high_fmt, w, ht)
        else:
            pixels = _decode_raw(block, h.high_fmt, w, ht)
        return w, ht, pixels

    @property
    def frame_count(self) -> int:
        return self.header.frame_count

    @property
    def mipmap_count(self) -> int:
        return self.header.mipmap_count
