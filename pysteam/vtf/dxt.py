"""DXT texture decompression in pure Python."""
from __future__ import annotations

from typing import List, Tuple


def _color565_to_rgba(c565: int) -> Tuple[int, int, int, int]:
    """Convert 5:6:5 RGB value to 8-bit RGBA tuple."""
    r = ((c565 >> 11) & 0x1F) * 255 // 31
    g = ((c565 >> 5) & 0x3F) * 255 // 63
    b = (c565 & 0x1F) * 255 // 31
    return r, g, b, 255


def _decode_dxt1_block(block: bytes) -> List[Tuple[int, int, int, int]]:
    """Decode a single 4x4 DXT1 block into a list of RGBA tuples."""
    color0 = block[0] | (block[1] << 8)
    color1 = block[2] | (block[3] << 8)
    c0 = _color565_to_rgba(color0)
    c1 = _color565_to_rgba(color1)
    colors = [c0, c1]
    if color0 > color1:
        colors.append(tuple((2 * c0[i] + c1[i]) // 3 for i in range(4)))
        colors.append(tuple((c0[i] + 2 * c1[i]) // 3 for i in range(4)))
    else:
        colors.append(tuple((c0[i] + c1[i]) // 2 for i in range(4)))
        colors.append((0, 0, 0, 0))
    result: List[Tuple[int, int, int, int]] = []
    codes = block[4:8]
    for row in range(4):
        code_row = codes[row]
        for col in range(4):
            code = (code_row >> (col * 2)) & 0x03
            result.append(colors[code])
    return result


def decode_dxt1(data: bytes, width: int, height: int) -> bytes:
    """Decode a DXT1 image to RGBA bytes."""
    out = bytearray(width * height * 4)
    offset = 0
    for y in range(0, height, 4):
        for x in range(0, width, 4):
            block = data[offset:offset + 8]
            offset += 8
            colors = _decode_dxt1_block(block)
            for by in range(4):
                for bx in range(4):
                    px = x + bx
                    py = y + by
                    if px >= width or py >= height:
                        continue
                    idx = (py * width + px) * 4
                    out[idx:idx + 4] = bytes(colors[by * 4 + bx])
    return bytes(out)


def _decode_dxt5_alpha(block: bytes) -> List[int]:
    """Return a list of 16 alpha values decoded from a DXT5 alpha block."""
    a0 = block[0]
    a1 = block[1]
    bits = int.from_bytes(block[2:8], "little")
    alphas = [0] * 16
    table = [a0, a1]
    if a0 > a1:
        for i in range(1, 7):
            table.append(((7 - i) * a0 + i * a1) // 7)
    else:
        for i in range(1, 5):
            table.append(((5 - i) * a0 + i * a1) // 5)
        table.extend([0, 255])
    for i in range(16):
        code = (bits >> (i * 3)) & 0x7
        alphas[i] = table[code]
    return alphas


def decode_dxt5(data: bytes, width: int, height: int) -> bytes:
    """Decode a DXT5 image to RGBA bytes including alpha."""
    out = bytearray(width * height * 4)
    offset = 0
    for y in range(0, height, 4):
        for x in range(0, width, 4):
            alpha_block = data[offset:offset + 8]
            offset += 8
            color_block = data[offset:offset + 8]
            offset += 8
            colors = _decode_dxt1_block(color_block)
            alphas = _decode_dxt5_alpha(alpha_block)
            for by in range(4):
                for bx in range(4):
                    px = x + bx
                    py = y + by
                    if px >= width or py >= height:
                        continue
                    idx = (py * width + px) * 4
                    color = list(colors[by * 4 + bx])
                    color[3] = alphas[by * 4 + bx]
                    out[idx:idx + 4] = bytes(color)
    return bytes(out)


def decode_dxt(data: bytes, fmt: int, width: int, height: int) -> bytes:
    """Decode DXT1 or DXT5 data based on ``fmt``."""
    if fmt == 0x0D:
        return decode_dxt1(data, width, height)
    if fmt == 0x0F:
        return decode_dxt5(data, width, height)
    raise ValueError(f"Unsupported DXT format: {fmt:#x}")
