import struct
from types import SimpleNamespace
from io import BytesIO

from pysteam.fs.cachefile import CacheFileBlockAllocationTableEntry


def test_parse_and_serialize_v1_block_entry():
    # Craft a v1 block entry with a 32-bit flags field that includes
    # high bits to ensure proper splitting across the v6 layout.
    flags = 0x80004004
    raw = struct.pack("<7L", flags, 1, 2, 3, 4, 5, 6)

    cf = SimpleNamespace(header=SimpleNamespace(format_version=1))
    bat = SimpleNamespace(owner=cf)
    entry = CacheFileBlockAllocationTableEntry(bat)
    entry.parse(BytesIO(raw))

    assert entry.flags == flags
    assert entry.entry_flags == flags & 0xFFFF
    assert entry.dummy0 == (flags >> 16) & 0xFFFF

    # Serialising with v1 layout should reproduce the original bytes.
    assert entry.serialize() == raw

    # Switching to a v6 header should emit the split flag structure.
    cf.header.format_version = 6
    expected_v6 = struct.pack("<2H6L", flags & 0xFFFF, (flags >> 16) & 0xFFFF, 1, 2, 3, 4, 5, 6)
    assert entry.serialize() == expected_v6
