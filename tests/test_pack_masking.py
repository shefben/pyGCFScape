import struct
from types import SimpleNamespace

from pysteam.fs.cachefile import (
    CacheFileBlockAllocationTableEntry,
    pack_dword_list,
)


def test_pack_dword_list_masks_out_of_range_values():
    data = pack_dword_list([0x1_0000_0000, -1])
    assert data == struct.pack("<2L", 0, 0xFFFFFFFF)


def test_block_entry_serialize_masks_large_fields():
    cf = SimpleNamespace(header=SimpleNamespace(format_version=6))
    bat = SimpleNamespace(owner=cf)
    entry = CacheFileBlockAllocationTableEntry(bat)
    entry.entry_flags = 0x123456
    entry.dummy0 = 0xABCDEF
    entry.file_data_offset = 0x1_0000_0001
    entry.file_data_size = 0x1_0000_0002
    entry._first_sector_index = 0x1_0000_0003
    entry._next_block_index = 0x1_0000_0004
    entry._prev_block_index = 0x1_0000_0005
    entry.manifest_index = 0x1_0000_0006

    data = entry.serialize()
    expected = struct.pack(
        "<2H6L",
        entry.entry_flags & 0xFFFF,
        entry.dummy0 & 0xFFFF,
        entry.file_data_offset & 0xFFFFFFFF,
        entry.file_data_size & 0xFFFFFFFF,
        entry._first_sector_index & 0xFFFFFFFF,
        entry._next_block_index & 0xFFFFFFFF,
        entry._prev_block_index & 0xFFFFFFFF,
        entry.manifest_index & 0xFFFFFFFF,
    )
    assert data == expected
