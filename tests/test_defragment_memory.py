import os
import sys
import tracemalloc
from io import BytesIO
from pathlib import Path

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from pysteam.fs.cachefile import CacheFile, CacheFileManifestEntry


class DummyHeader:
    def __init__(self, sector_size, sector_count):
        self.format_version = 6
        self.cache_type = 1
        self.sector_size = sector_size
        self.sector_count = sector_count

    def serialize(self):
        return b""  # minimal header for testing

    def is_gcf(self):
        return True


class DummyBlocks:
    def __init__(self):
        self.blocks = []
        self.blocks_used = 0
        self.last_block_used = -1

    def serialize(self):
        return b""


class DummyAllocTable:
    def __init__(self, terminator):
        self.entries = []
        self.sector_count = 0
        self.first_unused_entry = 0
        self.is_long_terminator = 1
        self.terminator = terminator
        self.checksum = 0

    def serialize(self):
        return b""


class DummyManifest:
    def __init__(self, entries):
        self.manifest_entries = entries
        self.header_data = b""
        self.manifest_stream = BytesIO(b"")
        self.manifest_map_entries = [0] * len(entries)


class DummyDataHeader:
    def __init__(self, sector_size):
        self.sector_size = sector_size
        self.first_sector_offset = 0
        self.sector_count = 0
        self.sectors_used = 0

    def serialize(self):
        return b""


class DummySector:
    def __init__(self, data):
        self._data = data

    def get_data(self):
        return self._data


class DummyBlock:
    def __init__(self, sectors):
        self._sectors = sectors
        self.next_block = None
        self._first_sector_index = 0
        self.file_data_offset = 0
        self.file_data_size = 0

    @property
    def sectors(self):
        return self._sectors


class DummyEntry:
    def __init__(self, block):
        self.directory_flags = CacheFileManifestEntry.FLAG_IS_FILE
        self.first_block = block


@pytest.mark.parametrize("sectors", [512])
def test_defragment_memory_usage(tmp_path: Path, sectors: int):
    sector_size = 4096
    dummy_data = b"x" * sector_size
    sector_objs = [DummySector(dummy_data) for _ in range(sectors)]
    block = DummyBlock(sector_objs)
    entry = DummyEntry(block)

    cf = CacheFile()
    cf.is_parsed = True
    cf.header = DummyHeader(sector_size, sectors)
    cf.alloc_table = DummyAllocTable(0xFFFFFFFF)
    cf.blocks = DummyBlocks()
    cf.manifest = DummyManifest([entry])
    cf.checksum_map = None
    cf.data_header = DummyDataHeader(sector_size)
    cf.filename = None

    cf._get_item_fragmentation = lambda idx: (1, sectors)

    out_path = tmp_path / "out.gcf"
    progress = []

    def cb(done, total):
        progress.append((done, total))

    tracemalloc.start()
    cf.defragment(str(out_path), cb)
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert progress[-1][0] == progress[-1][1] == sectors * sector_size
    assert peak < 1024 * 1024 * 4  # 4 MiB
    assert out_path.exists()
