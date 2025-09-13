import subprocess
import sys
from pathlib import Path

from pysteam.fs.cachefile import CacheFile


def test_convert_v1_to_v6_has_required_tables(tmp_path):
    data = {
        "a.txt": b"hello world",
        "b.txt": b"B" * (0x4000 + 123),
    }
    # Build latest version then write as v1 and parse again
    cf = CacheFile.build(data, app_id=1, app_version=1)
    v1_path = tmp_path / "test_v1.gcf"
    cf.convert_version(1, v1_path)

    cf_v1 = CacheFile.parse(v1_path)
    v6_path = tmp_path / "roundtrip_v6.gcf"
    cf_v1.convert_version(6, v6_path)

    # Parsed v6 should expose all modern tables
    rebuilt = CacheFile.parse(v6_path)
    assert rebuilt.block_entry_map is None
    assert rebuilt.checksum_map is not None
    assert rebuilt.alloc_table.is_long_terminator == 1
    assert (
        rebuilt.checksum_map.checksum_size
        == len(rebuilt.checksum_map.serialize()) - 8
    )
    assert rebuilt.header.dummy1 == 0
    assert rebuilt.blocks.dummy1 == 0
    assert rebuilt.blocks.dummy2 == 0
    assert rebuilt.blocks.dummy3 == 0
    assert rebuilt.blocks.dummy4 == 0
    assert rebuilt.blocks.checksum == rebuilt.blocks.calculate_checksum()
    assert rebuilt.alloc_table.checksum == rebuilt.alloc_table.calculate_checksum()

    # Reference validator does not support the reduced v6 layout.
