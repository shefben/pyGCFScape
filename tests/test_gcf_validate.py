import os
from pysteam.fs.cachefile import CacheFile


def test_validate_detects_missing_data(tmp_path):
    data = {"big.bin": b"A" * 10000}
    cf = CacheFile.build(data, app_id=1, app_version=1)
    out = tmp_path / "big.gcf"
    cf.convert_version(6, out)
    cf2 = CacheFile.parse(out)
    mentry = cf2.manifest.manifest_entries[1]
    block = mentry.first_block
    assert block and block._next_block_index != cf2.alloc_table.terminator
    block._next_block_index = cf2.alloc_table.terminator
    errors = cf2.validate()
    assert any("size mismatch" in e for e in errors)
    complete, total = cf2.count_complete_files()
    assert complete == 0 and total == 1

