from pysteam.fs.cachefile import CacheFile, CacheFileBlockAllocationTableEntry


def test_block_entry_layout(tmp_path):
    cf = CacheFile.build({"a.txt": b"hello"}, app_id=1, app_version=1)
    out = tmp_path / "test.gcf"
    cf.convert_version(6, out)
    rebuilt = CacheFile.parse(out)
    entry = rebuilt.blocks.blocks[0]
    assert entry.entry_flags == CacheFileBlockAllocationTableEntry.FLAG_DATA
    assert entry.dummy0 == CacheFileBlockAllocationTableEntry.DUMMY0
