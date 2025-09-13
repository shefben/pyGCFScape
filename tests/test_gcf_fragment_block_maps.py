from pysteam.fs.cachefile import CacheFile


def test_fragment_block_maps(tmp_path):
    big = b"x" * (0x2000 + 100)
    cf = CacheFile.build({"big.bin": big}, app_id=1, app_version=1)

    out_v6 = tmp_path / "test_v6.gcf"
    cf.convert_version(6, out_v6)
    rebuilt_v6 = CacheFile.parse(out_v6)

    assert rebuilt_v6.block_entry_map is not None
    assert rebuilt_v6.block_entry_map.entries == list(
        range(rebuilt_v6.blocks.block_count)
    )

    entry = rebuilt_v6.root["big.bin"]._manifest_entry
    first = rebuilt_v6.manifest.manifest_map_entries[entry.index]
    alloc = rebuilt_v6.alloc_table
    assert alloc.entries[first] == first + 1
    assert alloc.entries[first + 1] == alloc.terminator

    out_v1 = tmp_path / "test_v1.gcf"
    cf.convert_version(1, out_v1)
    rebuilt_v1 = CacheFile.parse(out_v1)
    assert rebuilt_v1.block_entry_map is not None
    assert rebuilt_v1.block_entry_map.entries == list(
        range(rebuilt_v1.blocks.block_count)
    )
