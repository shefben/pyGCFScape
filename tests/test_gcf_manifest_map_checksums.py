from pysteam.fs.cachefile import CacheFile, CacheFileManifestEntry


def test_manifest_map_and_checksum_header(tmp_path):
    data = {"a.txt": b"hello", "dir/b.txt": b"world"}
    cf = CacheFile.build(data, app_id=2, app_version=3)
    out = tmp_path / "out.gcf"
    cf.convert_version(6, out)
    cf.close()

    rebuilt = CacheFile.parse(out)

    blocks = rebuilt.blocks.block_count
    for entry, idx in zip(
        rebuilt.manifest.manifest_entries, rebuilt.manifest.manifest_map_entries
    ):
        if not (entry.directory_flags & CacheFileManifestEntry.FLAG_IS_FILE):
            assert idx == blocks

    csum_map = rebuilt.checksum_map
    assert csum_map.latest_application_version == rebuilt.header.application_version
    assert csum_map.verify_signature()
    expected_len = (
        24 + csum_map.file_id_count * 8 + csum_map.checksum_count * 4 + 128 + 4
    )
    assert len(csum_map.serialize()) == expected_len
