from pysteam.fs.cachefile import CacheFile, CacheFileManifest, CacheFileManifestEntry


def test_manifest_flags(tmp_path):
    flags = {
        "cfg.txt": CacheFileManifestEntry.FLAG_IS_USER_CONFIG
        | CacheFileManifestEntry.FLAG_IS_PURGE_FILE
    }
    mflags = CacheFileManifest.FLAG_BUILD_MODE | CacheFileManifest.FLAG_IS_PURGE_ALL
    cf = CacheFile.build({"cfg.txt": b"hi"}, app_id=1, app_version=1, flags=flags, manifest_flags=mflags)

    out = tmp_path / "test.gcf"
    cf.convert_version(6, out)
    rebuilt = CacheFile.parse(out)
    assert rebuilt.manifest.depot_info == mflags
    entry = rebuilt.root["cfg.txt"]._manifest_entry
    assert entry.index in rebuilt.manifest.user_config_entries
    assert entry.index in rebuilt.manifest.minimum_footprint_entries
