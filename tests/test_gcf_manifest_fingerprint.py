from pysteam.fs.cachefile import CacheFile


def test_manifest_fingerprint_random(tmp_path):
    cf1 = CacheFile.build({"a.txt": b"hello"}, app_id=1, app_version=1)
    cf2 = CacheFile.build({"a.txt": b"hello"}, app_id=1, app_version=1)
    assert cf1.manifest.fingerprint != 0
    assert cf2.manifest.fingerprint != 0
    assert cf1.manifest.fingerprint != cf2.manifest.fingerprint
