from pysteam.fs.cachefile import CacheFile


def test_v6_checksum_validation(tmp_path):
    data = {"a.txt": b"hello", "b.txt": b"world"}
    cf = CacheFile.build(data, app_id=1, app_version=1)
    out = tmp_path / "test.gcf"
    cf.convert_version(6, out)
    cf.close()
    rebuilt = CacheFile.parse(out)
    assert rebuilt.validate() == []
