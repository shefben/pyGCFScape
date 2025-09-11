import io
from pathlib import Path
from pysteam.fs.cachefile import CacheFile


def test_build_round_trip(tmp_path):
    data = {"hello.txt": b"hello world"}
    cf = CacheFile.build(data, app_id=111, app_version=1)
    out = tmp_path / "test.gcf"
    cf.convert_version(6, out)
    rebuilt = CacheFile.parse(out)
    assert "hello.txt" in rebuilt.root.items
    f = rebuilt.root["hello.txt"].open("rb")
    try:
        assert f.read() == b"hello world"
    finally:
        f.close()

    out_v1 = tmp_path / "test_v1.gcf"
    cf.convert_version(1, out_v1)
    rebuilt_v1 = CacheFile.parse(out_v1)
    assert "hello.txt" in rebuilt_v1.root.items
    f = rebuilt_v1.root["hello.txt"].open("rb")
    try:
        assert f.read() == b"hello world"
    finally:
        f.close()
