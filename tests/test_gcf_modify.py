import os
from pathlib import Path
from pysteam.fs.cachefile import CacheFile

def test_modify_gcf(tmp_path):
    files = {"a.txt": b"A", "dir/b.txt": b"B"}
    cf = CacheFile.build(files, app_id=1, app_version=1)
    orig = tmp_path / "orig.gcf"
    cf.convert_version(6, str(orig))

    cf2 = CacheFile.parse(orig)

    new_file = tmp_path / "c.txt"
    new_file.write_text("C")
    cf2.add_file(str(new_file))
    cf2.remove_file("a.txt")
    cf2.move_file("dir\\b.txt", "d.txt")
    cf2.root["c.txt"].flags = 0x20

    out = tmp_path / "mod.gcf"
    cf2.save(str(out))

    cf3 = CacheFile.parse(out)
    names = sorted(f.path().replace("\\", "/").lstrip("/") for f in cf3.root.all_files())
    assert names == ["c.txt", "d.txt"]
    f1 = cf3.root["c.txt"].open("rb")
    try:
        assert f1.read() == b"C"
    finally:
        f1.close()
    f2 = cf3.root["d.txt"].open("rb")
    try:
        assert f2.read() == b"B"
    finally:
        f2.close()
    assert cf3.root["c.txt"]._manifest_entry.directory_flags & 0x20
