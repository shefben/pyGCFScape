from pathlib import Path
import vpk
from pysteam.fs.archive import open_archive, VpkArchive


def test_vpk_open_and_edit(tmp_path: Path):
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "a.txt").write_text("hello")
    new = vpk.new(str(src_dir))
    vpk_path = tmp_path / "test.vpk"
    new.save(str(vpk_path))

    archive = open_archive(vpk_path)
    assert isinstance(archive, VpkArchive)
    assert "a.txt" in archive.root.items

    new_file = tmp_path / "b.txt"
    new_file.write_text("world")
    archive.add_file(str(new_file), archive.root.path())
    out_path = tmp_path / "out.vpk"
    archive.save(str(out_path))

    archive2 = open_archive(out_path)
    assert "b.txt" in archive2.root.items


def test_vpk_create_new(tmp_path: Path):
    archive = VpkArchive()
    new_file = tmp_path / "c.txt"
    new_file.write_text("data")
    archive.add_file(str(new_file), "")
    out = tmp_path / "create.vpk"
    archive.save(str(out))

    reopened = open_archive(out)
    assert "c.txt" in reopened.root.items
