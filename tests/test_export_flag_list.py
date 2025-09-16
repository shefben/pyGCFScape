import os
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from PyQt5.QtWidgets import QApplication, QMessageBox

from gcfscape_gui import GCFScapeWindow, describe_manifest_flags
from pysteam.fs.cachefile import CacheFile, CacheFileManifestEntry


def test_describe_manifest_flags_unknown_bits():
    unknown_bit = 0x80000000
    names = describe_manifest_flags(CacheFileManifestEntry.FLAG_IS_ENCRYPTED | unknown_bit)
    assert "Encrypted" in names
    assert f"0x{unknown_bit:08X}" in names


def test_export_flag_list(tmp_path, monkeypatch):
    app = QApplication.instance() or QApplication([])

    files = {
        "folder/a.txt": b"a",
        "b.txt": b"b",
    }
    cache_file = CacheFile.build(files, app_id=1, app_version=1)

    folder_file = cache_file.root["folder"]["a.txt"]
    folder_file.flags |= (
        CacheFileManifestEntry.FLAG_IS_EXECUTABLE
        | CacheFileManifestEntry.FLAG_IS_ENCRYPTED
    )

    window = GCFScapeWindow()
    window.cachefile = cache_file
    window.current_path = tmp_path / "sample.gcf"

    export_path = tmp_path / "flags.txt"
    calls = []

    def fake_get_save_file_name(*_args, **_kwargs):
        calls.append(1)
        return str(export_path), "Text Files (*.txt)"

    def fail_dialog(*_args, **_kwargs):
        raise AssertionError("unexpected modal dialog")

    monkeypatch.setattr("gcfscape_gui.QFileDialog.getSaveFileName", fake_get_save_file_name)
    monkeypatch.setattr("gcfscape_gui.QMessageBox.critical", fail_dialog)
    monkeypatch.setattr("gcfscape_gui.QMessageBox.warning", fail_dialog)
    monkeypatch.setattr("gcfscape_gui.QMessageBox.question", lambda *_a, **_k: QMessageBox.Yes)

    window._export_flag_list()

    assert len(calls) == 1

    data = export_path.read_text(encoding="utf-8").splitlines()
    assert data[0] == "Path\tFlags\tFlag Names"

    expected_lines = {
        f"root\\b.txt\t{hex(cache_file.root['b.txt'].flags)}\tFile",
        (
            "root\\folder\\a.txt\t"
            f"{hex(folder_file.flags)}\tExecutable, Encrypted, File"
        ),
    }

    assert set(data[1:]) == expected_lines

    window.close()
