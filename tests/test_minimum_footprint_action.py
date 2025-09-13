import os
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

from PyQt5.QtWidgets import QApplication

from gcfscape_gui import GCFScapeWindow
from pysteam.fs.cachefile import CacheFile, CacheFileManifestEntry


def test_minimum_footprint_action_toggle(tmp_path):
    app = QApplication.instance() or QApplication([])

    files = {
        "folder/a.txt": b"a",
        "folder/b.txt": b"b",
        "c.txt": b"c",
    }
    cf = CacheFile.build(files, app_id=1, app_version=1)

    win = GCFScapeWindow()
    win.cachefile = cf

    folder = cf.root["folder"]
    file_c = cf.root["c.txt"]
    win._selected_entries = lambda: [folder, file_c]

    win._toggle_minimum_footprint(True)

    indices = set(cf.manifest.minimum_footprint_entries)
    assert cf.root["folder"]["a.txt"].index in indices
    assert cf.root["folder"]["b.txt"].index in indices
    assert cf.root["c.txt"].index in indices

    flag = CacheFileManifestEntry.FLAG_IS_PURGE_FILE
    assert cf.root["folder"]["a.txt"].flags & flag
    assert cf.root["c.txt"].flags & flag

    win._update_edit_actions()
    assert win.minimum_footprint_action.isChecked()

    win._toggle_minimum_footprint(False)

    assert cf.manifest.minimum_footprint_entries == []
    assert not cf.root["folder"]["a.txt"].flags & flag
    assert not cf.root["c.txt"].flags & flag

    win._update_edit_actions()
    assert not win.minimum_footprint_action.isChecked()
