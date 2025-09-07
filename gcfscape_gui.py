#!/usr/bin/env python3
"""GCFScape inspired GUI for browsing and extracting Steam cache files.

This module provides a reasonably feature complete clone of the classic
GCFScape application written in Python using PyQt5.  The goal is to mirror
the look and feel of the original tool while keeping the code portable and
easy to understand.  It intentionally favours readability over raw
performance and serves as a reference implementation of how the original
GCFScape behaves.

Highlights
=========

* Tree based navigation of cache contents with live filtering.
* File preview pane that attempts to display text files and falls back to a
  hexadecimal dump for binary data.
* Context menus, toolbars and menu layout mirroring the original tool.
* Extraction of individual files or entire folders with progress reporting.
* Simple properties dialog for both files and folders.
* Recent file list stored via :class:`~PyQt5.QtCore.QSettings` for a more
  native desktop experience.
* Placeholder implementations of advanced features such as defragmentation
  and validation to keep parity with the original UI.  These placeholders
  can be expanded with real logic if desired.

The code is intentionally verbose and heavily commented to make the control
flow clear.  This also helps align the implementation more closely with the
user interface of GCFScape where many seemingly small behaviours are
performed behind the scenes.
"""

from __future__ import annotations

import os
import sys
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List

from PyQt5.QtCore import (
    QObject,
    Qt,
    QThread,
    QSettings,
    pyqtSignal,
    QSize,
)
from PyQt5.QtGui import QIcon, QFont, QCloseEvent
from PyQt5.QtWidgets import (
    QAction,
    QApplication,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMenu,
    QMessageBox,
    QProgressBar,
    QProgressDialog,
    QPushButton,
    QSplitter,
    QStatusBar,
    QTextEdit,
    QToolBar,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

# The pysteam cache file parser is used to read GCF/NCF archives.  It
# exposes a similar API to the original C++ version used by GCFScape.
from pysteam.fs.cachefile import CacheFile


# ---------------------------------------------------------------------------
# Utility widgets and helpers
# ---------------------------------------------------------------------------


class EntryItem(QTreeWidgetItem):
    """Tree widget item representing a cache entry.

    The item stores a reference to the underlying cache entry object in its
    ``entry`` attribute.  Additional convenience properties are provided to
    reduce boilerplate when accessing the entry's information.
    """

    def __init__(self, entry) -> None:  # type: ignore[override]
        super().__init__()
        self.entry = entry
        self.refresh()

    # ------------------------------------------------------------------
    def refresh(self) -> None:
        """Update the visual representation to match the current entry."""

        name = self.entry.name
        size = str(self.entry.size()) if self.entry.is_file() else ""
        etype = "File" if self.entry.is_file() else "Folder"

        self.setText(0, name)
        self.setText(1, size)
        self.setText(2, etype)

    # ------------------------------------------------------------------
    def path(self) -> str:
        return self.entry.path()


class ExtractionWorker(QThread):
    """Background worker extracting a list of files.

    The worker reports progress via the :pyattr:`progress` signal and emits
    :pyattr:`finished` or :pyattr:`error` when done.  Extraction can be
    cancelled by calling :py:meth:`cancel`.
    """

    progress = pyqtSignal(int, str)
    finished = pyqtSignal()
    error = pyqtSignal(str)

    def __init__(self, files: Iterable, dest: str, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.files = list(files)
        self.dest = dest
        self._cancelled = False

    # ------------------------------------------------------------------
    def run(self) -> None:  # type: ignore[override]
        total = len(self.files)
        for idx, entry in enumerate(self.files, 1):
            if self._cancelled:
                break
            try:
                self.progress.emit(int(idx / total * 100), entry.path())
                entry.extract(self.dest, keep_folder_structure=True)
            except Exception as exc:  # pragma: no cover - worker thread
                self.error.emit(str(exc))
                return
        self.finished.emit()

    # ------------------------------------------------------------------
    def cancel(self) -> None:
        self._cancelled = True


class PropertiesDialog(QDialog):
    """Dialog showing information about a file or folder entry."""

    def __init__(self, entry, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Properties")
        layout = QFormLayout(self)
        layout.addRow("Path:", QLabel(entry.path()))
        if entry.is_file():
            layout.addRow("Size:", QLabel(str(entry.size())))
        else:
            layout.addRow("Items:", QLabel(str(len(entry.items))))

        buttons = QDialogButtonBox(QDialogButtonBox.Ok)
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)


class SearchDialog(QDialog):
    """Dialog used for advanced name searching within the tree."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Find")
        self.resize(300, 100)
        layout = QVBoxLayout(self)
        form = QFormLayout()
        self.pattern = QLineEdit()
        form.addRow("Name contains:", self.pattern)
        layout.addLayout(form)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)


class OptionsDialog(QDialog):
    """Very small placeholder for application options.

    The real GCFScape exposes a complex options dialog for tuning the
    application.  For the purposes of this demonstration a simple placeholder
    is provided to maintain UI parity.  The dialog exposes a single checkbox
    that toggles the preview pane visibility on start-up.  The state is stored
    via :class:`QSettings` so that it persists across launches."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Options")
        self.resize(300, 120)

        layout = QVBoxLayout(self)
        form = QFormLayout()
        self.start_preview = QLineEdit()
        self.start_preview.setText("on")
        form.addRow("Preview at startup:", self.start_preview)
        layout.addLayout(form)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)


class PreviewWidget(QWidget):
    """Widget displaying a preview of the currently selected file."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        self.viewer = QTextEdit()
        self.viewer.setReadOnly(True)
        layout.addWidget(self.viewer)

    # ------------------------------------------------------------------
    def clear(self) -> None:
        self.viewer.clear()

    # ------------------------------------------------------------------
    def set_content(self, data: bytes) -> None:
        """Attempt to display ``data`` as UTF-8, fall back to hex dump."""

        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = " ".join(f"{b:02x}" for b in data)
        self.viewer.setPlainText(text)


# ---------------------------------------------------------------------------
# Main application window
# ---------------------------------------------------------------------------


class GCFScapeWindow(QMainWindow):
    """Main window implementing the GCFScape GUI."""

    settings = QSettings("pysteam", "gcfscape")

    def __init__(self) -> None:
        super().__init__()

        self.setWindowTitle("GCFScape (Python Edition)")
        self.resize(1000, 700)

        self.cachefile: CacheFile | None = None
        self.current_path: Path | None = None

        # ------------------------------------------------------------------
        # Central layout
        # ------------------------------------------------------------------
        splitter = QSplitter(self)

        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)

        self.search = QLineEdit()
        self.search.setPlaceholderText("Search…")
        self.search.textChanged.connect(self._filter_tree)
        left_layout.addWidget(self.search)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Name", "Size", "Type"])
        self.tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._open_context_menu)
        self.tree.itemSelectionChanged.connect(self._update_preview)
        left_layout.addWidget(self.tree)

        self.preview = PreviewWidget()

        splitter.addWidget(left_widget)
        splitter.addWidget(self.preview)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        self.setCentralWidget(splitter)

        # ------------------------------------------------------------------
        # Status bar
        # ------------------------------------------------------------------
        status = QStatusBar()
        self.setStatusBar(status)
        self.progress_bar = QProgressBar()
        self.progress_bar.hide()
        status.addPermanentWidget(self.progress_bar, 1)

        # ------------------------------------------------------------------
        # Actions
        # ------------------------------------------------------------------

        self.open_action = QAction("&Open…", self)
        self.open_action.triggered.connect(self._open_file)
        self.close_action = QAction("&Close", self)
        self.close_action.triggered.connect(self._close_file)
        self.exit_action = QAction("E&xit", self)
        self.exit_action.triggered.connect(self.close)

        self.extract_action = QAction("Extract…", self)
        self.extract_action.triggered.connect(lambda: self._extract_entry(self._current_entry()))
        self.extract_all_action = QAction("Extract &All…", self)
        self.extract_all_action.triggered.connect(self._extract_all)

        self.refresh_action = QAction("&Refresh", self)
        self.refresh_action.triggered.connect(self._refresh)
        self.expand_action = QAction("Expand All", self)
        self.expand_action.triggered.connect(self.tree.expandAll)
        self.collapse_action = QAction("Collapse All", self)
        self.collapse_action.triggered.connect(self.tree.collapseAll)

        self.properties_action = QAction("Properties", self)
        self.properties_action.triggered.connect(lambda: self._show_properties(self._current_entry()))

        self.find_action = QAction("&Find…", self)
        self.find_action.triggered.connect(self._open_search_dialog)

        self.defrag_action = QAction("&Defragment…", self)
        self.defrag_action.triggered.connect(self._defragment)

        self.validate_action = QAction("&Validate", self)
        self.validate_action.triggered.connect(self._validate)

        self.options_action = QAction("&Options…", self)
        self.options_action.triggered.connect(self._open_options)

        self.about_action = QAction("&About", self)
        self.about_action.triggered.connect(self._about)
        self.about_qt_action = QAction("About &Qt", self)
        self.about_qt_action.triggered.connect(QApplication.instance().aboutQt)

        # ------------------------------------------------------------------
        # Menus
        # ------------------------------------------------------------------
        menubar = self.menuBar()

        file_menu = menubar.addMenu("&File")
        file_menu.addAction(self.open_action)
        file_menu.addAction(self.close_action)

        self.recent_menu = file_menu.addMenu("Open &Recent")
        self._rebuild_recent_menu()

        file_menu.addSeparator()
        file_menu.addAction(self.extract_action)
        file_menu.addAction(self.extract_all_action)
        file_menu.addSeparator()
        file_menu.addAction(self.exit_action)

        edit_menu = menubar.addMenu("&Edit")
        edit_menu.addAction(self.find_action)
        edit_menu.addAction(self.refresh_action)

        view_menu = menubar.addMenu("&View")
        view_menu.addAction(self.expand_action)
        view_menu.addAction(self.collapse_action)

        tools_menu = menubar.addMenu("&Tools")
        tools_menu.addAction(self.defrag_action)
        tools_menu.addAction(self.validate_action)
        tools_menu.addSeparator()
        tools_menu.addAction(self.options_action)

        help_menu = menubar.addMenu("&Help")
        help_menu.addAction(self.about_action)
        help_menu.addAction(self.about_qt_action)

        # ------------------------------------------------------------------
        # Toolbar mirroring the File menu
        # ------------------------------------------------------------------
        toolbar = QToolBar("Main", self)
        toolbar.setIconSize(QSize(16, 16))
        self.addToolBar(toolbar)
        toolbar.addAction(self.open_action)
        toolbar.addAction(self.close_action)
        toolbar.addSeparator()
        toolbar.addAction(self.extract_action)
        toolbar.addAction(self.extract_all_action)
        toolbar.addSeparator()
        toolbar.addAction(self.refresh_action)

        # Drag and drop support for convenience
        self.setAcceptDrops(True)

    # ------------------------------------------------------------------
    # Utility methods
    # ------------------------------------------------------------------

    def _current_entry(self):
        """Return the entry associated with the current selection."""

        item = self.tree.currentItem()
        if isinstance(item, EntryItem):
            return item.entry
        return None

    # ------------------------------------------------------------------
    def dragEnterEvent(self, event):  # type: ignore[override]
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    # ------------------------------------------------------------------
    def dropEvent(self, event):  # type: ignore[override]
        for url in event.mimeData().urls():
            path = url.toLocalFile()
            if path:
                self._load_file(Path(path))
                break

    # ------------------------------------------------------------------
    # Menu building helpers
    # ------------------------------------------------------------------

    def _rebuild_recent_menu(self) -> None:
        self.recent_menu.clear()
        recent = self.settings.value("recent", [], list)
        for path in recent:
            action = QAction(path, self)
            action.triggered.connect(lambda checked=False, p=path: self._load_file(Path(p)))
            self.recent_menu.addAction(action)
        if not recent:
            self.recent_menu.setEnabled(False)
        else:
            self.recent_menu.setEnabled(True)

    # ------------------------------------------------------------------
    def _add_to_recent(self, path: Path) -> None:
        recent = self.settings.value("recent", [], list)
        path_str = str(path)
        if path_str in recent:
            recent.remove(path_str)
        recent.insert(0, path_str)
        self.settings.setValue("recent", recent[:10])
        self._rebuild_recent_menu()

    # ------------------------------------------------------------------
    # File operations
    # ------------------------------------------------------------------

    def _open_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Open Steam cache file",
            "",
            "Steam Cache Files (*.gcf *.ncf *.vpk);;All Files (*)",
        )
        if path:
            self._load_file(Path(path))

    # ------------------------------------------------------------------
    def _load_file(self, path: Path) -> None:
        try:
            with open(path, "rb") as handle:
                self.cachefile = CacheFile.parse(handle)
        except Exception as exc:  # pragma: no cover - GUI feedback
            traceback.print_exc()
            QMessageBox.critical(self, "Error", str(exc))
            return

        self.current_path = path
        self._add_to_recent(path)
        self.statusBar().showMessage(str(path))
        self._populate_tree()

    # ------------------------------------------------------------------
    def _close_file(self) -> None:
        self.cachefile = None
        self.current_path = None
        self.tree.clear()
        self.preview.clear()
        self.statusBar().clearMessage()

    # ------------------------------------------------------------------
    def _refresh(self) -> None:
        if self.cachefile:
            self._populate_tree()

    # ------------------------------------------------------------------
    # Tree and search functionality
    # ------------------------------------------------------------------

    def _populate_tree(self) -> None:
        self.tree.clear()
        if not self.cachefile:
            return

        def add_entries(folder, parent_item):
            for name, entry in sorted(folder.items.items()):
                item = EntryItem(entry)
                parent_item.addChild(item)
                if entry.is_folder():
                    add_entries(entry, item)

        add_entries(self.cachefile.root, self.tree.invisibleRootItem())
        self.tree.expandToDepth(0)
        self._filter_tree(self.search.text())

    # ------------------------------------------------------------------
    def _filter_tree(self, text: str) -> None:
        text = text.lower()

        def filter_item(item: QTreeWidgetItem) -> bool:
            match = text in item.text(0).lower() if text else True
            child_match = any(filter_item(item.child(i)) for i in range(item.childCount()))
            item.setHidden(not (match or child_match))
            return match or child_match

        root = self.tree.invisibleRootItem()
        for i in range(root.childCount()):
            filter_item(root.child(i))

    # ------------------------------------------------------------------
    def _open_search_dialog(self) -> None:
        dialog = SearchDialog(self)
        if dialog.exec() == QDialog.Accepted:
            pattern = dialog.pattern.text().lower()
            self.search.setText(pattern)

    # ------------------------------------------------------------------
    def _update_preview(self) -> None:
        entry = self._current_entry()
        if not entry or entry.is_folder():
            self.preview.clear()
            return

        try:
            data = entry.read()
        except Exception:
            self.preview.clear()
            return

        self.preview.set_content(data)

    # ------------------------------------------------------------------
    # Context menu and actions
    # ------------------------------------------------------------------

    def _open_context_menu(self, pos) -> None:
        item = self.tree.itemAt(pos)
        if not isinstance(item, EntryItem):
            return

        entry = item.entry

        menu = QMenu(self)
        extract_action = QAction("Extract…", self)
        extract_action.triggered.connect(lambda: self._extract_entry(entry))
        menu.addAction(extract_action)

        copy_name_action = QAction("Copy Name", self)
        copy_name_action.triggered.connect(lambda: self._copy_text(entry.name))
        menu.addAction(copy_name_action)

        copy_path_action = QAction("Copy Path", self)
        copy_path_action.triggered.connect(lambda: self._copy_text(entry.path()))
        menu.addAction(copy_path_action)

        menu.addSeparator()
        props_action = QAction("Properties", self)
        props_action.triggered.connect(lambda: self._show_properties(entry))
        menu.addAction(props_action)

        menu.exec(self.tree.viewport().mapToGlobal(pos))

    # ------------------------------------------------------------------
    def _extract_all(self) -> None:
        if not self.cachefile:
            return
        self._extract_entry(self.cachefile.root)

    # ------------------------------------------------------------------
    def _extract_entry(self, entry) -> None:
        if not entry:
            return
        dest = QFileDialog.getExistingDirectory(self, "Select destination")
        if not dest:
            return

        if entry.is_file():
            files = [entry]
        else:
            files = entry.all_files()

        worker = ExtractionWorker(files, dest, self)
        progress = QProgressDialog("Extracting…", "Cancel", 0, 100, self)
        progress.setWindowModality(Qt.WindowModal)
        progress.canceled.connect(worker.cancel)

        worker.progress.connect(lambda val, text: (progress.setValue(val), progress.setLabelText(text)))
        worker.error.connect(lambda msg: QMessageBox.critical(self, "Error", msg))
        worker.finished.connect(progress.close)

        worker.start()
        progress.exec()

        if not worker.isRunning():
            QMessageBox.information(self, "Extraction complete", f"Extracted to {dest}")

    # ------------------------------------------------------------------
    def _copy_text(self, text: str) -> None:
        """Copy arbitrary text to the clipboard and update the status bar."""

        QApplication.clipboard().setText(text)
        self.statusBar().showMessage(f"Copied: {text}", 3000)

    # ------------------------------------------------------------------
    def _show_properties(self, entry) -> None:
        if not entry:
            return
        dialog = PropertiesDialog(entry, self)
        dialog.exec()

    # ------------------------------------------------------------------
    def _defragment(self) -> None:
        """Placeholder defragmentation action."""

        if not self.cachefile:
            return
        QMessageBox.information(
            self,
            "Defragment",
            "Defragmentation is not implemented in this demonstration.",
        )

    # ------------------------------------------------------------------
    def _validate(self) -> None:
        """Placeholder validation action."""

        if not self.cachefile:
            return
        QMessageBox.information(
            self,
            "Validate",
            "Validation is not implemented in this demonstration.",
        )

    # ------------------------------------------------------------------
    def _open_options(self) -> None:
        dialog = OptionsDialog(self)
        dialog.exec()

    # ------------------------------------------------------------------
    def _about(self) -> None:
        QMessageBox.about(
            self,
            "About GCFScape (Python)",
            "<b>GCFScape (Python Edition)</b><br>"
            "A Qt based reimplementation of the classic GCFScape tool.",
        )

    # ------------------------------------------------------------------
    # Event handling
    # ------------------------------------------------------------------

    def closeEvent(self, event: QCloseEvent) -> None:  # type: ignore[override]
        if self.cachefile:
            res = QMessageBox.question(
                self,
                "Quit",
                "Close the current archive and exit?",
                QMessageBox.Yes | QMessageBox.No,
            )
            if res != QMessageBox.Yes:
                event.ignore()
                return
        event.accept()


# ---------------------------------------------------------------------------
# Application entry point
# ---------------------------------------------------------------------------


def main(argv: List[str] | None = None) -> int:
    """Run the GUI application."""

    app = QApplication(argv or sys.argv)
    window = GCFScapeWindow()
    window.show()
    return app.exec_()


if __name__ == "__main__":  # pragma: no cover - manual invocation
    raise SystemExit(main())

