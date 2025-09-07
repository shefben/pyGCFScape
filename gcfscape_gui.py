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
from PyQt5.QtGui import QIcon, QFont, QCloseEvent, QPixmap
from PyQt5.QtWidgets import (
    QAction,
    QApplication,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QProgressBar,
    QProgressDialog,
    QPushButton,
    QSplitter,
    QStackedWidget,
    QStatusBar,
    QCheckBox,
    QTextEdit,
    QToolBar,
    QTreeWidget,
    QTreeWidgetItem,
    QInputDialog,
    QStyle,
    QVBoxLayout,
    QWidget,
)

# The pysteam cache file parser is used to read GCF/NCF archives.  It
# exposes a similar API to the original C++ version used by GCFScape.
from pysteam.fs.cachefile import CacheFile, CacheFileManifestEntry
from pysteam.bsp.preview import BSPViewWidget
from pysteam.image import ImageViewWidget
from pysteam.vtf.preview import VTFViewWidget
from pysteam.mdl.preview import MDLViewWidget
def is_encrypted(entry) -> bool:
    """Return ``True`` if the manifest flags mark ``entry`` as encrypted."""

    manifest = getattr(entry, "_manifest_entry", None)
    if not manifest:
        return False
    return bool(manifest.directory_flags & CacheFileManifestEntry.FLAG_IS_ENCRYPTED)


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
        icon = QApplication.style().standardIcon(
            QStyle.SP_FileIcon if self.entry.is_file() else QStyle.SP_DirIcon
        )
        if self.entry.is_file() and name.lower().endswith(".ico"):
            try:
                stream = self.entry.open("rb")
                data = stream.readall()
                pix = QPixmap()
                if pix.loadFromData(data):
                    icon = QIcon(pix)
            except Exception:
                pass
        self.setIcon(0, icon)

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

    def __init__(
        self,
        files: Iterable,
        dest: str,
        key: bytes | None = None,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self.files = list(files)
        self.dest = dest
        self.key = key
        self._cancelled = False

    # ------------------------------------------------------------------
    def run(self) -> None:  # type: ignore[override]
        total = len(self.files)
        for idx, entry in enumerate(self.files, 1):
            if self._cancelled:
                break
            try:
                self.progress.emit(int(idx / total * 100), entry.path())
                if is_encrypted(entry) and self.key is None:
                    raise ValueError("File is encrypted but no key was provided")
                entry.extract(self.dest, keep_folder_structure=True, key=self.key)
            except Exception as exc:  # pragma: no cover - worker thread
                self.error.emit(str(exc))
                return
        self.finished.emit()

    # ------------------------------------------------------------------
    def cancel(self) -> None:
        self._cancelled = True


def _format_bytes(value: int) -> str:
    gb = value / (1024 ** 3)
    mb = value / (1024 ** 2)
    kb = value / 1024
    return f"{gb:.2f} GB / {mb:.2f} MB / {kb:.2f} KB / {value} bytes"


def _count_items(folder) -> tuple[int, int]:
    files = 0
    folders = 0
    for item in folder:
        if item.is_file():
            files += 1
        else:
            f, d = _count_items(item)
            files += f
            folders += d + 1
    return files, folders


def _completion(entry) -> float:
    if entry.is_file():
        total = entry.size()
        manifest = getattr(entry, "_manifest_entry", None)
        if not manifest or total == 0:
            return 100.0
        avail = sum(b.file_data_size for b in manifest.blocks if b)
        return 100.0 * min(1.0, avail / total)
    files = entry.all_files()
    total = sum(f.size() for f in files)
    if total == 0:
        return 100.0
    avail = 0
    for f in files:
        manifest = getattr(f, "_manifest_entry", None)
        if manifest:
            avail += sum(b.file_data_size for b in manifest.blocks if b)
    return 100.0 * min(1.0, avail / total)


class PropertiesDialog(QDialog):
    """Dialog showing detailed information about an entry."""

    def __init__(self, entry, window, parent: QWidget | None = None) -> None:
        super().__init__(parent or window)
        self.entry = entry
        self.window = window
        self.cache = window.cachefile
        self.setWindowTitle("Properties")

        layout = QVBoxLayout(self)
        header = QHBoxLayout()

        icon_label = QLabel()
        icon = QApplication.style().standardIcon(
            QStyle.SP_FileIcon if entry.is_file() else QStyle.SP_DirIcon
        )
        if entry.is_file() and entry.name.lower().endswith(".ico"):
            try:
                stream = entry.open("rb")
                data = stream.readall()
                pix = QPixmap()
                if pix.loadFromData(data):
                    icon = QIcon(pix)
            except Exception:
                pass
        icon_label.setPixmap(icon.pixmap(48, 48))
        name = entry.name or getattr(self.cache, "filename", "")
        header.addWidget(icon_label)
        header.addWidget(QLabel(name))
        layout.addLayout(header)

        form = QFormLayout()
        layout.addLayout(form)

        if self.cache and entry is self.cache.root:
            form.addRow("Item type:", QLabel("Cache"))
            location = str(self.window.current_path or "")
            form.addRow("Location:", QLabel(location))
            form.addRow("Size:", QLabel(_format_bytes(entry.size())))
            blocks_used = self.cache.blocks.blocks_used if self.cache.blocks else 0
            sector_size = self.cache.header.sector_size
            form.addRow(
                "Size on disk:",
                QLabel(_format_bytes(blocks_used * sector_size)),
            )
            files, folders = _count_items(entry)
            form.addRow(
                "Contains:",
                QLabel(f"{files + folders} items, {folders} folders"),
            )
            form.addRow(
                "Percent complete:", QLabel(f"{_completion(entry):.0f}%")
            )
            header = self.cache.header
            form.addRow("GCF version:", QLabel(str(header.format_version)))
            form.addRow("Cache ID:", QLabel(str(header.application_id)))
            if self.cache.blocks:
                form.addRow(
                    "Allocated blocks:", QLabel(str(self.cache.blocks.block_count))
                )
                form.addRow(
                    "Used blocks:", QLabel(str(self.cache.blocks.blocks_used))
                )
            form.addRow("Block length:", QLabel(str(header.sector_size)))
            form.addRow(
                "Last played version:", QLabel(str(header.application_version))
            )
            if self.cache.alloc_table:
                allocs = self.cache.alloc_table.sector_count
                form.addRow("Total mapping allocations:", QLabel(str(allocs)))
                form.addRow(
                    "Total mapping memory allocated:",
                    QLabel(_format_bytes(allocs * sector_size)),
                )
                form.addRow(
                    "Total mapping memory used:",
                    QLabel(_format_bytes(blocks_used * sector_size)),
                )
            flags = getattr(self.cache.manifest, "depot_info", 0)
            form.addRow("Flags:", QLabel(hex(flags)))
            form.addRow(
                "Fragmented:",
                QLabel("Yes" if self.cache.is_fragmented() else "No"),
            )
        elif entry.is_folder():
            form.addRow("Item type:", QLabel("Folder"))
            form.addRow("Location:", QLabel(entry.path()))
            form.addRow("Size:", QLabel(_format_bytes(entry.size())))
            files, folders = _count_items(entry)
            form.addRow(
                "Contains:",
                QLabel(f"{files + folders} items, {folders} folders"),
            )
            sector = self.cache.header.sector_size if self.cache else 0
            size_on_disk = (
                sum(getattr(f, "num_of_blocks", 0) for f in entry.all_files())
                * sector
            )
            form.addRow("Size on disk:", QLabel(_format_bytes(size_on_disk)))
            form.addRow(
                "Total file completion:",
                QLabel(f"{_completion(entry):.0f}%"),
            )
            flags = getattr(getattr(entry, "_manifest_entry", None), "directory_flags", 0)
            form.addRow("Flags:", QLabel(hex(flags)))
            frag = any(getattr(f, "is_fragmented", False) for f in entry.all_files())
            form.addRow("Fragmented:", QLabel("Yes" if frag else "No"))
        else:
            form.addRow("Item type:", QLabel("File"))
            form.addRow("Location:", QLabel(entry.path()))
            form.addRow("Size:", QLabel(_format_bytes(entry.size())))
            sector = self.cache.header.sector_size if self.cache else 0
            blocks = getattr(entry, "num_of_blocks", 0)
            form.addRow(
                "Size on disk:", QLabel(_format_bytes(blocks * sector))
            )
            comp = _completion(entry)
            form.addRow("Extractable:", QLabel("True" if comp >= 100 else "False"))
            form.addRow("Completion:", QLabel(f"{comp:.0f}%"))
            manifest = getattr(entry, "_manifest_entry", None)
            flags = manifest.directory_flags if manifest else 0
            form.addRow(
                "Is encrypted:",
                QLabel(str(bool(flags & CacheFileManifestEntry.FLAG_IS_ENCRYPTED))),
            )
            form.addRow(
                "Copy locally:",
                QLabel(str(bool(flags & CacheFileManifestEntry.FLAG_IS_NO_CACHE))),
            )
            form.addRow(
                "Overwrite local copy:",
                QLabel(str(bool(flags & CacheFileManifestEntry.FLAG_IS_LOCKED))),
            )
            form.addRow(
                "Backup local copy:",
                QLabel(str(bool(flags & CacheFileManifestEntry.FLAG_BACKUP_PLZ))),
            )
            form.addRow("Flags:", QLabel(hex(flags)))
            form.addRow(
                "Fragmented:",
                QLabel("Yes" if getattr(entry, "is_fragmented", False) else "No"),
            )

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

    Only a tiny subset of the original tool's preferences are implemented.
    Currently a single checkbox allows toggling the preview pane visibility on
    application start-up.  The value is persisted via :class:`QSettings`.
    """

    def __init__(self, settings: QSettings, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.settings = settings
        self.setWindowTitle("Options")
        self.resize(300, 120)

        layout = QVBoxLayout(self)
        self.preview_check = QCheckBox("Show preview at startup")
        self.preview_check.setChecked(self.settings.value("preview", True, bool))
        layout.addWidget(self.preview_check)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    # ------------------------------------------------------------------
    @property
    def preview_enabled(self) -> bool:
        return self.preview_check.isChecked()

    # ------------------------------------------------------------------
    def accept(self) -> None:  # type: ignore[override]
        self.settings.setValue("preview", self.preview_check.isChecked())
        super().accept()


class PreviewWidget(QWidget):
    """Widget displaying a preview of the currently selected file."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        self.stack = QStackedWidget()
        self.text_view = QTextEdit()
        self.text_view.setReadOnly(True)
        self.image_view = ImageViewWidget()
        self.bsp_view = BSPViewWidget()
        self.vtf_view = VTFViewWidget()
        self.mdl_view = MDLViewWidget()
        self.stack.addWidget(self.text_view)
        self.stack.addWidget(self.image_view)
        self.stack.addWidget(self.bsp_view)
        self.stack.addWidget(self.vtf_view)
        self.stack.addWidget(self.mdl_view)
        layout.addWidget(self.stack)

    # ------------------------------------------------------------------
    def clear(self) -> None:
        self.text_view.clear()
        self.image_view.clear()
        self.bsp_view.clear()
        self.vtf_view.clear()
        self.mdl_view.clear()
        self.stack.setCurrentWidget(self.text_view)

    # ------------------------------------------------------------------
    def set_entry(self, entry) -> None:
        """Display a preview for ``entry`` which may be a BSP or text file."""

        name = entry.name.lower()
        ext = os.path.splitext(name)[1]
        key = None
        if is_encrypted(entry):
            key = self._request_key()
            if key is None:
                self.clear()
                return

        try:
            stream = entry.open("rb", key=key)
            data = stream.readall()
        except Exception:
            self.clear()
            return
        finally:
            try:
                stream.close()
            except Exception:
                pass

        IMAGE_EXTS = {".gif", ".jpg", ".jpeg", ".bmp", ".png", ".tga", ".ico"}
        TEXT_EXTS = {".res", ".txt", ".vmt", ".lst", ".xml", ".vdf", ".html"}

        if ext == ".bsp":
            self.bsp_view.load_map(data)
            self.stack.setCurrentWidget(self.bsp_view)
        elif ext == ".vtf":
            self.vtf_view.load_vtf(data)
            self.stack.setCurrentWidget(self.vtf_view)
        elif ext == ".mdl":
            self.mdl_view.load_model(data)
            self.stack.setCurrentWidget(self.mdl_view)
        elif ext in IMAGE_EXTS:
            self.image_view.load_image(data)
            self.stack.setCurrentWidget(self.image_view)
        elif ext in TEXT_EXTS:
            text = data.decode("utf-8", errors="replace")
            self.text_view.setPlainText(text)
            self.stack.setCurrentWidget(self.text_view)
        else:
            text = " ".join(f"{b:02x}" for b in data)
            self.text_view.setPlainText(text)
            self.stack.setCurrentWidget(self.text_view)

    # ------------------------------------------------------------------
    def _request_key(self) -> bytes | None:
        text, ok = QInputDialog.getText(self, "Encrypted file", "Enter decryption key:")
        if not ok or not text:
            return None
        try:
            return bytes.fromhex(text)
        except ValueError:
            return text.encode("utf-8")


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
        self.entry_to_tree_item: dict = {}

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
        self.tree.setHeaderHidden(True)
        self.tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._open_context_menu)
        self.tree.itemSelectionChanged.connect(self._update_file_list)
        self.tree.itemSelectionChanged.connect(self._update_preview)
        left_layout.addWidget(self.tree)

        right_splitter = QSplitter(Qt.Vertical)
        self.file_list = QTreeWidget()
        self.file_list.setHeaderLabels(["Name", "Size", "Type"])
        self.file_list.setRootIsDecorated(False)
        self.file_list.setItemsExpandable(False)
        self.file_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.file_list.customContextMenuRequested.connect(self._open_context_menu)
        self.file_list.itemSelectionChanged.connect(self._update_preview)
        self.file_list.itemDoubleClicked.connect(self._file_list_double_clicked)
        self.file_list.setSortingEnabled(True)
        header = self.file_list.header()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        right_splitter.addWidget(self.file_list)

        self.preview = PreviewWidget()
        right_splitter.addWidget(self.preview)
        right_splitter.setStretchFactor(0, 3)
        right_splitter.setStretchFactor(1, 1)
        show_preview = self.settings.value("preview", True, bool)
        self.preview.setVisible(show_preview)

        splitter.addWidget(left_widget)
        splitter.addWidget(right_splitter)
        splitter.setStretchFactor(0, 1)
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

        self.preview_toggle_action = QAction("Show Preview", self, checkable=True, checked=show_preview)
        self.preview_toggle_action.toggled.connect(lambda checked: (self.preview.setVisible(checked), self.settings.setValue("preview", checked)))

        self.find_action = QAction("&Find…", self)
        self.find_action.triggered.connect(self._open_search_dialog)

        self.defrag_action = QAction("&Defragment…", self)
        self.defrag_action.triggered.connect(self._defragment)

        self.validate_action = QAction("&Validate", self)
        self.validate_action.triggered.connect(self._validate)

        self.convert_v1_action = QAction("Convert to &V1…", self)
        self.convert_v1_action.triggered.connect(lambda: self._convert_gcf(1))

        self.convert_latest_action = QAction("Convert to &Latest…", self)
        self.convert_latest_action.triggered.connect(lambda: self._convert_gcf(6))

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
        view_menu.addAction(self.preview_toggle_action)

        tools_menu = menubar.addMenu("&Tools")
        tools_menu.addAction(self.defrag_action)
        tools_menu.addAction(self.validate_action)
        tools_menu.addAction(self.convert_v1_action)
        tools_menu.addAction(self.convert_latest_action)
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
        item = self.file_list.currentItem()
        if isinstance(item, EntryItem):
            return item.entry
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
        self.file_list.clear()
        self.preview.clear()
        self.statusBar().clearMessage()
        self.entry_to_tree_item.clear()

    # ------------------------------------------------------------------
    def _refresh(self) -> None:
        if self.cachefile:
            self._populate_tree()

    # ------------------------------------------------------------------
    # Tree and search functionality
    # ------------------------------------------------------------------

    def _populate_tree(self) -> None:
        self.tree.clear()
        self.file_list.clear()
        self.entry_to_tree_item.clear()
        if not self.cachefile:
            return

        root_entry = self.cachefile.root
        root_item = EntryItem(root_entry)
        root_item.setText(0, "root")
        self.tree.addTopLevelItem(root_item)
        self.entry_to_tree_item[root_entry] = root_item

        def add_dirs(folder, parent_item):
            for name, entry in sorted(folder.items.items()):
                if entry.is_folder():
                    item = EntryItem(entry)
                    parent_item.addChild(item)
                    self.entry_to_tree_item[entry] = item
                    add_dirs(entry, item)

        add_dirs(root_entry, root_item)
        self.tree.setCurrentItem(root_item)
        self._update_file_list()
        self.tree.collapseAll()
        self._filter_tree(self.search.text())

    def _current_directory(self):
        item = self.tree.currentItem()
        if isinstance(item, EntryItem):
            return item.entry
        return None

    def _update_file_list(self) -> None:
        self.file_list.clear()
        folder = self._current_directory()
        if not folder:
            return
        for name, entry in sorted(folder.items.items()):
            self.file_list.addTopLevelItem(EntryItem(entry))
        self.preview.clear()
        self.statusBar().showMessage(f"{folder.path()} ({len(folder.items)} items)")

    def _file_list_double_clicked(self, item: QTreeWidgetItem, column: int) -> None:
        if isinstance(item, EntryItem) and item.entry.is_folder():
            tree_item = self.entry_to_tree_item.get(item.entry)
            if tree_item:
                self.tree.setCurrentItem(tree_item)

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

        self.preview.set_entry(entry)
        self.statusBar().showMessage(entry.path())

    # ------------------------------------------------------------------
    # Context menu and actions
    # ------------------------------------------------------------------

    def _open_context_menu(self, pos) -> None:
        widget = self.sender()
        item = widget.itemAt(pos) if isinstance(widget, QTreeWidget) else None
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

        viewport = widget.viewport() if isinstance(widget, QTreeWidget) else None
        if viewport:
            menu.exec(viewport.mapToGlobal(pos))

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

        key = None
        if any(is_encrypted(f) for f in files):
            text, ok = QInputDialog.getText(self, "Encrypted file", "Enter decryption key:")
            if not ok or not text:
                return
            try:
                key = bytes.fromhex(text)
            except ValueError:
                key = text.encode("utf-8")

        worker = ExtractionWorker(files, dest, key, self)
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
        """Run a lightweight fragmentation check.

        The Python port does not currently support rewriting cache files, but
        we mimic the behaviour of GCFScape by informing the user whether the
        archive appears fragmented.
        """

        if not self.cachefile:
            return

        if not self.cachefile.is_fragmented():
            QMessageBox.information(self, "Defragment", "Archive is already defragmented.")
            return

        QMessageBox.warning(
            self,
            "Defragment",
            "This archive appears fragmented.  Defragmentation is not yet implemented in this Python port.",
        )

    # ------------------------------------------------------------------
    def _validate(self) -> None:
        """Validate the currently loaded archive and report any errors."""

        if not self.cachefile:
            return

        errors = self.cachefile.validate()
        if errors:
            text = "\n".join(errors[:20])
            QMessageBox.warning(
                self,
                "Validate",
                f"Problems were detected in the archive:\n{text}",
            )
        else:
            QMessageBox.information(
                self,
                "Validate",
                "Archive appears to be valid.",
            )

    # ------------------------------------------------------------------
    def _convert_gcf(self, target_version: int) -> None:
        """Convert the loaded GCF to a given format version."""

        if not self.cachefile or not self.cachefile.is_gcf():
            QMessageBox.warning(self, "Convert", "No GCF archive loaded.")
            return

        default = os.path.splitext(self.cachefile.filename)[0] + f"_v{target_version}.gcf"
        path, _ = QFileDialog.getSaveFileName(self, "Save Converted GCF", default, "GCF Files (*.gcf)")
        if not path:
            return
        try:
            self.cachefile.convert_version(target_version, path)
            QMessageBox.information(self, "Convert", "Conversion completed.")
        except NotImplementedError:
            QMessageBox.warning(self, "Convert", "Conversion is not yet implemented in this build.")
        except Exception as exc:
            QMessageBox.critical(self, "Convert", f"Conversion failed: {exc}")

    # ------------------------------------------------------------------
    def _open_options(self) -> None:
        dialog = OptionsDialog(self.settings, self)
        if dialog.exec() == QDialog.Accepted:
            self.preview_toggle_action.setChecked(dialog.preview_enabled)

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

