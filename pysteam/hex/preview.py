"""Hex/ASCII preview widget with linked selection."""
from __future__ import annotations

from typing import List

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QAbstractItemView,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
)

class HexViewWidget(QTableWidget):
    """Display bytes in hex alongside ASCII with coupled selection."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setColumnCount(33)
        headers = ["Offset"] + [f"{i:02X}" for i in range(16)] + [f"{i:02X}" for i in range(16)]
        self.setHorizontalHeaderLabels(headers)
        self.verticalHeader().setVisible(False)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.Fixed)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setSelectionBehavior(QAbstractItemView.SelectItems)
        self.itemSelectionChanged.connect(self._sync_selection)
        self._syncing = False

    def clear(self) -> None:  # type: ignore[override]
        self.setRowCount(0)

    def load_data(self, data: bytes) -> None:
        self.clear()
        row_count = (len(data) + 15) // 16
        self.setRowCount(row_count)
        for row in range(row_count):
            offset_item = QTableWidgetItem(f"{row * 16:08X}")
            offset_item.setFlags(Qt.ItemIsEnabled)
            self.setItem(row, 0, offset_item)
            for col in range(16):
                idx = row * 16 + col
                hex_item = QTableWidgetItem("" if idx >= len(data) else f"{data[idx]:02X}")
                asc_item = QTableWidgetItem("" if idx >= len(data) else chr(data[idx]) if 32 <= data[idx] < 127 else '.')
                hex_item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
                asc_item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
                self.setItem(row, 1 + col, hex_item)
                self.setItem(row, 17 + col, asc_item)
        for col in range(33):
            self.horizontalHeader().resizeSection(col, 24)

    def _sync_selection(self) -> None:
        if self._syncing:
            return
        self._syncing = True
        try:
            selected = self.selectedIndexes()
            for index in selected:
                row = index.row()
                col = index.column()
                if 1 <= col <= 16:
                    counterpart = self.model().index(row, col + 16)
                    if counterpart not in selected:
                        self.selectionModel().select(counterpart, self.selectionModel().Select)
                elif 17 <= col <= 32:
                    counterpart = self.model().index(row, col - 16)
                    if counterpart not in selected:
                        self.selectionModel().select(counterpart, self.selectionModel().Select)
        finally:
            self._syncing = False
