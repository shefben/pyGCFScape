"""Hex/ASCII preview widget with side-by-side text column."""
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
    """Display bytes in hex with decoded text at the side."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setColumnCount(18)
        headers = ["Offset"] + [f"{i:02X}" for i in range(16)] + ["Decoded text"]
        self.setHorizontalHeaderLabels(headers)
        self.verticalHeader().setVisible(False)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.Fixed)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setSelectionBehavior(QAbstractItemView.SelectItems)

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
            ascii_chars: List[str] = []
            for col in range(16):
                idx = row * 16 + col
                if idx >= len(data):
                    hex_text = ""
                    ascii_chars.append("")
                else:
                    byte = data[idx]
                    hex_text = f"{byte:02X}"
                    ascii_chars.append(chr(byte) if 32 <= byte < 127 else ".")
                hex_item = QTableWidgetItem(hex_text)
                hex_item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
                self.setItem(row, 1 + col, hex_item)
            ascii_item = QTableWidgetItem("".join(ascii_chars))
            ascii_item.setFlags(Qt.ItemIsEnabled)
            self.setItem(row, 17, ascii_item)
        for col in range(17):
            self.horizontalHeader().resizeSection(col, 24)
        self.horizontalHeader().resizeSection(17, 160)
