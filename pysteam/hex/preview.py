"""Hex/ASCII preview widget with side-by-side text column."""
from __future__ import annotations

from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import QPlainTextEdit


class HexViewWidget(QPlainTextEdit):
    """Display bytes in hex with decoded text at the side."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setReadOnly(True)
        self.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.setFont(QFont("monospace"))

    def clear(self) -> None:  # type: ignore[override]
        self.setPlainText("")

    def load_data(self, data: bytes) -> None:
        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i : i + 16]
            hex_part = " ".join(f"{b:02X}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{hex_part:<47} {ascii_part}")
        self.setPlainText("\n".join(lines))

