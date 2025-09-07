"""Qt widget capable of displaying VTF textures."""
from __future__ import annotations

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QImage, QPixmap
from PyQt5.QtWidgets import QLabel, QVBoxLayout, QWidget

from .reader import VTFFile


class VTFViewWidget(QWidget):
    """Widget displaying the first frame/mip of a VTF texture."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.label = QLabel("No preview")
        self.label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.label)

    # ------------------------------------------------------------------
    def clear(self) -> None:
        self.label.setText("No preview")
        self.label.setPixmap(QPixmap())

    # ------------------------------------------------------------------
    def load_vtf(self, data: bytes) -> None:
        try:
            vtf = VTFFile(data)
            w, h, pixels = vtf.get_image()
            image = QImage(pixels, w, h, QImage.Format_RGBA8888)
            self.label.setPixmap(QPixmap.fromImage(image))
            self.label.setToolTip(f"{w}x{h} VTF")
        except Exception as exc:  # pragma: no cover - user feedback
            self.label.setText(str(exc))
            self.label.setPixmap(QPixmap())
