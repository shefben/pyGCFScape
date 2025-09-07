"""Generic image preview widget using Qt's image plugins."""
from __future__ import annotations

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QImage, QPixmap
from PyQt5.QtWidgets import QLabel, QVBoxLayout, QWidget


class ImageViewWidget(QWidget):
    """Widget displaying standard image formats.

    The widget relies solely on Qt's built-in image plugins so formats such as
    GIF, JPEG, BMP, PNG, TGA and ICO are supported without external
    dependencies.
    """

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
    def load_image(self, data: bytes) -> None:
        image = QImage.fromData(data)
        if image.isNull():
            self.label.setText("Unsupported image format")
            self.label.setPixmap(QPixmap())
            return
        self.label.setPixmap(QPixmap.fromImage(image))
        self.label.setToolTip(f"{image.width()}x{image.height()} image")
