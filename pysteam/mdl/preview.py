"""Qt widget that draws a simple preview of Valve MDL models.

The implementation is intentionally lightweight – it does not attempt to render
textured meshes or support camera interaction.  Instead it reads the model
bounding box from the MDL header and draws a wireframe rectangle representing
the front view.  This mirrors the minimalist preview behaviour in other parts
of the application and keeps the dependency footprint small.

When a model is selected the widget automatically detects whether it targets the
Goldsource or Source engine and adjusts the bounding box offsets accordingly.
"""

from __future__ import annotations

import struct
from typing import Tuple

from PyQt5.QtCore import QPointF, Qt
from PyQt5.QtGui import QPainter, QPixmap
from PyQt5.QtWidgets import QLabel, QVBoxLayout, QWidget

from . import detect_engine

Vector = Tuple[float, float, float]

class MDLViewWidget(QWidget):
    """Widget capable of displaying a crude MDL preview."""

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
    def load_model(self, data: bytes) -> None:
        """Render ``data`` containing an MDL model into the label."""

        engine = detect_engine(data)
        bbox = None
        if engine == "Goldsrc":
            bbox = self._goldsrc_bounds(data)
        elif engine == "Source":
            bbox = self._source_bounds(data)
        if bbox is None:
            self.label.setText("Unsupported MDL")
            return
        self.label.setToolTip(f"{engine} model")
        (min_x, min_y, min_z), (max_x, max_y, max_z) = bbox
        width = max_x - min_x or 1.0
        height = max_z - min_z or 1.0
        pixmap = QPixmap(self.width() or 300, self.height() or 300)
        pixmap.fill(Qt.black)
        painter = QPainter(pixmap)
        painter.setPen(Qt.white)
        scale = min((pixmap.width() - 20) / width, (pixmap.height() - 20) / height)
        def map_pt(x: float, z: float) -> QPointF:
            return QPointF((x - min_x) * scale + 10, (max_z - z) * scale + 10)
        pts = [
            map_pt(min_x, min_z),
            map_pt(max_x, min_z),
            map_pt(max_x, max_z),
            map_pt(min_x, max_z),
        ]
        for i in range(len(pts)):
            painter.drawLine(pts[i], pts[(i + 1) % len(pts)])
        painter.end()
        self.label.setPixmap(pixmap)

    # ------------------------------------------------------------------
    def _goldsrc_bounds(self, data: bytes) -> Tuple[Vector, Vector] | None:
        """Return bounding box for a Goldsource model."""

        # Offsets taken from ``studiohdr_t`` in the Goldsource SDK.
        if len(data) < 136:
            return None
        bbmin = struct.unpack_from("<3f", data, 112)
        bbmax = struct.unpack_from("<3f", data, 124)
        return bbmin, bbmax

    # ------------------------------------------------------------------
    def _source_bounds(self, data: bytes) -> Tuple[Vector, Vector] | None:
        """Return bounding box for a Source engine model."""

        # Offsets taken from ``studiohdr_t`` in the Source SDK.
        if len(data) < 152:
            return None

        view_bbmin = struct.unpack_from("<3f", data, 128)
        view_bbmax = struct.unpack_from("<3f", data, 140)
        if any(view_bbmin) or any(view_bbmax):
            return view_bbmin, view_bbmax

        hull_min = struct.unpack_from("<3f", data, 104)
        hull_max = struct.unpack_from("<3f", data, 116)
        return hull_min, hull_max
