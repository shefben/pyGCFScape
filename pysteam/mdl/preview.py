"""Qt widget that renders a very small 3D preview of Valve MDL models.

The original implementation only displayed a 2D rectangle representing the
model's bounding box.  This module replaces that approach with a lightweight
``pyqtgraph`` based viewer that renders the bounding box as a 3D wireframe.

Rendering full geometry for MDL files requires parsing additional companion
files (``.vvd``/``.vtx`` for Source models) and is out of scope for this
project, but the bounding box is still a useful visual cue when browsing
archives.
"""

from __future__ import annotations

import struct
from typing import List, Tuple

from PyQt5.QtWidgets import QLabel, QVBoxLayout, QWidget

from . import detect_engine

# ``pyqtgraph`` and ``numpy`` are optional dependencies.  Import them lazily so
# we can show a helpful message when missing.
try:  # pragma: no cover - optional dependencies
    import numpy as np  # type: ignore
    import pyqtgraph.opengl as gl  # type: ignore
except Exception:  # pragma: no cover - missing optional deps
    np = None  # type: ignore
    gl = None  # type: ignore

Vector = Tuple[float, float, float]


class MDLViewWidget(QWidget):
    """Widget capable of displaying a crude 3D MDL preview."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        if gl is None or np is None:
            self.view: QWidget = QLabel("pyqtgraph or numpy module missing")
            layout.addWidget(self.view)
        else:
            self.view = gl.GLViewWidget()
            self.view.setBackgroundColor("k")
            layout.addWidget(self.view)
            self._items: List[gl.GLGraphicsItem] = []

    # ------------------------------------------------------------------
    def clear(self) -> None:
        if gl and hasattr(self, "_items"):
            for item in self._items:
                self.view.removeItem(item)
            self._items.clear()

    # ------------------------------------------------------------------
    def load_model(self, data: bytes) -> None:
        """Render ``data`` containing an MDL model into the widget."""

        engine = detect_engine(data)
        bbox = None
        if engine == "Goldsrc":
            bbox = self._goldsrc_bounds(data)
        elif engine == "Source":
            bbox = self._source_bounds(data)
        if bbox is None:
            if isinstance(self.view, QLabel):
                self.view.setText("Unsupported MDL")
            return

        if not (gl and np):
            if isinstance(self.view, QLabel):
                self.view.setText("pyqtgraph or numpy module missing")
            return

        self.clear()
        self.view.setToolTip(f"{engine} model")

        (min_x, min_y, min_z), (max_x, max_y, max_z) = bbox
        verts = np.array([
            [min_x, min_y, min_z],
            [max_x, min_y, min_z],
            [max_x, max_y, min_z],
            [min_x, max_y, min_z],
            [min_x, min_y, max_z],
            [max_x, min_y, max_z],
            [max_x, max_y, max_z],
            [min_x, max_y, max_z],
        ], dtype=float)
        edges = [
            (0, 1), (1, 2), (2, 3), (3, 0),
            (4, 5), (5, 6), (6, 7), (7, 4),
            (0, 4), (1, 5), (2, 6), (3, 7),
        ]
        for a, b in edges:
            pts = verts[[a, b]]
            item = gl.GLLinePlotItem(pos=pts, color=(1, 1, 1, 1), width=1, mode="line_strip")
            self.view.addItem(item)
            self._items.append(item)

        center = [
            (min_x + max_x) / 2,
            (min_y + max_y) / 2,
            (min_z + max_z) / 2,
        ]
        size = max(max_x - min_x, max_y - min_y, max_z - min_z) or 1.0
        self.view.opts["center"] = center
        self.view.opts["distance"] = size * 2

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

