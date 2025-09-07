"""Qt widget capable of rendering a 3D wireframe preview of BSP maps.

The widget relies on the optional :mod:`bsp_tool` package to parse map data
and :mod:`pyqtgraph` for interactive OpenGL rendering.  Users can orbit the
scene with a mouse drag and zoom using the scroll wheel, providing a minimal
yet informative overview of the map geometry.
"""

from __future__ import annotations

import os
import tempfile
from typing import List, Sequence, Tuple

from PyQt5.QtWidgets import QLabel, QVBoxLayout, QWidget

from . import detect_engine

# ``bsp_tool``/``pyqtgraph``/``numpy`` are optional dependencies used for the
# interactive 3D preview.  Import them individually so we can provide more
# helpful error messages when one is missing.
try:  # pragma: no cover - optional dependencies
    import bsp_tool  # type: ignore
except Exception:  # pragma: no cover - missing optional deps
    bsp_tool = None  # type: ignore

try:  # pragma: no cover - optional dependencies
    import numpy as np  # type: ignore
except Exception:  # pragma: no cover - missing optional deps
    np = None  # type: ignore

try:  # pragma: no cover - optional dependencies
    import pyqtgraph.opengl as gl  # type: ignore
except Exception:  # pragma: no cover - missing optional deps
    gl = None  # type: ignore


class BSPViewWidget(QWidget):
    """Widget displaying a simple 3D wireframe preview of a BSP map."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        if gl is None:
            self.view: QWidget = QLabel("pyqtgraph module missing")
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
    def load_map(self, data: bytes) -> None:
        """Render ``data`` representing a BSP file into the widget."""

        if not bsp_tool:
            if isinstance(self.view, QLabel):
                self.view.setText("bsp_tool module missing")
            return
        if not gl:
            if isinstance(self.view, QLabel):
                self.view.setText("pyqtgraph module missing")
            return
        if not np:
            if isinstance(self.view, QLabel):
                self.view.setText("numpy module missing")
            return

        self.clear()
        engine = detect_engine(data)
        self.view.setToolTip(f"{engine} engine")

        # ``bsp_tool`` expects a file path.  Write to a temporary file and parse
        # it, then immediately remove the file once loaded.
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bsp") as tmp:
            tmp.write(data)
            tmp_path = tmp.name
        try:
            bsp = bsp_tool.load_bsp(tmp_path)
        finally:
            try:
                os.unlink(tmp_path)
            except PermissionError:
                pass

        # Gather geometry as a list of polygons, each polygon being a sequence
        # of ``(x, y, z)`` tuples.
        vertices: Sequence = bsp.VERTICES
        surf_edges: Sequence[int] = bsp.SURFEDGES
        edges: Sequence[Tuple[int, int]] = bsp.EDGES
        faces: Sequence = bsp.FACES

        polygons: List[List[Tuple[float, float, float]]] = []
        for face in faces:
            start = getattr(face, "first_edge", getattr(face, "firstEdge", 0))
            length = getattr(face, "num_edges", getattr(face, "numEdges", 0))
            indices: List[int] = []
            for i in range(length):
                e_index = surf_edges[start + i]
                if e_index < 0:
                    edge = edges[-e_index][::-1]
                else:
                    edge = edges[e_index]
                indices.append(edge[0])
            polygon = [(vertices[i].x, vertices[i].y, vertices[i].z) for i in indices]
            if polygon:
                polygons.append(polygon)

        if not polygons:
            if isinstance(self.view, QLabel):
                self.view.setText(f"No geometry ({engine})")
            return

        xs = [x for poly in polygons for x, _, _ in poly]
        ys = [y for poly in polygons for _, y, _ in poly]
        zs = [z for poly in polygons for _, _, z in poly]
        min_x, max_x = min(xs), max(xs)
        min_y, max_y = min(ys), max(ys)
        min_z, max_z = min(zs), max(zs)
        center = [(min_x + max_x) / 2, (min_y + max_y) / 2, (min_z + max_z) / 2]
        size = max(max_x - min_x, max_y - min_y, max_z - min_z) or 1.0

        self.view.opts["center"] = center
        self.view.opts["distance"] = size * 1.5

        for poly in polygons:
            pts = np.array(poly + [poly[0]], dtype=float)
            item = gl.GLLinePlotItem(pos=pts, color=(1, 1, 1, 1), width=1, mode="line_strip")
            self.view.addItem(item)
            self._items.append(item)
