"""Qt widget capable of rendering a top-down preview of BSP maps.

The widget relies on the :mod:`bsp_tool` package to parse both Goldsource and
Source engine map formats.  Geometry is rendered using simple 2D line drawing
via :class:`PyQt5.QtGui.QPainter`, providing a lightweight preview that works
in headless environments and does not require an OpenGL context.
"""

from __future__ import annotations

import os
import tempfile
from typing import List, Sequence, Tuple

from PyQt5.QtCore import QPointF, Qt
from PyQt5.QtGui import QPainter, QPixmap
from PyQt5.QtWidgets import (
    QGraphicsScene,
    QGraphicsView,
    QVBoxLayout,
    QWidget,
)

from . import detect_engine

try:  # pragma: no cover - optional dependency
    import bsp_tool
except Exception:  # pragma: no cover - if unavailable the widget will display an error
    bsp_tool = None  # type: ignore


class BSPViewWidget(QWidget):
    """Widget displaying a very small top-down preview of a BSP map."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.view = _ZoomView()
        self.scene = QGraphicsScene(self)
        self.view.setScene(self.scene)
        layout.addWidget(self.view)

    # ------------------------------------------------------------------
    def clear(self) -> None:
        self.scene.clear()

    # ------------------------------------------------------------------
    def load_map(self, data: bytes) -> None:
        """Render ``data`` representing a BSP file into the label."""

        if not bsp_tool:
            self.label.setText("bsp_tool module missing")
            return

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
        # of ``(x, y)`` tuples.  The logic mirrors the approach used by both
        # reference viewers with minimal abstraction.
        vertices: Sequence = bsp.VERTICES
        surf_edges: Sequence[int] = bsp.SURFEDGES
        edges: Sequence[Tuple[int, int]] = bsp.EDGES
        faces: Sequence = bsp.FACES

        polygons: List[List[Tuple[float, float]]] = []
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
            polygon = [(vertices[i].x, vertices[i].y) for i in indices]
            polygons.append(polygon)

        if not polygons:
            self.scene.clear()
            self.scene.addText(f"No geometry ({engine})")
            return

        xs = [x for poly in polygons for x, _ in poly]
        ys = [y for poly in polygons for _, y in poly]
        min_x, max_x = min(xs), max(xs)
        min_y, max_y = min(ys), max(ys)
        width = max_x - min_x or 1.0
        height = max_y - min_y or 1.0

        pixmap = QPixmap(400, 300)
        pixmap.fill(Qt.black)
        painter = QPainter(pixmap)
        painter.setPen(Qt.white)
        scale = min((pixmap.width() - 20) / width, (pixmap.height() - 20) / height)
        for poly in polygons:
            pts = [
                QPointF((x - min_x) * scale + 10, (max_y - y) * scale + 10)
                for x, y in poly
            ]
            for i in range(len(pts)):
                painter.drawLine(pts[i], pts[(i + 1) % len(pts)])
        painter.end()

        self.scene.clear()
        self.scene.addPixmap(pixmap)
        self.view.fitInView(self.scene.itemsBoundingRect(), Qt.KeepAspectRatio)


class _ZoomView(QGraphicsView):
    def __init__(self):
        super().__init__()
        self.setDragMode(QGraphicsView.ScrollHandDrag)
        self.setTransformationAnchor(QGraphicsView.AnchorUnderMouse)

    def wheelEvent(self, event):
        factor = 1.25 if event.angleDelta().y() > 0 else 0.8
        self.scale(factor, factor)

    def keyPressEvent(self, event):
        step = 20
        if event.key() == Qt.Key_Left:
            self.horizontalScrollBar().setValue(self.horizontalScrollBar().value() - step)
        elif event.key() == Qt.Key_Right:
            self.horizontalScrollBar().setValue(self.horizontalScrollBar().value() + step)
        elif event.key() == Qt.Key_Up:
            self.verticalScrollBar().setValue(self.verticalScrollBar().value() - step)
        elif event.key() == Qt.Key_Down:
            self.verticalScrollBar().setValue(self.verticalScrollBar().value() + step)
        else:
            super().keyPressEvent(event)
