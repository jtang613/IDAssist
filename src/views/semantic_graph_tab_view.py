#!/usr/bin/env python3

import json
import math
import shutil
import subprocess
from datetime import datetime
from typing import Any, Dict, List, Optional

from PySide6.QtCore import Qt, Signal, QPointF
from PySide6.QtGui import (
    QFont, QFontDatabase, QTextCursor, QBrush, QColor, QPen,
    QPainterPath, QPainter, QPolygonF, QMouseEvent
)
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QTabWidget,
    QGroupBox, QGridLayout, QSplitter, QListWidget, QListWidgetItem, QTableWidget,
    QTableWidgetItem, QComboBox, QTextEdit, QCheckBox, QSpinBox, QGraphicsView,
    QGraphicsScene, QGraphicsPathItem, QGraphicsLineItem, QGraphicsTextItem, QGraphicsItem,
    QGraphicsPolygonItem, QProgressBar, QSizePolicy,
    QScrollArea,
    QFrame, QRadioButton, QButtonGroup, QAbstractItemView, QInputDialog
)

from .semantic_graph.manual_analysis_panel import ManualAnalysisPanel


class ClickableGraphicsView(QGraphicsView):
    """QGraphicsView that emits a signal on double-click with the clicked node data."""
    node_double_clicked = Signal(object)

    def mouseDoubleClickEvent(self, event: QMouseEvent):
        item = self.itemAt(event.pos())
        if item:
            node_data = item.data(0)
            # If no data on this item, check parent (text items are children of rects)
            if not node_data and item.parentItem():
                node_data = item.parentItem().data(0)
            if node_data:
                self.node_double_clicked.emit(node_data)
                return
        super().mouseDoubleClickEvent(event)


class SemanticGraphTabView(QWidget):
    go_requested = Signal(str)
    reset_requested = Signal()
    reindex_requested = Signal()
    semantic_analysis_requested = Signal()
    security_analysis_requested = Signal()
    network_flow_requested = Signal()
    community_detection_requested = Signal()
    refresh_names_requested = Signal()
    navigate_requested = Signal(int)
    index_function_requested = Signal(int)
    save_summary_requested = Signal(str)
    add_flag_requested = Signal(str)
    remove_flag_requested = Signal(str)
    edge_clicked = Signal(str)
    visual_refresh_requested = Signal(int, list)
    search_query_requested = Signal(str, dict)

    def __init__(self):
        super().__init__()
        self._current_address = 0
        self._current_node_id = None
        self._build_ui()
        self.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)

    def _build_ui(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(5, 5, 5, 5)

        header = QHBoxLayout()
        header.addWidget(QLabel("Current:"))
        self.current_field = QLineEdit()
        self.current_field.setPlaceholderText("Function name or address")
        header.addWidget(self.current_field)
        self.go_button = QPushButton("Go")
        header.addWidget(self.go_button)
        layout.addLayout(header)

        self.status_label = QLabel("Status: No program loaded")
        layout.addWidget(self.status_label)

        self.subtabs = QTabWidget()
        self.list_view = SemanticGraphListView()
        self.graph_view = SemanticGraphGraphView()
        self.search_view = SemanticGraphSearchView()
        self.manual_analysis_view = ManualAnalysisPanel()
        # Allow all sub-views to shrink freely so IDA docking can resize
        for sub in (self.list_view, self.graph_view, self.search_view, self.manual_analysis_view):
            sub.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        self.subtabs.addTab(self.list_view, "List View")
        self.subtabs.addTab(self.graph_view, "Visual Graph")
        self.subtabs.addTab(self.search_view, "Search")
        self.subtabs.addTab(self.manual_analysis_view, "Manual Analysis")
        layout.addWidget(self.subtabs)

        bottom = QHBoxLayout()
        self.reset_button = QPushButton("Reset Graph")
        self.reset_button.setToolTip("Delete all indexed data for this binary.")
        bottom.addWidget(self.reset_button)

        self.reindex_button = QPushButton("ReIndex Binary")
        self.reindex_button.setToolTip("Full Pipeline: Extract structure, then run Security, Network Flow, and Community Detection analyses.")
        bottom.addWidget(self.reindex_button)

        self.semantic_button = QPushButton("Semantic Analysis")
        self.semantic_button.setToolTip("Use LLM to generate summaries for unsummarized functions.")
        bottom.addWidget(self.semantic_button)

        # Progress indicator widget (hidden by default)
        self.bottom_progress_container = QWidget()
        progress_layout = QHBoxLayout(self.bottom_progress_container)
        progress_layout.setContentsMargins(10, 0, 0, 0)

        self.bottom_progress_bar = QProgressBar()
        self.bottom_progress_bar.setRange(0, 100)
        self.bottom_progress_bar.setValue(0)
        self.bottom_progress_bar.setTextVisible(True)
        self.bottom_progress_bar.setMaximumWidth(200)
        self.bottom_progress_bar.setFixedHeight(22)
        progress_layout.addWidget(self.bottom_progress_bar)

        self.bottom_progress_label = QLabel("")
        self.bottom_progress_label.setStyleSheet("color: gray; font-size: 11px;")
        progress_layout.addWidget(self.bottom_progress_label)

        self.bottom_progress_container.setVisible(False)
        bottom.addWidget(self.bottom_progress_container)

        bottom.addStretch()
        layout.addLayout(bottom)

        self.stats_label = QLabel("Graph Stats: Not loaded")
        layout.addWidget(self.stats_label)

        self.setLayout(layout)
        self._wire_signals()

    def _wire_signals(self):
        self.go_button.clicked.connect(self._on_go_clicked)
        self.current_field.returnPressed.connect(self._on_go_clicked)
        self.reset_button.clicked.connect(self.reset_requested.emit)
        self.reindex_button.clicked.connect(self.reindex_requested.emit)
        self.semantic_button.clicked.connect(self.semantic_analysis_requested.emit)

        # Manual Analysis Panel signals
        self.manual_analysis_view.reindex_requested.connect(self.reindex_requested.emit)
        self.manual_analysis_view.semantic_analysis_requested.connect(self.semantic_analysis_requested.emit)
        self.manual_analysis_view.security_analysis_requested.connect(self.security_analysis_requested.emit)
        self.manual_analysis_view.network_flow_requested.connect(self.network_flow_requested.emit)
        self.manual_analysis_view.community_detection_requested.connect(self.community_detection_requested.emit)
        self.manual_analysis_view.refresh_names_requested.connect(self.refresh_names_requested.emit)

        self.list_view.navigate_requested.connect(self.navigate_requested.emit)
        self.list_view.index_function_requested.connect(self._emit_index_current)
        self.list_view.reindex_requested.connect(self.reindex_requested.emit)
        self.list_view.save_summary_requested.connect(self.save_summary_requested.emit)
        self.list_view.add_flag_requested.connect(self.add_flag_requested.emit)
        self.list_view.remove_flag_requested.connect(self.remove_flag_requested.emit)
        self.list_view.edge_clicked.connect(self.edge_clicked.emit)

        self.graph_view.navigate_requested.connect(self.navigate_requested.emit)
        self.graph_view.index_function_requested.connect(self._emit_index_current)
        self.graph_view.reindex_requested.connect(self.reindex_requested.emit)
        self.graph_view.refresh_requested.connect(self.visual_refresh_requested.emit)

        self.search_view.query_requested.connect(self.search_query_requested.emit)
        self.search_view.navigate_requested.connect(self.navigate_requested.emit)

    def _on_go_clicked(self):
        text = self.current_field.text().strip()
        if text:
            self.go_requested.emit(text)

    def _emit_index_current(self):
        self.index_function_requested.emit(self._current_address)

    def update_location(self, address: int, function_name: Optional[str]):
        self._current_address = address
        display = f"{function_name} @ 0x{address:x}" if function_name else f"0x{address:x}"
        self.current_field.setText(display)
        self.search_view.update_current_address(address)
        if self.subtabs.currentWidget() == self.list_view:
            self.list_view.refresh()
        elif self.subtabs.currentWidget() == self.graph_view:
            self.graph_view.refresh()

    def update_status(self, indexed: bool, caller_count: int, callee_count: int, flag_count: int):
        if indexed:
            self.status_label.setText(
                f"Status: Indexed | {caller_count} callers | {callee_count} callees | {flag_count} security flags"
            )
        else:
            self.status_label.setText("Status: Not Indexed")

    def update_stats(self, node_count: int, edge_count: int, stale_count: int, last_indexed: Optional[str]):
        if node_count == 0:
            self.stats_label.setText("Graph Stats: Not indexed")
        else:
            timestamp = self._format_timestamp(last_indexed)
            self.stats_label.setText(
                f"Graph Stats: {node_count} nodes | {edge_count} edges | {stale_count} stale | Last indexed: {timestamp}"
            )

    def set_current_node_id(self, node_id: Optional[str]):
        self._current_node_id = node_id

    def get_current_address(self) -> int:
        return self._current_address

    @staticmethod
    def _format_timestamp(value: Optional[str]) -> str:
        if value is None:
            return "unknown"
        if isinstance(value, (int, float)):
            epoch = float(value)
        else:
            text = str(value).strip()
            if text.isdigit():
                epoch = float(text)
            else:
                return text or "unknown"
        if epoch > 1e12:
            epoch /= 1000.0
        try:
            return datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return "unknown"

    def show_bottom_progress(self):
        """Show the bottom progress indicator."""
        self.bottom_progress_container.setVisible(True)

    def hide_bottom_progress(self):
        """Hide the bottom progress indicator and reset values."""
        self.bottom_progress_container.setVisible(False)
        self.bottom_progress_bar.setValue(0)
        self.bottom_progress_bar.setFormat("0%")
        self.bottom_progress_label.setText("")

    def set_bottom_progress(self, current: int, total: int, message: str = ""):
        """Update the bottom progress indicator."""
        if total > 0:
            percent = int((current / total) * 100)
            self.bottom_progress_bar.setValue(percent)
            self.bottom_progress_bar.setFormat(f"{percent}%")
        else:
            self.bottom_progress_bar.setValue(0)
            self.bottom_progress_bar.setFormat("0%")

        self.bottom_progress_label.setText(message if message else "")

        if not self.bottom_progress_container.isVisible():
            self.bottom_progress_container.setVisible(True)

    def is_rag_enabled(self) -> bool:
        """Return whether RAG is enabled for semantic analysis."""
        return self.manual_analysis_view.is_rag_enabled()

    def is_mcp_enabled(self) -> bool:
        """Return whether MCP is enabled for semantic analysis."""
        return self.manual_analysis_view.is_mcp_enabled()

    def is_force_enabled(self) -> bool:
        """Return whether force re-analysis is enabled for semantic analysis."""
        return self.manual_analysis_view.is_force_enabled()


class SemanticGraphListView(QWidget):
    index_function_requested = Signal(int)
    reindex_requested = Signal()
    navigate_requested = Signal(int)
    save_summary_requested = Signal(str)
    add_flag_requested = Signal(str)
    remove_flag_requested = Signal(str)
    edge_clicked = Signal(str)

    KNOWN_FLAGS = [
        "BUFFER_OVERFLOW_RISK",
        "COMMAND_INJECTION_RISK",
        "FORMAT_STRING_RISK",
        "USE_AFTER_FREE_RISK",
        "PATH_TRAVERSAL_RISK",
        "INTEGER_OVERFLOW_RISK",
        "NULL_DEREF_RISK",
        "MEMORY_LEAK_RISK",
        "RACE_CONDITION_RISK",
        "HANDLES_USER_INPUT",
        "PARSES_NETWORK_DATA",
        "CRYPTO_OPERATION",
        "AUTHENTICATION",
    ]

    def __init__(self):
        super().__init__()
        self._all_edges: List[Dict[str, Any]] = []
        self._editing_summary = False
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout()

        self.stack = QStackedFrame()
        self.content_widget = QWidget()
        self.placeholder_widget = self._build_placeholder()

        content_layout = QHBoxLayout()
        left = QVBoxLayout()
        right = QVBoxLayout()

        self.callers_list = QListWidget()
        self.callers_list.itemDoubleClicked.connect(self._navigate_from_list)
        callers_group = self._wrap_group("CALLERS", self.callers_list)
        left.addWidget(callers_group)

        self.callees_list = QListWidget()
        self.callees_list.itemDoubleClicked.connect(self._navigate_from_list)
        callees_group = self._wrap_group("CALLEES", self.callees_list)
        left.addWidget(callees_group)

        self.edge_filter = QComboBox()
        self.edge_filter.addItems(
            ["All Types", "calls", "references", "calls_vulnerable", "similar_purpose",
             "taint_flows_to", "vulnerable_via", "network_send", "network_recv"]
        )
        self.edge_filter.currentIndexChanged.connect(self._refresh_edges_table)

        self.edges_table = QTableWidget(0, 4)
        self.edges_table.setHorizontalHeaderLabels(["Type", "Target", "Weight", "Actions"])
        self.edges_table.setSelectionMode(QAbstractItemView.NoSelection)
        self.edges_table.setEditTriggers(QAbstractItemView.NoEditTriggers)

        edges_box = QWidget()
        edges_layout = QVBoxLayout()
        filter_row = QHBoxLayout()
        filter_row.addWidget(QLabel("Filter:"))
        filter_row.addWidget(self.edge_filter)
        filter_row.addStretch()
        edges_layout.addLayout(filter_row)
        edges_layout.addWidget(self.edges_table)
        edges_box.setLayout(edges_layout)
        left.addWidget(self._wrap_group("EDGES", edges_box))

        self.flags_container = QWidget()
        self.flags_layout = QVBoxLayout()
        self.flags_container.setLayout(self.flags_layout)
        self.flags_scroll = QScrollArea()
        self.flags_scroll.setWidgetResizable(True)
        self.flags_scroll.setFrameShape(QFrame.NoFrame)
        self.flags_scroll.setWidget(self.flags_container)
        flags_group = self._wrap_group("SECURITY FLAGS", self.flags_scroll)
        right.addWidget(flags_group)

        self.add_flag_button = QPushButton("+ Add Custom Flag...")
        self.add_flag_button.clicked.connect(self._prompt_add_flag)
        right.addWidget(self.add_flag_button)

        self.summary_area = QTextEdit()
        self.summary_area.setReadOnly(True)
        self.summary_area.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))
        summary_group = self._wrap_group("LLM SUMMARY", self.summary_area)
        right.addWidget(summary_group)

        self.edit_summary_button = QPushButton("Edit")
        self.edit_summary_button.clicked.connect(self._toggle_summary_edit)
        right.addWidget(self.edit_summary_button)

        content_layout.addLayout(left, 3)
        content_layout.addLayout(right, 2)
        self.content_widget.setLayout(content_layout)

        self.stack.addWidget(self.placeholder_widget)
        self.stack.addWidget(self.content_widget)
        layout.addWidget(self.stack)
        self.setLayout(layout)
        self.show_not_indexed()

    def _wrap_group(self, title: str, widget: QWidget) -> QGroupBox:
        box = QGroupBox(title)
        inner = QVBoxLayout()
        inner.addWidget(widget)
        box.setLayout(inner)
        return box

    def _build_placeholder(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout()
        label = QLabel("Function not yet indexed in the knowledge graph.")
        label.setAlignment(Qt.AlignCenter)
        layout.addWidget(label)
        index_button = QPushButton("Index This Function")
        index_button.clicked.connect(lambda: self.index_function_requested.emit(0))
        layout.addWidget(index_button)
        reindex_button = QPushButton("ReIndex Binary")
        reindex_button.clicked.connect(self.reindex_requested.emit)
        layout.addWidget(reindex_button)
        widget.setLayout(layout)
        return widget

    def show_not_indexed(self):
        self.stack.setCurrentWidget(self.placeholder_widget)

    def show_content(self):
        self.stack.setCurrentWidget(self.content_widget)

    def refresh(self):
        pass

    def set_callers(self, callers: List[Dict[str, Any]]):
        self.callers_list.clear()
        for entry in callers:
            item = QListWidgetItem(f"{entry['name']} @ 0x{entry['address']:x}")
            item.setData(Qt.UserRole, entry["address"])
            self.callers_list.addItem(item)

    def set_callees(self, callees: List[Dict[str, Any]]):
        self.callees_list.clear()
        for entry in callees:
            item = QListWidgetItem(f"{entry['name']} @ 0x{entry['address']:x}")
            item.setData(Qt.UserRole, entry["address"])
            self.callees_list.addItem(item)

    def set_edges(self, edges: List[Dict[str, Any]]):
        self._all_edges = edges
        self._refresh_edges_table()

    def _refresh_edges_table(self):
        self.edges_table.setRowCount(0)
        filter_val = self.edge_filter.currentText()
        for edge in self._all_edges:
            if filter_val != "All Types" and edge["type"] != filter_val:
                continue
            row = self.edges_table.rowCount()
            self.edges_table.insertRow(row)
            self.edges_table.setItem(row, 0, QTableWidgetItem(edge["type"]))
            self.edges_table.setItem(row, 1, QTableWidgetItem(edge["target"]))
            self.edges_table.setItem(row, 2, QTableWidgetItem(f"{edge.get('weight', 1.0):.2f}"))
            button = QPushButton("View")
            button.clicked.connect(lambda _=None, target=edge["target"]: self.edge_clicked.emit(target))
            self.edges_table.setCellWidget(row, 3, button)

    def set_security_flags(self, flags: List[str]):
        while self.flags_layout.count():
            item = self.flags_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        flags_set = set(flags)
        for known in self.KNOWN_FLAGS:
            cb = QCheckBox(known)
            cb.setChecked(known in flags_set)
            cb.stateChanged.connect(lambda state, f=known: self._toggle_flag(f, state))
            self.flags_layout.addWidget(cb)

        for flag in flags:
            if flag in self.KNOWN_FLAGS:
                continue
            cb = QCheckBox(flag)
            cb.setChecked(True)
            cb.stateChanged.connect(lambda state, f=flag: self._toggle_flag(f, state))
            self.flags_layout.addWidget(cb)

        self.flags_layout.addStretch()

    def set_summary(self, summary: str):
        self.summary_area.setPlainText(summary or "")
        self.summary_area.moveCursor(QTextCursor.Start)

    def _toggle_summary_edit(self):
        if self._editing_summary:
            summary = self.summary_area.toPlainText()
            self.summary_area.setReadOnly(True)
            self.edit_summary_button.setText("Edit")
            self._editing_summary = False
            self.save_summary_requested.emit(summary)
        else:
            self.summary_area.setReadOnly(False)
            self.edit_summary_button.setText("Save")
            self._editing_summary = True

    def _prompt_add_flag(self):
        flag, ok = QInputDialog.getText(self, "Add Security Flag", "Enter custom security flag:")
        if not ok:
            return
        if flag:
            clean = flag.strip().upper().replace(" ", "_")
            self.add_flag_requested.emit(clean)

    def _toggle_flag(self, flag: str, state: int):
        if state == Qt.Checked:
            self.add_flag_requested.emit(flag)
        else:
            self.remove_flag_requested.emit(flag)

    def _navigate_from_list(self, item: QListWidgetItem):
        address = item.data(Qt.UserRole)
        if address is not None:
            self.navigate_requested.emit(int(address))


class SemanticGraphGraphView(QWidget):
    refresh_requested = Signal(int, list)
    navigate_requested = Signal(int)
    index_function_requested = Signal(int)
    reindex_requested = Signal()

    NODE_WIDTH = 120
    NODE_HEIGHT = 60
    NODE_RADIUS = 6
    NODE_TEXT_SCALE = 0.8
    EDGE_LABEL_SCALE = 0.7
    ARROW_SIZE = 8.0
    EDGE_STUB_RATIO = 0.2

    def __init__(self):
        super().__init__()
        self._nodes = []
        self._edges = []
        self._node_items = {}
        self._node_sizes = {}
        self._selected_node = None
        self._colors = {
            "background": QColor("#1f2123"),
            "node": QColor("#3a3f44"),
            "node_text": QColor("#e6e6e6"),
            "center": QColor("#2ea8b3"),
            "center_text": QColor("#ffffff"),
            "vuln": QColor("#7a2b2b"),
            "vuln_text": QColor("#ffd6d6"),
            "edge_calls": QColor("#58a6ff"),
            "edge_refs": QColor("#7a7f87"),
            "edge_vuln": QColor("#ff5c5c"),
            "edge_network": QColor("#06b6d4"),  # cyan-500
        }
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout()

        self.stack = QStackedFrame()
        self.content_widget = QWidget()
        self.placeholder_widget = self._build_placeholder()

        content_layout = QVBoxLayout()

        controls = QHBoxLayout()
        controls.addWidget(QLabel("N-Hops:"))
        self.n_hops = QSpinBox()
        self.n_hops.setRange(1, 5)
        self.n_hops.setValue(2)
        self.n_hops.valueChanged.connect(self._on_refresh)
        controls.addWidget(self.n_hops)

        controls.addWidget(QLabel("Edge Types:"))
        self.calls_cb = QCheckBox("CALLS")
        self.calls_cb.setChecked(True)
        self.vuln_cb = QCheckBox("VULN")
        self.vuln_cb.setChecked(True)
        self.network_cb = QCheckBox("NETWORK")
        self.network_cb.setChecked(True)
        for cb in (self.calls_cb, self.vuln_cb, self.network_cb):
            cb.stateChanged.connect(self._on_refresh)
            controls.addWidget(cb)
        controls.addStretch()

        zoom_box = QHBoxLayout()
        zoom_box.addWidget(QLabel("Zoom:"))
        self.zoom_out = QPushButton("-")
        self.zoom_out.setFixedWidth(24)
        self.zoom_out.clicked.connect(self._zoom_out)
        self.zoom_label = QLabel("100%")
        self.zoom_in = QPushButton("+")
        self.zoom_in.setFixedWidth(24)
        self.zoom_in.clicked.connect(self._zoom_in)
        self.zoom_fit = QPushButton("Fit")
        self.zoom_fit.clicked.connect(self._zoom_fit)
        zoom_box.addWidget(self.zoom_out)
        zoom_box.addWidget(self.zoom_label)
        zoom_box.addWidget(self.zoom_in)
        zoom_box.addWidget(self.zoom_fit)
        controls.addLayout(zoom_box)

        content_layout.addLayout(controls)

        self.scene = QGraphicsScene()
        self.scene.selectionChanged.connect(self._on_selection_changed)
        self.view = ClickableGraphicsView(self.scene)
        self.view.setRenderHint(QPainter.Antialiasing, True)
        self.view.setBackgroundBrush(QBrush(self._colors["background"]))
        self.view.node_double_clicked.connect(self._on_node_double_clicked)

        # Summary area - renders markdown inline
        self.summary_text = QTextEdit()
        self.summary_text.setReadOnly(True)
        self.summary_text.setMinimumHeight(40)
        self.summary_text.setPlaceholderText("Select a node to view its summary. Double-click to navigate.")
        self.summary_text.setStyleSheet("QTextEdit { background-color: #1e1e1e; color: #d4d4d4; border: 1px solid #3c3c3c; }")

        # Splitter for resizable graph/summary
        self.splitter = QSplitter(Qt.Vertical)
        self.splitter.addWidget(self.view)
        self.splitter.addWidget(self.summary_text)
        self.splitter.setStretchFactor(0, 4)
        self.splitter.setStretchFactor(1, 1)
        self.splitter.setSizes([500, 140])
        content_layout.addWidget(self.splitter)

        self.content_widget.setLayout(content_layout)
        self.stack.addWidget(self.placeholder_widget)
        self.stack.addWidget(self.content_widget)
        self.stack.setCurrentWidget(self.placeholder_widget)

        layout.addWidget(self.stack)
        self.setLayout(layout)

    def _build_placeholder(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout()
        label = QLabel("Function not yet indexed in the knowledge graph.")
        label.setAlignment(Qt.AlignCenter)
        layout.addWidget(label)
        index_button = QPushButton("Index This Function")
        index_button.clicked.connect(lambda: self.index_function_requested.emit(0))
        layout.addWidget(index_button)
        reindex_button = QPushButton("ReIndex Binary")
        reindex_button.clicked.connect(self.reindex_requested.emit)
        layout.addWidget(reindex_button)
        widget.setLayout(layout)
        return widget

    def show_not_indexed(self):
        self.scene.clear()
        self.summary_text.clear()
        self.stack.setCurrentWidget(self.placeholder_widget)

    def show_content(self):
        self.stack.setCurrentWidget(self.content_widget)

    def refresh(self):
        self._on_refresh()

    def build_graph(self, center_node: Dict[str, Any], nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]]):
        self._nodes = nodes
        self._edges = edges
        self.scene.clear()
        self._node_items.clear()

        self._node_sizes = self._compute_node_sizes(nodes)
        positions, _ = self._layout_nodes(center_node, nodes, edges, self._node_sizes)
        for node in nodes:
            pos = positions.get(node["id"], (0, 0))
            width = self._node_sizes.get(node["id"], self.NODE_WIDTH)
            item = self._add_node_item(node, pos[0], pos[1], node["id"] == center_node["id"], width)
            self._node_items[node["id"]] = item

        edge_paths = self._compute_edge_paths(edges)
        for idx, edge in enumerate(edges):
            src = self._node_items.get(edge["source_id"])
            tgt = self._node_items.get(edge["target_id"])
            if src and tgt:
                edge_color, edge_width, dash = self._edge_style(edge["type"])
                pen = QPen(edge_color, edge_width)
                if dash:
                    pen.setStyle(Qt.DashLine)
                if edge_paths and idx in edge_paths:
                    points = edge_paths[idx]
                    if len(points) >= 2:
                        path = QPainterPath()
                        path.moveTo(points[0][0], points[0][1])
                        for x, y in points[1:]:
                            path.lineTo(x, y)
                        path_item = QGraphicsPathItem(path)
                        path_item.setPen(pen)
                        path_item.setZValue(-2)
                        self.scene.addItem(path_item)
                        self._add_edge_label(points, edge["type"], edge_color)
                        self._add_arrowhead(points[-2], points[-1], edge_color)
                        continue
                src_center = src.sceneBoundingRect().center()
                tgt_center = tgt.sceneBoundingRect().center()
                line = QGraphicsLineItem(src_center.x(), src_center.y(),
                                         tgt_center.x(), tgt_center.y())
                line.setPen(pen)
                line.setZValue(-2)
                self.scene.addItem(line)
                self._add_edge_label(
                    [(src_center.x(), src_center.y()), (tgt_center.x(), tgt_center.y())],
                    edge["type"],
                    edge_color,
                )
                self._add_arrowhead(
                    (src_center.x(), src_center.y()),
                    (tgt_center.x(), tgt_center.y()),
                    edge_color,
                )
        self._zoom_reset(self._node_items.get(center_node["id"]))

        center_item = self._node_items.get(center_node["id"])
        if center_item:
            center_item.setSelected(True)
        self._selected_node = center_node
        self._set_summary_content(center_node)

    def _add_node_item(self, node: Dict[str, Any], x: float, y: float, is_center: bool, width: float):
        path = QPainterPath()
        path.addRoundedRect(0, 0, width, self.NODE_HEIGHT,
                            self.NODE_RADIUS, self.NODE_RADIUS)
        rect = QGraphicsPathItem(path)
        rect.setPos(x, y)
        fill, text_color = self._node_style(node, is_center)
        rect.setBrush(QBrush(fill))
        rect.setPen(QPen(QColor("#2a2d30"), 1))
        rect.setFlag(QGraphicsItem.ItemIsSelectable)
        rect.setData(0, node)
        label = node["label"]
        address = node.get("address", 0)
        text = QGraphicsTextItem(f"{label}\n0x{address:x}")
        text.setFont(self._node_font())
        text.setDefaultTextColor(text_color)
        text.setParentItem(rect)
        text.setTextWidth(width - 12)
        text.setPos(6, 4)
        self.scene.addItem(rect)
        return rect

    def _compute_edge_paths(self, edges: List[Dict[str, Any]]) -> Dict[int, List[tuple]]:
        side_edges: Dict[tuple, List[tuple]] = {}
        edge_sides: Dict[int, tuple] = {}
        edge_centers: Dict[int, tuple] = {}

        for idx, edge in enumerate(edges):
            src = self._node_items.get(edge["source_id"])
            tgt = self._node_items.get(edge["target_id"])
            if not src or not tgt:
                continue
            src_center = src.sceneBoundingRect().center()
            tgt_center = tgt.sceneBoundingRect().center()
            if tgt_center.y() >= src_center.y():
                src_side, tgt_side = "bottom", "top"
            else:
                src_side, tgt_side = "top", "bottom"
            edge_sides[idx] = (src_side, tgt_side)
            edge_centers[idx] = (src_center, tgt_center)
            side_edges.setdefault((edge["source_id"], src_side), []).append((tgt_center.x(), idx))
            side_edges.setdefault((edge["target_id"], tgt_side), []).append((src_center.x(), idx))

        edge_offsets: Dict[tuple, float] = {}
        for key, entries in side_edges.items():
            node_id, _ = key
            node_item = self._node_items.get(node_id)
            node_width = node_item.sceneBoundingRect().width() if node_item else self.NODE_WIDTH
            count = len(entries)
            entries.sort(key=lambda item: item[0])
            available = max(10.0, node_width - 20.0)
            if count == 1:
                offsets = [0.0]
            else:
                step = available / (count - 1)
                offsets = [-(available / 2.0) + step * idx for idx in range(count)]
            for offset, (_, edge_idx) in zip(offsets, entries):
                edge_offsets[(key[0], key[1], edge_idx)] = offset

        paths: Dict[int, List[tuple]] = {}
        stub_len = self.NODE_HEIGHT * self.EDGE_STUB_RATIO
        for idx, edge in enumerate(edges):
            src = self._node_items.get(edge["source_id"])
            tgt = self._node_items.get(edge["target_id"])
            if not src or not tgt or idx not in edge_sides:
                continue
            src_side, tgt_side = edge_sides[idx]
            src_rect = src.sceneBoundingRect()
            tgt_rect = tgt.sceneBoundingRect()
            src_center_x = src_rect.center().x()
            tgt_center_x = tgt_rect.center().x()
            src_offset = edge_offsets.get((edge["source_id"], src_side, idx), 0.0)
            tgt_offset = edge_offsets.get((edge["target_id"], tgt_side, idx), 0.0)

            src_x = src_center_x + src_offset
            tgt_x = tgt_center_x + tgt_offset
            src_y = src_rect.top() if src_side == "top" else src_rect.bottom()
            tgt_y = tgt_rect.top() if tgt_side == "top" else tgt_rect.bottom()
            src_stub = (src_x, src_y - stub_len) if src_side == "top" else (src_x, src_y + stub_len)
            tgt_stub = (tgt_x, tgt_y - stub_len) if tgt_side == "top" else (tgt_x, tgt_y + stub_len)
            paths[idx] = [(src_x, src_y), src_stub, tgt_stub, (tgt_x, tgt_y)]
        return paths

    def _node_font(self) -> QFont:
        font = QFont()
        base_size = font.pointSizeF() if font.pointSizeF() > 0 else float(font.pointSize())
        if base_size <= 0:
            base_size = 10.0
        font.setPointSizeF(max(6.0, base_size * self.NODE_TEXT_SCALE))
        return font

    def _compute_node_sizes(self, nodes: List[Dict[str, Any]]) -> Dict[str, float]:
        font = self._node_font()
        sizes = {}
        max_width = self.NODE_WIDTH * 3
        padding = 20.0
        for node in nodes:
            label = node.get("label", "")
            address = node.get("address", 0)
            text_item = QGraphicsTextItem(f"{label}\n0x{address:x}")
            text_item.setFont(font)
            width = text_item.boundingRect().width() + padding
            width = max(self.NODE_WIDTH, min(max_width, width))
            sizes[node["id"]] = width
        return sizes

    def _layout_nodes(
        self,
        center_node: Dict[str, Any],
        nodes: List[Dict[str, Any]],
        edges: List[Dict[str, Any]],
        node_sizes: Dict[str, float],
    ):
        graphviz_positions = self._layout_nodes_graphviz(nodes, edges, node_sizes)
        if graphviz_positions:
            return graphviz_positions

        node_ids = {n["id"] for n in nodes}
        outgoing = {}
        incoming = {}
        for edge in edges:
            src = edge.get("source_id")
            tgt = edge.get("target_id")
            if src in node_ids and tgt in node_ids:
                outgoing.setdefault(src, set()).add(tgt)
                incoming.setdefault(tgt, set()).add(src)

        levels = {center_node["id"]: 0}
        max_hops = max(1, int(self.n_hops.value()))

        # BFS to the next row (callees/outgoing)
        frontier = {center_node["id"]}
        for depth in range(1, max_hops + 1):
            next_frontier = set()
            for nid in frontier:
                for neighbor in outgoing.get(nid, set()):
                    if neighbor not in levels:
                        levels[neighbor] = depth
                        next_frontier.add(neighbor)
            frontier = next_frontier

        # BFS to the previous row (callers/incoming)
        frontier = {center_node["id"]}
        for depth in range(1, max_hops + 1):
            next_frontier = set()
            for nid in frontier:
                for neighbor in incoming.get(nid, set()):
                    if neighbor not in levels:
                        levels[neighbor] = -depth
                        next_frontier.add(neighbor)
            frontier = next_frontier

        # Any remaining nodes (not reached) stay near center column
        for node in nodes:
            levels.setdefault(node["id"], 0)

        level_map = {}
        for node in nodes:
            level_map.setdefault(levels[node["id"]], []).append(node)

        max_width = max(node_sizes.values()) if node_sizes else self.NODE_WIDTH
        x_spacing = max(self.NODE_WIDTH, max_width) + 60.0
        y_spacing = 180
        positions = {}
        for level, level_nodes in level_map.items():
            level_nodes.sort(key=lambda n: n.get("label", ""))
            count = len(level_nodes)
            start_x = -((count - 1) * x_spacing) / 2.0
            for idx, node in enumerate(level_nodes):
                x = start_x + idx * x_spacing
                y = level * y_spacing
                positions[node["id"]] = (x, y)

        return positions, None

    def _layout_nodes_graphviz(
        self,
        nodes: List[Dict[str, Any]],
        edges: List[Dict[str, Any]],
        node_sizes: Dict[str, float],
    ):
        if shutil.which("dot") is None:
            return None

        node_height = self.NODE_HEIGHT / 72.0
        node_map = {node["id"]: f"n{idx}" for idx, node in enumerate(nodes)}
        edge_queue: Dict[tuple, List[int]] = {}
        for idx, edge in enumerate(edges):
            src = node_map.get(edge.get("source_id"))
            tgt = node_map.get(edge.get("target_id"))
            if src and tgt:
                edge_queue.setdefault((src, tgt), []).append(idx)

        lines = [
            "digraph G {",
            "  graph [rankdir=TB, splines=polyline, nodesep=0.35, ranksep=0.9, pad=0.2];",
            f"  node [shape=box, height={node_height:.2f}, fixedsize=true];",
        ]
        for node in nodes:
            name = node_map[node["id"]]
            label = node.get("label", name).replace("\"", "'")
            width = node_sizes.get(node["id"], self.NODE_WIDTH)
            width_in = width / 72.0
            lines.append(f"  {name} [label=\"{label}\", width={width_in:.2f}];")
        for edge in edges:
            src = node_map.get(edge.get("source_id"))
            tgt = node_map.get(edge.get("target_id"))
            if src and tgt:
                lines.append(f"  {src} -> {tgt};")
        lines.append("}")

        dot_input = "\n".join(lines).encode()
        try:
            result = subprocess.run(
                ["dot", "-Tplain"],
                input=dot_input,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            )
        except Exception:
            return None

        positions = {}
        edge_paths: Dict[int, List[tuple]] = {}
        all_points = []
        lines = result.stdout.decode(errors="ignore").splitlines()
        for line in lines:
            if not line.startswith("node "):
                if not line.startswith("edge "):
                    continue
                parts = line.split()
                if len(parts) < 4:
                    continue
                tail = parts[1]
                head = parts[2]
                try:
                    count = int(parts[3])
                except ValueError:
                    continue
                expected = 4 + (count * 2)
                if len(parts) < expected:
                    continue
                points = []
                for idx in range(count):
                    try:
                        x = float(parts[4 + idx * 2]) * 72.0
                        y = float(parts[4 + idx * 2 + 1]) * 72.0
                    except ValueError:
                        points = []
                        break
                    points.append((x, y))
                    all_points.append((x, y))
                if not points:
                    continue
                queue = edge_queue.get((tail, head))
                if queue:
                    edge_idx = queue.pop(0)
                    edge_paths[edge_idx] = points
                continue
            parts = line.split()
            if len(parts) < 6:
                continue
            name = parts[1]
            try:
                x = float(parts[2]) * 72.0
                y = float(parts[3]) * 72.0
            except ValueError:
                continue
            positions[name] = (x, y)
            all_points.append((x, y))

        if not positions or not all_points:
            return None

        max_y = max(pos[1] for pos in all_points)
        converted = [(pos[0], max_y - pos[1]) for pos in all_points]
        min_x = min(pos[0] for pos in converted)
        min_y = min(pos[1] for pos in converted)
        mapped = {}
        for node_id, name in node_map.items():
            if name not in positions:
                continue
            x, y = positions[name]
            node_width = node_sizes.get(node_id, self.NODE_WIDTH)
            mapped[node_id] = (
                x - min_x - (node_width / 2.0),
                (max_y - y) - min_y - (self.NODE_HEIGHT / 2.0),
            )

        mapped_edges = {}
        for edge_idx, points in edge_paths.items():
            mapped_edges[edge_idx] = [(x - min_x, (max_y - y) - min_y) for x, y in points]
        return mapped, mapped_edges

    def _add_edge_label(self, points: List[tuple], label: str, color: QColor) -> None:
        if not points or len(points) < 2:
            return
        mid_x, mid_y = self._midpoint(points)
        text_item = QGraphicsTextItem(label)
        font = text_item.font()
        base_size = font.pointSizeF() if font.pointSizeF() > 0 else float(font.pointSize())
        font.setPointSizeF(max(6.0, base_size * self.EDGE_LABEL_SCALE))
        text_item.setFont(font)
        text_item.setDefaultTextColor(color)
        text_item.setPos(mid_x + 4, mid_y + 2)
        text_item.setZValue(-1)
        self.scene.addItem(text_item)

    def _add_arrowhead(self, start: tuple, end: tuple, color: QColor) -> None:
        sx, sy = start
        ex, ey = end
        dx = ex - sx
        dy = ey - sy
        length = math.hypot(dx, dy)
        if length == 0:
            return
        ux = dx / length
        uy = dy / length
        left_x = ex - self.ARROW_SIZE * ux + (self.ARROW_SIZE / 2.0) * uy
        left_y = ey - self.ARROW_SIZE * uy - (self.ARROW_SIZE / 2.0) * ux
        right_x = ex - self.ARROW_SIZE * ux - (self.ARROW_SIZE / 2.0) * uy
        right_y = ey - self.ARROW_SIZE * uy + (self.ARROW_SIZE / 2.0) * ux
        polygon = QPolygonF()
        polygon.append(QPointF(ex, ey))
        polygon.append(QPointF(left_x, left_y))
        polygon.append(QPointF(right_x, right_y))
        arrow = QGraphicsPolygonItem(polygon)
        arrow.setBrush(QBrush(color))
        arrow.setPen(QPen(color))
        arrow.setZValue(-1)
        self.scene.addItem(arrow)

    @staticmethod
    def _midpoint(points: List[tuple]) -> tuple:
        total = 0.0
        segments = []
        for idx in range(len(points) - 1):
            x1, y1 = points[idx]
            x2, y2 = points[idx + 1]
            length = math.hypot(x2 - x1, y2 - y1)
            segments.append((length, x1, y1, x2, y2))
            total += length
        if total == 0:
            x1, y1 = points[0]
            return x1, y1
        half = total / 2.0
        for length, x1, y1, x2, y2 in segments:
            if half <= length:
                ratio = half / length if length else 0
                return (x1 + (x2 - x1) * ratio, y1 + (y2 - y1) * ratio)
            half -= length
        return points[-1]

    def _on_refresh(self):
        edge_types = []
        if self.calls_cb.isChecked():
            edge_types.append("calls")
        if self.vuln_cb.isChecked():
            edge_types.append("calls_vulnerable")
        if self.network_cb.isChecked():
            edge_types.append("network_send")
            edge_types.append("network_recv")
        self.refresh_requested.emit(int(self.n_hops.value()), edge_types)

    def _go_to_selected(self):
        if self._selected_node:
            self.navigate_requested.emit(self._selected_node["address"])

    def _on_node_double_clicked(self, node_data):
        """Handle double-click on a node to navigate to its address."""
        if node_data and "address" in node_data:
            self.navigate_requested.emit(node_data["address"])

    def _on_selection_changed(self):
        items = self.scene.selectedItems()
        if not items:
            self._selected_node = None
            self.summary_text.clear()
            return
        node = items[0].data(0)
        if not node:
            return
        self._selected_node = node
        self._set_summary_content(node)

    def _set_summary_content(self, node: Dict[str, Any]):
        label = node.get("label", "Unknown")
        address = node.get("address", 0)
        summary = node.get("summary", "")

        md_content = f"**{label}** (0x{address:x})"
        if summary:
            md_content += f"\n\n{summary}"

        self.summary_text.setMarkdown(md_content)

    def _node_style(self, node: Dict[str, Any], is_center: bool):
        if is_center:
            return self._colors["center"], self._colors["center_text"]
        if node.get("has_vuln"):
            return self._colors["vuln"], self._colors["vuln_text"]
        return self._colors["node"], self._colors["node_text"]

    def _edge_style(self, edge_type: str):
        if edge_type == "calls":
            return self._colors["edge_calls"], 2, False
        if edge_type == "references":
            return self._colors["edge_refs"], 1, True
        if edge_type == "calls_vulnerable":
            return self._colors["edge_vuln"], 2, False
        if edge_type in ("network_send", "network_recv"):
            return self._colors["edge_network"], 2, False
        return self._colors["edge_calls"], 1, False

    def _zoom_in(self):
        self.view.scale(1.2, 1.2)
        self._update_zoom_label()

    def _zoom_out(self):
        self.view.scale(1 / 1.2, 1 / 1.2)
        self._update_zoom_label()

    def _zoom_fit(self):
        self.view.fitInView(self.scene.itemsBoundingRect(), Qt.KeepAspectRatio)
        self._update_zoom_label()

    def _zoom_reset(self, center_item: Optional[QGraphicsItem] = None):
        self.view.resetTransform()
        if center_item:
            self.view.centerOn(center_item.sceneBoundingRect().center())
        else:
            self.view.centerOn(self.scene.itemsBoundingRect().center())
        self._update_zoom_label()

    def _update_zoom_label(self):
        transform = self.view.transform()
        percent = int(transform.m11() * 100)
        self.zoom_label.setText(f"{percent}%")


class SemanticGraphSearchView(QWidget):
    query_requested = Signal(str, dict)
    navigate_requested = Signal(int)

    QUERY_TYPES = [
        ("Semantic Search", "ga_search_semantic"),
        ("Get Analysis", "ga_get_semantic_analysis"),
        ("Similar Functions", "ga_get_similar_functions"),
        ("Call Context", "ga_get_call_context"),
        ("Security Analysis", "ga_get_security_analysis"),
        ("Module Summary", "ga_get_module_summary"),
        ("Activity Analysis", "ga_get_activity_analysis"),
    ]

    def __init__(self):
        super().__init__()
        self._last_results = []
        self._selected_address = None
        self._current_address = None
        self._current_query_type = "ga_search_semantic"
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout()

        types_group = QGroupBox("Query Type")
        types_layout = QGridLayout()
        self.type_group = QButtonGroup()
        for idx, (label, value) in enumerate(self.QUERY_TYPES):
            radio = QRadioButton(label)
            radio.setProperty("query_value", value)
            if idx == 0:
                radio.setChecked(True)
            self.type_group.addButton(radio)
            types_layout.addWidget(radio, idx // 4, idx % 4)
        types_group.setLayout(types_layout)
        layout.addWidget(types_group)

        params_group = QGroupBox("Parameters")
        params_layout = QGridLayout()
        self.query_field = QLineEdit()
        self.address_field = QLineEdit()
        self.limit_spin = QSpinBox()
        self.limit_spin.setRange(1, 100)
        self.limit_spin.setValue(20)
        self.depth_spin = QSpinBox()
        self.depth_spin.setRange(1, 5)
        self.depth_spin.setValue(1)
        self.direction_combo = QComboBox()
        self.direction_combo.addItems(["both", "callers", "callees"])
        self.scope_combo = QComboBox()
        self.scope_combo.addItems(["function", "binary"])
        params_layout.addWidget(QLabel("Query:"), 0, 0)
        params_layout.addWidget(self.query_field, 0, 1)
        params_layout.addWidget(QLabel("Address:"), 0, 2)
        params_layout.addWidget(self.address_field, 0, 3)
        params_layout.addWidget(QLabel("Limit:"), 1, 0)
        params_layout.addWidget(self.limit_spin, 1, 1)
        params_layout.addWidget(QLabel("Depth:"), 1, 2)
        params_layout.addWidget(self.depth_spin, 1, 3)
        params_layout.addWidget(QLabel("Direction:"), 2, 0)
        params_layout.addWidget(self.direction_combo, 2, 1)
        params_layout.addWidget(QLabel("Scope:"), 2, 2)
        params_layout.addWidget(self.scope_combo, 2, 3)
        params_layout.setColumnStretch(1, 1)
        params_layout.setColumnStretch(3, 1)
        params_group.setLayout(params_layout)
        layout.addWidget(params_group)

        controls = QHBoxLayout()
        self.use_current = QCheckBox("Use Current Address")
        self.use_current.stateChanged.connect(self._apply_current_address)
        self.execute_button = QPushButton("Execute Query")
        self.execute_button.clicked.connect(self._execute_query)
        controls.addWidget(self.use_current)
        controls.addStretch()
        controls.addWidget(self.execute_button)
        layout.addLayout(controls)

        self.results_table = QTableWidget(0, 5)
        self.results_table.setHorizontalHeaderLabels(["#", "Function", "Address", "Score", "Summary"])
        self.results_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.results_table.itemSelectionChanged.connect(self._on_result_selected)
        layout.addWidget(self.results_table)

        self.details = QTextEdit()
        self.details.setReadOnly(True)
        layout.addWidget(self.details)

        details_controls = QHBoxLayout()
        self.go_to_button = QPushButton("Go To")
        self.go_to_button.setEnabled(False)
        self.go_to_button.clicked.connect(self._go_to_selected)
        details_controls.addWidget(self.go_to_button)
        details_controls.addStretch()
        layout.addLayout(details_controls)

        self.setLayout(layout)

    def _execute_query(self):
        query_type = self._get_selected_query_type()
        args = self._build_args(query_type)
        if args is None:
            return
        self._current_query_type = query_type
        self.execute_button.setEnabled(False)
        self.execute_button.setText("Executing...")
        self.query_requested.emit(query_type, args)

    def handle_query_result(self, json_result: str):
        self.execute_button.setEnabled(True)
        self.execute_button.setText("Execute Query")
        self._populate_results(json_result, self._current_query_type)

    def update_current_address(self, address: int):
        self._current_address = address
        if self.use_current.isChecked():
            self.address_field.setText(f"0x{address:x}")

    def _populate_results(self, json_result: str, query_type: str):
        self.results_table.setRowCount(0)
        self._last_results = []
        if not json_result:
            return
        try:
            parsed = json.loads(json_result)
        except Exception:
            self.details.setPlainText("Failed to parse results.")
            return

        results = self._normalize_results(parsed, query_type)
        if not results:
            return
        self._last_results = results
        for idx, entry in enumerate(results, 1):
            row = self.results_table.rowCount()
            self.results_table.insertRow(row)
            name = entry.get("function_name") or entry.get("name") or "Unknown"
            address = entry.get("address", "-")
            score = entry.get("score", "-")
            summary = entry.get("summary") or entry.get("description") or ""
            if len(summary) > 80:
                summary = summary[:77] + "..."
            self.results_table.setItem(row, 0, QTableWidgetItem(str(idx)))
            self.results_table.setItem(row, 1, QTableWidgetItem(name))
            self.results_table.setItem(row, 2, QTableWidgetItem(str(address)))
            self.results_table.setItem(row, 3, QTableWidgetItem(str(score)))
            self.results_table.setItem(row, 4, QTableWidgetItem(summary))

    def _normalize_results(self, parsed: object, query_type: str) -> List[Dict[str, Any]]:
        if isinstance(parsed, dict) and parsed.get("error"):
            self.details.setPlainText(parsed.get("error"))
            return []
        if query_type in ("ga_search_semantic", "ga_get_similar_functions"):
            results = parsed.get("results") if isinstance(parsed, dict) else parsed
            if isinstance(results, dict):
                results = [results]
            return results or []
        if query_type == "ga_get_semantic_analysis":
            if isinstance(parsed, dict):
                return [parsed]
            return []
        if query_type == "ga_get_call_context":
            return self._flatten_call_context(parsed if isinstance(parsed, dict) else {})
        if query_type == "ga_get_security_analysis":
            return [self._flatten_security_analysis(parsed if isinstance(parsed, dict) else {})]
        if query_type == "ga_get_module_summary":
            if isinstance(parsed, dict):
                return [{
                    "name": "Module Summary",
                    "address": parsed.get("address", "-"),
                    "summary": parsed.get("module_summary", ""),
                }]
            return []
        if query_type == "ga_get_activity_analysis":
            if isinstance(parsed, dict):
                summary = f"Activity: {parsed.get('activity_profile', 'NONE')} | Risk: {parsed.get('risk_level', 'LOW')}"
                return [{
                    "function_name": parsed.get("function_name", "Unknown"),
                    "address": parsed.get("address", "-"),
                    "summary": summary,
                    "score": "-",
                }]
            return []
        return []

    def _flatten_call_context(self, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        results = []
        center = payload.get("function") or {}
        if center:
            results.append({
                "function_name": f"Center: {center.get('function_name', 'Unknown')}",
                "address": center.get("address", "-"),
                "summary": center.get("summary", ""),
                "score": "-",
                "security_flags": center.get("security_flags", []),
            })
        for caller in payload.get("callers", []) or []:
            label = f"Caller[d{caller.get('depth', 1)}]: {caller.get('function_name', 'Unknown')}"
            results.append({
                "function_name": label,
                "address": caller.get("address", "-"),
                "summary": caller.get("summary", ""),
                "score": "-",
                "security_flags": caller.get("security_flags", []),
            })
        for callee in payload.get("callees", []) or []:
            label = f"Callee[d{callee.get('depth', 1)}]: {callee.get('function_name', 'Unknown')}"
            results.append({
                "function_name": label,
                "address": callee.get("address", "-"),
                "summary": callee.get("summary", ""),
                "score": "-",
                "security_flags": callee.get("security_flags", []),
            })
        return results

    def _flatten_security_analysis(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        name = payload.get("name", "Unknown")
        flags = payload.get("security_flags", [])
        summary = "Flags: " + (", ".join(flags) if flags else "None")
        return {
            "name": name,
            "summary": summary,
            "score": "-",
            "address": payload.get("address", "-"),
        }

    def _on_result_selected(self):
        items = self.results_table.selectedItems()
        if not items:
            return
        row = items[0].row()
        if row >= len(self._last_results):
            return
        result = self._last_results[row]
        address = result.get("address")
        self._selected_address = address
        details = json.dumps(result, indent=2)
        self.details.setPlainText(details)
        self.go_to_button.setEnabled(self._is_valid_address(address))

    def _is_valid_address(self, address: object) -> bool:
        if address is None:
            return False
        if isinstance(address, int):
            return True
        if isinstance(address, str):
            addr = address.strip().lower()
            if addr.startswith("0x") and len(addr) > 2:
                try:
                    int(addr, 16)
                    return True
                except ValueError:
                    return False
        return False

    def _go_to_selected(self):
        if not self._selected_address:
            return
        addr = str(self._selected_address)
        if addr.startswith("0x"):
            value = int(addr, 16)
        else:
            value = int(addr, 16)
        self.navigate_requested.emit(value)

    def _get_selected_query_type(self) -> str:
        for button in self.type_group.buttons():
            if button.isChecked():
                return button.property("query_value")
        return "ga_search_semantic"

    def _build_args(self, query_type: str) -> Optional[Dict[str, Any]]:
        args: Dict[str, Any] = {}
        if query_type == "ga_search_semantic":
            query = self.query_field.text().strip()
            if not query:
                return None
            args["query"] = query
            args["limit"] = int(self.limit_spin.value())
        elif query_type in ("ga_get_semantic_analysis", "ga_get_module_summary", "ga_get_activity_analysis"):
            addr = self.address_field.text().strip()
            if addr:
                args["address"] = addr
        elif query_type == "ga_get_similar_functions":
            addr = self.address_field.text().strip()
            if addr:
                args["address"] = addr
            args["limit"] = int(self.limit_spin.value())
        elif query_type == "ga_get_call_context":
            addr = self.address_field.text().strip()
            if addr:
                args["address"] = addr
            args["depth"] = int(self.depth_spin.value())
            args["direction"] = self.direction_combo.currentText()
        elif query_type == "ga_get_security_analysis":
            addr = self.address_field.text().strip()
            if addr:
                args["address"] = addr
            args["scope"] = self.scope_combo.currentText()
        return args

    def _apply_current_address(self):
        if self.use_current.isChecked() and self._current_address is not None:
            self.address_field.setText(f"0x{self._current_address:x}")


class QStackedFrame(QFrame):
    def __init__(self):
        super().__init__()
        self._stack = QVBoxLayout()
        self._widgets = []
        self.setLayout(self._stack)

    def addWidget(self, widget: QWidget):
        widget.setVisible(False)
        self._widgets.append(widget)
        self._stack.addWidget(widget)

    def setCurrentWidget(self, widget: QWidget):
        for w in self._widgets:
            w.setVisible(w is widget)
