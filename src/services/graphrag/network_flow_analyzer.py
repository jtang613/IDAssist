#!/usr/bin/env python3

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set

from .graph_store import GraphStore
from .models import GraphEdge, GraphNode, EdgeType

from src.ida_compat import log


@dataclass
class NetworkFlowResult:
    """Result of network flow analysis."""
    send_edges_created: int = 0
    recv_edges_created: int = 0
    send_edges_existing: int = 0
    recv_edges_existing: int = 0
    send_functions: List[str] = field(default_factory=list)
    recv_functions: List[str] = field(default_factory=list)

    @property
    def total_send_edges(self) -> int:
        return self.send_edges_created + self.send_edges_existing

    @property
    def total_recv_edges(self) -> int:
        return self.recv_edges_created + self.recv_edges_existing

    def to_summary(self) -> str:
        return (
            f"Network Flow Analysis Complete:\n"
            f"- Found {len(self.send_functions)} functions calling send APIs\n"
            f"- NETWORK_SEND edges: {self.total_send_edges} total ({self.send_edges_created} new, {self.send_edges_existing} existing)\n"
            f"- Found {len(self.recv_functions)} functions calling recv APIs\n"
            f"- NETWORK_RECV edges: {self.total_recv_edges} total ({self.recv_edges_created} new, {self.recv_edges_existing} existing)"
        )


class NetworkFlowAnalyzer:
    """
    Analyzes network data flow and creates NETWORK_SEND and NETWORK_RECV edges.

    Network send APIs are functions that send data over the network.
    Network recv APIs are functions that receive data from the network.

    Edges are created from entry points to send functions (NETWORK_SEND)
    and from recv functions to their callers (NETWORK_RECV).
    """

    MAX_PATH_LENGTH = 10

    # Network send APIs - functions that send data over the network
    NETWORK_SEND_APIS = {
        # POSIX
        "send", "sendto", "sendmsg", "write",
        # WinSock
        "WSASend", "WSASendTo", "WSASendMsg", "WSASendDisconnect",
        # SSL/TLS
        "SSL_write",
        # WinHTTP
        "WinHttpWriteData", "WinHttpSendRequest",
        # WinINet
        "InternetWriteFile", "HttpSendRequest", "HttpSendRequestA", "HttpSendRequestW",
        "HttpSendRequestEx", "HttpSendRequestExA", "HttpSendRequestExW",
        # libcurl
        "curl_easy_send",
    }

    # Network recv APIs - functions that receive data from the network
    NETWORK_RECV_APIS = {
        # POSIX
        "recv", "recvfrom", "recvmsg", "read",
        # WinSock
        "WSARecv", "WSARecvFrom", "WSARecvMsg", "WSARecvDisconnect",
        # SSL/TLS
        "SSL_read",
        # WinHTTP
        "WinHttpReadData", "WinHttpReceiveResponse",
        # WinINet
        "InternetReadFile", "InternetReadFileEx", "HttpQueryInfo", "HttpQueryInfoA", "HttpQueryInfoW",
        # libcurl
        "curl_easy_recv",
    }

    # Common entry point function names
    ENTRY_POINT_NAMES = {
        "main", "_main", "wmain", "_wmain",
        "WinMain", "wWinMain", "_WinMain@16", "_wWinMain@16",
        "DllMain", "_DllMain@12", "DllEntryPoint",
        "start", "_start", "entry", "_entry",
        "mainCRTStartup", "wmainCRTStartup",
        "WinMainCRTStartup", "wWinMainCRTStartup",
    }

    def __init__(self, graph_store: GraphStore, binary_hash: str):
        self.graph_store = graph_store
        self.binary_hash = binary_hash
        self.cancelled = False
        self._adjacency_cache: Optional[Dict[str, List[str]]] = None

    def cancel(self) -> None:
        """Request cancellation of ongoing analysis."""
        self.cancelled = True

    def reset_cancel(self) -> None:
        """Reset cancellation flag (call before starting new analysis)."""
        self.cancelled = False

    def analyze(
        self,
        progress_callback: Optional[Callable[[int, int, str], None]] = None
    ) -> NetworkFlowResult:
        """
        Analyze network data flow and create NETWORK_SEND and NETWORK_RECV edges.

        Args:
            progress_callback: Optional callback(current, total, message) for progress updates

        Returns:
            NetworkFlowResult with statistics about edges created
        """
        log.log_info("Starting network flow analysis...")
        self.reset_cancel()
        self._build_adjacency_cache()

        result = NetworkFlowResult()

        if progress_callback:
            progress_callback(0, 100, "Finding network send functions...")

        # Find network send/recv nodes
        send_nodes = self._find_network_send_nodes()
        if self.cancelled:
            log.log_info("Network flow analysis cancelled during send node discovery")
            return result

        if progress_callback:
            progress_callback(2, 100, "Finding network recv functions...")

        recv_nodes = self._find_network_recv_nodes()
        if self.cancelled:
            log.log_info("Network flow analysis cancelled during recv node discovery")
            return result

        result.send_functions = [self._get_node_name(n) for n in send_nodes]
        result.recv_functions = [self._get_node_name(n) for n in recv_nodes]

        log.log_info(f"Found {len(send_nodes)} functions that send network data")
        log.log_info(f"Found {len(recv_nodes)} functions that receive network data")

        if progress_callback:
            progress_callback(5, 100, f"Found {len(send_nodes)} send, {len(recv_nodes)} recv functions. Creating send edges...")

        # Create NETWORK_SEND edges
        send_created, send_existing = self._create_network_send_edges(send_nodes, progress_callback)
        result.send_edges_created = send_created
        result.send_edges_existing = send_existing

        if self.cancelled:
            log.log_info("Network flow analysis cancelled during send edge creation")
            return result

        # Create NETWORK_RECV edges
        recv_created, recv_existing = self._create_network_recv_edges(recv_nodes, progress_callback)
        result.recv_edges_created = recv_created
        result.recv_edges_existing = recv_existing

        if progress_callback:
            progress_callback(100, 100, f"Complete: {result.total_send_edges} send edges ({send_created} new), {result.total_recv_edges} recv edges ({recv_created} new)")

        log.log_info(f"Network flow analysis complete: {result.total_send_edges} send edges ({send_created} new, {send_existing} existing), {result.total_recv_edges} recv edges ({recv_created} new, {recv_existing} existing)")

        return result

    def _build_adjacency_cache(self) -> None:
        """Build adjacency list cache for faster path finding."""
        self._adjacency_cache = {}
        edges = self.graph_store.get_edges_by_types(self.binary_hash, [EdgeType.CALLS.value])
        for edge in edges:
            if edge.source_id not in self._adjacency_cache:
                self._adjacency_cache[edge.source_id] = []
            self._adjacency_cache[edge.source_id].append(edge.target_id)

    def _get_callees(self, node_id: str) -> List[str]:
        """Get callees for a node using cached adjacency list."""
        if self._adjacency_cache is None:
            self._build_adjacency_cache()
        return self._adjacency_cache.get(node_id, [])

    def _get_callers(self, node_id: str) -> List[str]:
        """Get callers for a node."""
        edges = self.graph_store.get_edges_for_node(self.binary_hash, node_id)
        return [edge.source_id for edge in edges if edge.target_id == node_id and edge.edge_type == EdgeType.CALLS.value]

    def _find_network_send_nodes(self) -> List[GraphNode]:
        """Find functions that call network send APIs."""
        seen_ids: Set[str] = set()
        send_nodes: List[GraphNode] = []

        nodes = self.graph_store.get_nodes_by_type(self.binary_hash, "FUNCTION")
        for node in nodes:
            if self.cancelled:
                break

            # Check if function name is a known send API
            name = node.name
            if name and self._is_network_send_api(name):
                if node.id not in seen_ids:
                    seen_ids.add(node.id)
                    send_nodes.append(node)
                continue

            # Check callees for network send functions
            for callee_id in self._get_callees(node.id):
                callee = self.graph_store.get_node_by_id(callee_id)
                if callee and callee.name and self._is_network_send_api(callee.name):
                    if node.id not in seen_ids:
                        seen_ids.add(node.id)
                        send_nodes.append(node)
                    break

        return send_nodes

    def _find_network_recv_nodes(self) -> List[GraphNode]:
        """Find functions that call network recv APIs."""
        seen_ids: Set[str] = set()
        recv_nodes: List[GraphNode] = []

        nodes = self.graph_store.get_nodes_by_type(self.binary_hash, "FUNCTION")
        for node in nodes:
            if self.cancelled:
                break

            # Check if function name is a known recv API
            name = node.name
            if name and self._is_network_recv_api(name):
                if node.id not in seen_ids:
                    seen_ids.add(node.id)
                    recv_nodes.append(node)
                continue

            # Check callees for network recv functions
            for callee_id in self._get_callees(node.id):
                callee = self.graph_store.get_node_by_id(callee_id)
                if callee and callee.name and self._is_network_recv_api(callee.name):
                    if node.id not in seen_ids:
                        seen_ids.add(node.id)
                        recv_nodes.append(node)
                    break

        return recv_nodes

    def _is_network_send_api(self, name: str) -> bool:
        """Check if a function name is a network send API."""
        if not name:
            return False
        normalized = self._normalize_function_name(name)
        return name in self.NETWORK_SEND_APIS or normalized in self.NETWORK_SEND_APIS

    def _is_network_recv_api(self, name: str) -> bool:
        """Check if a function name is a network recv API."""
        if not name:
            return False
        normalized = self._normalize_function_name(name)
        return name in self.NETWORK_RECV_APIS or normalized in self.NETWORK_RECV_APIS

    def _normalize_function_name(self, name: str) -> str:
        """Normalize a function name by removing common decorations."""
        if not name:
            return name

        normalized = name

        # Remove library prefix (e.g., "WS2_32.dll::" or "KERNEL32.DLL_")
        if "::" in normalized:
            normalized = normalized.split("::")[-1]

        # Handle underscore-separated library prefix
        if ".DLL_" in normalized.upper():
            idx = normalized.upper().find(".DLL_")
            if idx > 0:
                normalized = normalized[idx + 5:]

        # Remove <EXTERNAL>:: prefix
        if normalized.startswith("<EXTERNAL>::"):
            normalized = normalized[12:]

        # Remove __imp_ prefix (import thunk)
        if normalized.startswith("__imp_"):
            normalized = normalized[6:]

        # Remove leading underscores
        while normalized.startswith("_") and len(normalized) > 1:
            normalized = normalized[1:]

        # Remove trailing @N (stdcall decoration)
        at_idx = normalized.rfind("@")
        if at_idx > 0:
            suffix = normalized[at_idx + 1:]
            if suffix.isdigit():
                normalized = normalized[:at_idx]

        return normalized

    def _find_entry_points(self) -> List[GraphNode]:
        """Find entry point nodes (exported functions, main, etc.)."""
        entry_points: List[GraphNode] = []
        seen_ids: Set[str] = set()

        nodes = self.graph_store.get_nodes_by_type(self.binary_hash, "FUNCTION")
        for node in nodes:
            is_entry = False

            # Check security flags for ENTRY_POINT or EXPORTED
            flags = node.security_flags or []
            if "ENTRY_POINT" in flags or "EXPORTED" in flags:
                is_entry = True

            # Check for known entry point names
            name = node.name
            if name and name in self.ENTRY_POINT_NAMES:
                is_entry = True

            if is_entry and node.id not in seen_ids:
                seen_ids.add(node.id)
                entry_points.append(node)

        return entry_points

    def _bfs_path_exists(self, source_id: str, target_id: str, max_depth: int = None) -> Optional[int]:
        """
        Check if a path exists from source to target using BFS.
        Returns path length if found, None if not found.
        """
        if max_depth is None:
            max_depth = self.MAX_PATH_LENGTH

        if source_id == target_id:
            return 0

        visited: Set[str] = {source_id}
        queue = [(source_id, 0)]

        while queue:
            current_id, depth = queue.pop(0)

            if depth >= max_depth:
                continue

            for neighbor_id in self._get_callees(current_id):
                if neighbor_id == target_id:
                    return depth + 1

                if neighbor_id not in visited:
                    visited.add(neighbor_id)
                    queue.append((neighbor_id, depth + 1))

        return None

    def _create_network_send_edges(
        self,
        send_nodes: List[GraphNode],
        progress_callback: Optional[Callable[[int, int, str], None]] = None
    ) -> tuple:
        """
        Create NETWORK_SEND edges from entry points to send functions.
        Returns tuple of (edges_created, edges_existing).
        """
        if not send_nodes:
            return (0, 0)

        entry_points = self._find_entry_points()
        log.log_info(f"Processing {len(entry_points)} entry points x {len(send_nodes)} send nodes...")

        edges_created = 0
        edges_existing = 0
        total = len(entry_points)

        for idx, entry in enumerate(entry_points):
            if self.cancelled:
                break

            for send_node in send_nodes:
                if self.cancelled:
                    break

                if entry.id == send_node.id:
                    continue

                # Skip if edge already exists
                if self.graph_store.has_edge(entry.id, send_node.id, EdgeType.NETWORK_SEND.value):
                    edges_existing += 1
                    continue

                # Check if path exists
                path_length = self._bfs_path_exists(entry.id, send_node.id)
                if path_length is not None:
                    send_api = self._get_send_api_name(send_node)
                    metadata = f'{{"path_length":{path_length},"send_api":"{send_api}","entry_point":"{entry.name}"}}'

                    self.graph_store.add_edge(GraphEdge(
                        binary_hash=self.binary_hash,
                        source_id=entry.id,
                        target_id=send_node.id,
                        edge_type=EdgeType.NETWORK_SEND,
                        weight=1.0,
                        metadata=metadata,
                    ))
                    edges_created += 1

            if progress_callback and total > 0:
                pct = 5 + int((idx + 1) / total * 75)
                progress_callback(pct, 100, f"Send paths: {idx + 1}/{total} entry points, {edges_created} edges")

        # Also add direct caller edges
        for send_node in send_nodes:
            if self.cancelled:
                break

            for caller_id in self._get_callers(send_node.id):
                if not self.graph_store.has_edge(caller_id, send_node.id, EdgeType.NETWORK_SEND.value):
                    send_api = self._get_send_api_name(send_node)
                    metadata = f'{{"direct_caller":true,"send_api":"{send_api}"}}'

                    self.graph_store.add_edge(GraphEdge(
                        binary_hash=self.binary_hash,
                        source_id=caller_id,
                        target_id=send_node.id,
                        edge_type=EdgeType.NETWORK_SEND,
                        weight=0.5,
                        metadata=metadata,
                    ))
                    edges_created += 1
                else:
                    edges_existing += 1

        return (edges_created, edges_existing)

    def _create_network_recv_edges(
        self,
        recv_nodes: List[GraphNode],
        progress_callback: Optional[Callable[[int, int, str], None]] = None
    ) -> tuple:
        """
        Create NETWORK_RECV edges from recv functions to their callers.
        Returns tuple of (edges_created, edges_existing).
        """
        if not recv_nodes:
            return (0, 0)

        log.log_info(f"Processing {len(recv_nodes)} recv nodes for caller tracing...")

        edges_created = 0
        edges_existing = 0
        total = len(recv_nodes)

        for idx, recv_node in enumerate(recv_nodes):
            if self.cancelled:
                break

            recv_api = self._get_recv_api_name(recv_node)

            # Get direct callers (1-hop)
            callers = self._get_callers(recv_node.id)

            for caller_id in callers:
                if self.cancelled:
                    break

                # Edge: recv -> caller (showing data flow direction)
                if not self.graph_store.has_edge(recv_node.id, caller_id, EdgeType.NETWORK_RECV.value):
                    metadata = f'{{"recv_api":"{recv_api}","hop":1}}'

                    self.graph_store.add_edge(GraphEdge(
                        binary_hash=self.binary_hash,
                        source_id=recv_node.id,
                        target_id=caller_id,
                        edge_type=EdgeType.NETWORK_RECV,
                        weight=1.0,
                        metadata=metadata,
                    ))
                    edges_created += 1
                else:
                    edges_existing += 1

                # Also trace 2-hop callers
                for grand_caller_id in self._get_callers(caller_id):
                    caller_node = self.graph_store.get_node_by_id(caller_id)
                    caller_name = self._get_node_name(caller_node) if caller_node else "unknown"

                    if not self.graph_store.has_edge(recv_node.id, grand_caller_id, EdgeType.NETWORK_RECV.value):
                        metadata = f'{{"recv_api":"{recv_api}","hop":2,"via":"{caller_name}"}}'

                        self.graph_store.add_edge(GraphEdge(
                            binary_hash=self.binary_hash,
                            source_id=recv_node.id,
                            target_id=grand_caller_id,
                            edge_type=EdgeType.NETWORK_RECV,
                            weight=0.5,
                            metadata=metadata,
                        ))
                        edges_created += 1
                    else:
                        edges_existing += 1

            if progress_callback and total > 0:
                pct = 80 + int((idx + 1) / total * 18)
                progress_callback(pct, 100, f"Recv paths: {idx + 1}/{total} recv nodes, {edges_created} edges")

        return (edges_created, edges_existing)

    def _get_send_api_name(self, node: GraphNode) -> str:
        """Get the name of the send API called by a node."""
        # If the node itself is a send API
        if node.name and self._is_network_send_api(node.name):
            return self._normalize_function_name(node.name)

        # Check callees
        for callee_id in self._get_callees(node.id):
            callee = self.graph_store.get_node_by_id(callee_id)
            if callee and callee.name and self._is_network_send_api(callee.name):
                return self._normalize_function_name(callee.name)

        return "unknown"

    def _get_recv_api_name(self, node: GraphNode) -> str:
        """Get the name of the recv API called by a node."""
        # If the node itself is a recv API
        if node.name and self._is_network_recv_api(node.name):
            return self._normalize_function_name(node.name)

        # Check callees
        for callee_id in self._get_callees(node.id):
            callee = self.graph_store.get_node_by_id(callee_id)
            if callee and callee.name and self._is_network_recv_api(callee.name):
                return self._normalize_function_name(callee.name)

        return "unknown"

    def _get_node_name(self, node: GraphNode) -> str:
        """Get a display name for a node."""
        if node.name:
            return node.name
        if node.address:
            return f"sub_{node.address:x}"
        return node.id or "unknown"
