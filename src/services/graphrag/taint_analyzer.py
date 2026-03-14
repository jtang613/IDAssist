#!/usr/bin/env python3

from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Set

from .graph_store import GraphStore
from .models import GraphEdge, GraphNode, EdgeType

from src.ida_compat import log


@dataclass
class TaintPath:
    source: GraphNode
    sink: GraphNode
    path: List[int]

    def to_dict(self) -> Dict[str, object]:
        return {
            "source": self.source.name or f"sub_{self.source.address:x}",
            "sink": self.sink.name or f"sub_{self.sink.address:x}",
            "path": self.path,
        }


class TaintAnalyzer:
    MAX_PATH_LENGTH = 10

    TAINT_SOURCES = {
        "recv", "recvfrom", "recvmsg", "read", "WSARecv", "WSARecvFrom",
        "InternetReadFile", "HttpQueryInfo", "WinHttpReadData",
        "fread", "fgets", "fgetc", "getc", "ReadFile", "ReadFileEx",
        "NtReadFile", "ZwReadFile",
        "scanf", "fscanf", "sscanf", "gets", "getline", "getdelim",
        "getenv", "GetEnvironmentVariable",
        "msgrcv", "mq_receive", "ReadEventLog", "PeekNamedPipe",
        "MapViewOfFile", "mmap",
    }

    TAINT_SINKS = {
        "strcpy", "strcat", "sprintf", "vsprintf", "gets", "wcscpy", "wcscat",
        "lstrcpy", "lstrcpyA", "lstrcpyW", "lstrcat",
        "printf", "fprintf", "sprintf", "snprintf", "vprintf", "vfprintf",
        "wprintf", "fwprintf", "swprintf",
        "system", "popen", "_popen", "exec", "execl", "execle", "execlp",
        "execv", "execve", "execvp", "CreateProcess", "CreateProcessA",
        "CreateProcessW", "ShellExecute", "ShellExecuteA", "ShellExecuteW",
        "WinExec",
        "fopen", "open", "CreateFile", "CreateFileA", "CreateFileW",
        "DeleteFile", "RemoveDirectory", "MoveFile", "CopyFile",
        "mysql_query", "sqlite3_exec", "PQexec",
        "memcpy", "memmove", "memset", "RtlCopyMemory",
    }

    SOURCE_FLAGS = {
        "NETWORK_CAPABLE",
        "READS_FILES",
        "ACCEPTS_CONNECTIONS",
        "INITIATES_CONNECTIONS",
        "PERFORMS_DNS_LOOKUP",
    }

    SINK_FLAGS = {
        "BUFFER_OVERFLOW_RISK",
        "COMMAND_INJECTION_RISK",
        "FORMAT_STRING_RISK",
        "PATH_TRAVERSAL_RISK",
        "SQL_INJECTION_RISK",
        "CALLS_DANGEROUS_FUNCTIONS",
        "CALLS_VULNERABLE_FUNCTION",
    }

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

    def cancel(self) -> None:
        self.cancelled = True

    def find_taint_paths(self, max_paths: int = 100, create_edges: bool = True) -> List[TaintPath]:
        sources = self._find_source_nodes()
        sinks = {node.id: node for node in self._find_sink_nodes()}

        if not sources or not sinks:
            return []

        paths: List[TaintPath] = []
        for source in sources:
            if self.cancelled:
                break
            if len(paths) >= max_paths:
                break
            found = self._dfs_paths(source.id, sinks, max_paths - len(paths))
            for path_ids, sink_node in found:
                if self.cancelled:
                    break
                paths.append(TaintPath(source, sink_node, path_ids))
                if create_edges:
                    self._create_taint_edges(path_ids)
                    self._create_vulnerable_via_edge(source.id, sink_node.id)
                if len(paths) >= max_paths:
                    break
        return paths

    def _dfs_paths(self, source_id: int, sinks: Dict[int, GraphNode], remaining: int):
        stack = [(source_id, [source_id])]
        results = []
        while stack and remaining > 0:
            if self.cancelled:
                break
            node_id, path = stack.pop()
            if len(path) > self.MAX_PATH_LENGTH:
                continue
            if node_id in sinks and node_id != source_id:
                results.append((path, sinks[node_id]))
                remaining -= 1
                continue
            neighbors = self._get_callees(node_id)
            for neighbor in neighbors:
                if neighbor in path:
                    continue
                stack.append((neighbor, path + [neighbor]))
        return results

    def _get_callees(self, node_id: int) -> List[int]:
        edges = self.graph_store.get_edges_for_node(self.binary_hash, node_id)
        return [
            edge.target_id
            for edge in edges
            if edge.source_id == node_id and edge.edge_type == EdgeType.CALLS.value
        ]

    def _create_taint_edges(self, path: List[int]) -> None:
        for idx in range(len(path) - 1):
            if self.graph_store.has_edge(path[idx], path[idx + 1], EdgeType.TAINT_FLOWS_TO.value):
                continue
            self.graph_store.add_edge(GraphEdge(
                binary_hash=self.binary_hash,
                source_id=path[idx],
                target_id=path[idx + 1],
                edge_type=EdgeType.TAINT_FLOWS_TO,
                weight=1.0,
            ))

    def _create_vulnerable_via_edge(self, source_id: int, sink_id: int) -> None:
        self.graph_store.add_edge(GraphEdge(
            binary_hash=self.binary_hash,
            source_id=source_id,
            target_id=sink_id,
            edge_type=EdgeType.VULNERABLE_VIA,
            weight=1.0,
        ))

    def _find_source_nodes(self) -> List[GraphNode]:
        nodes = self.graph_store.get_nodes_by_type(self.binary_hash, "FUNCTION")
        results = []
        for node in nodes:
            # Tier 1: Security flags
            if self._has_any_flag(node.security_flags, self.SOURCE_FLAGS):
                results.append(node)
                continue
            # Tier 2: Network APIs
            if self._has_any_api(node.network_apis, self.TAINT_SOURCES):
                results.append(node)
                continue
            # Tier 3 (part a): File I/O APIs
            if self._has_any_api(node.file_io_apis, self.TAINT_SOURCES):
                results.append(node)
                continue
            # Tier 3 (part b): Function name check against TAINT_SOURCES
            if node.name:
                if node.name in self.TAINT_SOURCES or self._normalize_function_name(node.name) in self.TAINT_SOURCES:
                    results.append(node)
                    continue
            # Tier 4: Callees fallback
            callee_ids = self._get_callees(node.id)
            matched = False
            for callee_id in callee_ids:
                callee = self.graph_store.get_node_by_id(callee_id)
                if callee and callee.name:
                    if callee.name in self.TAINT_SOURCES or self._normalize_function_name(callee.name) in self.TAINT_SOURCES:
                        matched = True
                        break
            if matched:
                results.append(node)
                continue
        return results

    def _find_sink_nodes(self) -> List[GraphNode]:
        nodes = self.graph_store.get_nodes_by_type(self.binary_hash, "FUNCTION")
        results = []
        for node in nodes:
            # Tier 1: Security flags
            if self._has_any_flag(node.security_flags, self.SINK_FLAGS):
                results.append(node)
                continue
            # Tier 2: Network APIs
            if self._has_any_api(node.network_apis, self.TAINT_SINKS):
                results.append(node)
                continue
            # Tier 3 (part a): File I/O APIs
            if self._has_any_api(node.file_io_apis, self.TAINT_SINKS):
                results.append(node)
                continue
            # Tier 3 (part b): Function name check against TAINT_SINKS
            if node.name:
                if node.name in self.TAINT_SINKS or self._normalize_function_name(node.name) in self.TAINT_SINKS:
                    results.append(node)
                    continue
            # Tier 4: Callees fallback
            callee_ids = self._get_callees(node.id)
            matched = False
            for callee_id in callee_ids:
                callee = self.graph_store.get_node_by_id(callee_id)
                if callee and callee.name:
                    if callee.name in self.TAINT_SINKS or self._normalize_function_name(callee.name) in self.TAINT_SINKS:
                        matched = True
                        break
            if matched:
                results.append(node)
                continue
        return results

    def create_vulnerable_via_edges(self) -> int:
        """Create VULNERABLE_VIA edges from entry points to vulnerable nodes."""
        entry_points = self._find_entry_points()
        vulnerable_nodes = self._find_vulnerable_nodes()

        if not entry_points or not vulnerable_nodes:
            return 0

        edges_created = 0
        for entry in entry_points:
            if self.cancelled:
                break
            for vuln_node in vulnerable_nodes:
                if entry.id == vuln_node.id:
                    continue
                if self.graph_store.has_edge(entry.id, vuln_node.id, EdgeType.VULNERABLE_VIA.value):
                    continue
                path_length = self._bfs_path_length(entry.id, vuln_node.id)
                if path_length is not None:
                    vuln_type = self._get_vulnerability_type(vuln_node)
                    metadata = f'{{"path_length":{path_length},"vuln_type":"{vuln_type}"}}'
                    self.graph_store.add_edge(GraphEdge(
                        binary_hash=self.binary_hash,
                        source_id=entry.id,
                        target_id=vuln_node.id,
                        edge_type=EdgeType.VULNERABLE_VIA,
                        weight=1.0,
                        metadata=metadata,
                    ))
                    edges_created += 1
        return edges_created

    def _find_entry_points(self) -> List[GraphNode]:
        nodes = self.graph_store.get_nodes_by_type(self.binary_hash, "FUNCTION")
        entry_points = []
        seen_ids: Set = set()
        for node in nodes:
            is_entry = False
            flags = node.security_flags or []
            if "ENTRY_POINT" in flags or "EXPORTED" in flags:
                is_entry = True
            if node.name and node.name in self.ENTRY_POINT_NAMES:
                is_entry = True
            if is_entry and node.id not in seen_ids:
                seen_ids.add(node.id)
                entry_points.append(node)
        return entry_points

    def _find_vulnerable_nodes(self) -> List[GraphNode]:
        nodes = self.graph_store.get_nodes_by_type(self.binary_hash, "FUNCTION")
        vulnerable = []
        for node in nodes:
            flags = node.security_flags or []
            for flag in flags:
                if flag.endswith("_RISK") or flag.startswith("VULN_"):
                    vulnerable.append(node)
                    break
        return vulnerable

    def _get_vulnerability_type(self, node: GraphNode) -> str:
        flags = node.security_flags or []
        for flag in flags:
            if flag.startswith("VULN_"):
                return flag[5:]
        for flag in flags:
            if flag.endswith("_RISK"):
                return flag.replace("_RISK", "")
        return "UNKNOWN"

    def _bfs_path_length(self, source_id, target_id) -> Optional[int]:
        if source_id == target_id:
            return 0
        visited = {source_id}
        queue = [(source_id, 0)]
        while queue:
            current_id, depth = queue.pop(0)
            if depth >= self.MAX_PATH_LENGTH:
                continue
            for neighbor_id in self._get_callees(current_id):
                if neighbor_id == target_id:
                    return depth + 1
                if neighbor_id not in visited:
                    visited.add(neighbor_id)
                    queue.append((neighbor_id, depth + 1))
        return None

    @staticmethod
    def _normalize_function_name(name: str) -> str:
        if not name:
            return name
        normalized = name
        if "::" in normalized:
            normalized = normalized.split("::")[-1]
        if ".DLL_" in normalized.upper():
            idx = normalized.upper().find(".DLL_")
            if idx > 0:
                normalized = normalized[idx + 5:]
        if normalized.startswith("<EXTERNAL>::"):
            normalized = normalized[12:]
        if normalized.startswith("__imp_"):
            normalized = normalized[6:]
        while normalized.startswith("_") and len(normalized) > 1:
            normalized = normalized[1:]
        at_idx = normalized.rfind("@")
        if at_idx > 0:
            suffix = normalized[at_idx + 1:]
            if suffix.isdigit():
                normalized = normalized[:at_idx]
        return normalized

    @staticmethod
    def _has_any_flag(flags: Iterable[str], targets: Set[str]) -> bool:
        return any(flag in targets for flag in (flags or []))

    @staticmethod
    def _has_any_api(apis: Iterable[str], targets: Set[str]) -> bool:
        return any(api in targets for api in (apis or []))
