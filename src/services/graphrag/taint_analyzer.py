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
            if self._has_any_flag(node.security_flags, self.SOURCE_FLAGS):
                results.append(node)
                continue
            if self._has_any_api(node.network_apis, self.TAINT_SOURCES):
                results.append(node)
                continue
            if self._has_any_api(node.file_io_apis, self.TAINT_SOURCES):
                results.append(node)
                continue
        return results

    def _find_sink_nodes(self) -> List[GraphNode]:
        nodes = self.graph_store.get_nodes_by_type(self.binary_hash, "FUNCTION")
        results = []
        for node in nodes:
            if self._has_any_flag(node.security_flags, self.SINK_FLAGS):
                results.append(node)
                continue
            if self._has_any_api(node.network_apis, self.TAINT_SINKS):
                results.append(node)
                continue
            if self._has_any_api(node.file_io_apis, self.TAINT_SINKS):
                results.append(node)
                continue
        return results

    @staticmethod
    def _has_any_flag(flags: Iterable[str], targets: Set[str]) -> bool:
        return any(flag in targets for flag in (flags or []))

    @staticmethod
    def _has_any_api(apis: Iterable[str], targets: Set[str]) -> bool:
        return any(api in targets for api in (apis or []))
