#!/usr/bin/env python3

"""
Structure Extractor for IDAssist GraphRAG

Full rewrite of BinAssist's StructureExtractor for IDA Pro 9.x.
Uses IDA API for function enumeration, call graph construction,
and decompilation.
"""

import os
import threading
from dataclasses import dataclass
from typing import Callable, List, Optional

from .graph_store import GraphStore
from .models import GraphNode, GraphEdge, EdgeType
from .security_feature_extractor import SecurityFeatureExtractor
from ..binary_context_service import BinaryContextService, ViewLevel

from src.ida_compat import log, execute_on_main_thread

# IDA imports
try:
    import idaapi
    import idautils
    import ida_funcs
    import ida_hexrays
    import ida_name
    import idc
    _IN_IDA = True
except ImportError:
    _IN_IDA = False


DEFAULT_THREAD_COUNT = max(2, os.cpu_count() // 2 if os.cpu_count() else 2)


@dataclass
class ExtractionResult:
    """Result of structure extraction."""
    functions_extracted: int = 0
    edges_created: int = 0


class StructureExtractor:
    """Extracts function nodes and relationships into the GraphRAG store.

    IDA Pro version: uses idautils.Functions(), CodeRefsFrom/To(),
    and ida_hexrays.decompile() for enrichment.
    """

    def __init__(self, graph_store: GraphStore):
        self.graph_store = graph_store
        self.security_extractor = SecurityFeatureExtractor()
        self.context_service = BinaryContextService()
        self._cancelled = False
        self._progress_lock = threading.Lock()

    def cancel(self):
        """Cancel the extraction process."""
        self._cancelled = True

    def extract_function(self, func_ea: int, binary_hash: str) -> Optional[GraphNode]:
        """Extract a single function into the graph store.

        Args:
            func_ea: Function start address
            binary_hash: Hash of the binary
        """
        if func_ea is None or not binary_hash:
            return None

        name_holder = [None]

        def _get_name():
            name_holder[0] = ida_funcs.get_func_name(func_ea) or f"sub_{func_ea:x}"

        execute_on_main_thread(_get_name)
        func_name = name_holder[0]

        node = self.graph_store.get_node_by_address(binary_hash, "FUNCTION", func_ea)
        if node is None:
            node = GraphNode(
                binary_hash=binary_hash,
                node_type="FUNCTION",
                address=func_ea,
                name=func_name,
            )
        else:
            node.name = func_name

        raw_code = self._get_raw_code(func_ea)
        features = self.security_extractor.extract_features_from_code(func_name, raw_code)
        node.network_apis = sorted(features.network_apis)
        node.file_io_apis = sorted(features.file_io_apis)
        node.ip_addresses = sorted(features.ip_addresses)
        node.urls = sorted(features.urls)
        node.file_paths = sorted(features.file_paths)
        node.domains = sorted(features.domains)
        node.registry_keys = sorted(features.registry_keys)
        node.activity_profile = features.get_activity_profile()
        node.risk_level = features.get_risk_level()
        node.security_flags = features.generate_security_flags()
        if raw_code:
            node.raw_code = raw_code
        node.is_stale = True

        node = self.graph_store.upsert_node(node)

        self._extract_call_edges(func_ea, binary_hash, node)
        return node

    def _extract_call_edges(self, func_ea: int, binary_hash: str, node: GraphNode) -> int:
        """Extract call edges for a function using IDA cross-references."""
        edges_created = 0

        # Gather all cross-reference data on the main thread
        # xref_data: ([(callee_ea, callee_name), ...], [(caller_ea, caller_name), ...])
        xref_data = [None]

        def _gather_xrefs():
            callees = []
            func = ida_funcs.get_func(func_ea)
            if func:
                callee_addrs = set()
                for item_ea in idautils.FuncItems(func_ea):
                    for ref in idautils.CodeRefsFrom(item_ea, 0):
                        ref_func = ida_funcs.get_func(ref)
                        if ref_func and ref_func.start_ea != func_ea:
                            callee_addrs.add(ref_func.start_ea)
                for ea in callee_addrs:
                    cn = ida_funcs.get_func_name(ea) or f"sub_{ea:x}"
                    callees.append((ea, cn))

            callers = []
            caller_addrs = set()
            for ref in idautils.CodeRefsTo(func_ea, 0):
                caller_func = ida_funcs.get_func(ref)
                if caller_func and caller_func.start_ea != func_ea:
                    caller_addrs.add(caller_func.start_ea)
            for ea in caller_addrs:
                cn = ida_funcs.get_func_name(ea) or f"sub_{ea:x}"
                callers.append((ea, cn))

            xref_data[0] = (callees, callers)

        execute_on_main_thread(_gather_xrefs)
        callee_list, caller_list = xref_data[0]

        # Process callees — graph store operations only (thread-safe)
        for callee_ea, callee_name in callee_list:
            callee_node = self.graph_store.get_node_by_address(binary_hash, "FUNCTION", callee_ea)
            if callee_node is None:
                callee_node = GraphNode(
                    binary_hash=binary_hash,
                    node_type="FUNCTION",
                    address=callee_ea,
                    name=callee_name,
                    is_stale=True,
                )
                callee_node = self.graph_store.upsert_node(callee_node)

            self.graph_store.add_edge(GraphEdge(
                binary_hash=binary_hash,
                source_id=node.id,
                target_id=callee_node.id,
                edge_type=EdgeType.CALLS,
                weight=1.0,
            ))
            edges_created += 1

            if callee_node.security_flags and any(flag.endswith("_RISK") for flag in callee_node.security_flags):
                self.graph_store.add_edge(GraphEdge(
                    binary_hash=binary_hash,
                    source_id=node.id,
                    target_id=callee_node.id,
                    edge_type=EdgeType.CALLS_VULNERABLE,
                    weight=1.0,
                ))
                edges_created += 1
                if "CALLS_VULNERABLE_FUNCTION" not in node.security_flags:
                    node.security_flags.append("CALLS_VULNERABLE_FUNCTION")
                    self.graph_store.upsert_node(node)

        # Process callers — graph store operations only (thread-safe)
        for caller_ea, caller_name in caller_list:
            caller_node = self.graph_store.get_node_by_address(binary_hash, "FUNCTION", caller_ea)
            if caller_node is None:
                caller_node = GraphNode(
                    binary_hash=binary_hash,
                    node_type="FUNCTION",
                    address=caller_ea,
                    name=caller_name,
                    is_stale=True,
                )
                caller_node = self.graph_store.upsert_node(caller_node)

            if not self.graph_store.has_edge(caller_node.id, node.id, EdgeType.CALLS.value):
                self.graph_store.add_edge(GraphEdge(
                    binary_hash=binary_hash,
                    source_id=caller_node.id,
                    target_id=node.id,
                    edge_type=EdgeType.CALLS,
                    weight=1.0,
                ))
                edges_created += 1

        return edges_created

    def extract_structure(
        self,
        binary_hash: str,
        progress_callback: Optional[Callable[[int, int, str], None]] = None
    ) -> ExtractionResult:
        """
        Phase 1: Fast structure-only extraction.

        Extracts function names, addresses, and call graph.
        No decompilation - just structure.
        All IDA API calls are marshalled to the main thread.
        """
        self._cancelled = False
        result = ExtractionResult()

        # Get function list on main thread
        func_eas_holder = [[]]

        def _get_funcs():
            func_eas_holder[0] = list(idautils.Functions())

        execute_on_main_thread(_get_funcs)
        func_eas = func_eas_holder[0]
        total = len(func_eas)

        if total == 0:
            return result

        log.log_info(f"Phase 1: Extracting structure for {total} functions")

        # Clean up duplicates from previous runs
        dup_nodes = self.graph_store.deduplicate_nodes(binary_hash)
        dup_edges = self.graph_store.deduplicate_edges(binary_hash)
        if dup_nodes > 0 or dup_edges > 0:
            log.log_info(f"Removed {dup_nodes} duplicate nodes, {dup_edges} duplicate edges")

        existing_count = self.graph_store.preload_node_cache(binary_hash)
        if existing_count > 0:
            log.log_info(f"Loaded {existing_count} existing node IDs for reindex")

        if progress_callback:
            progress_callback(0, total, f"Phase 1: Extracting structure...")

        for i, func_ea in enumerate(func_eas):
            if self._cancelled:
                break

            try:
                # Gather all IDA data for this function on the main thread
                # ida_data: (func_name, [(callee_ea, callee_name), ...])
                ida_data = [None]

                def _gather():
                    try:
                        fn = ida_funcs.get_func_name(func_ea) or f"sub_{func_ea:x}"
                        call_targets = []
                        func = ida_funcs.get_func(func_ea)
                        if func:
                            for item_ea in idautils.FuncItems(func_ea):
                                for ref in idautils.CodeRefsFrom(item_ea, 0):
                                    try:
                                        ref_func = ida_funcs.get_func(ref)
                                        if ref_func and ref_func.start_ea != func_ea:
                                            cea = ref_func.start_ea
                                            cn = ida_funcs.get_func_name(cea) or f"sub_{cea:x}"
                                            call_targets.append((cea, cn))
                                    except Exception:
                                        pass
                        ida_data[0] = (fn, call_targets)
                    except Exception:
                        ida_data[0] = (f"sub_{func_ea:x}", [])

                execute_on_main_thread(_gather)
                func_name, call_targets = ida_data[0]

                # Graph operations below — thread-safe, no IDA calls
                node = GraphNode(
                    binary_hash=binary_hash,
                    node_type="FUNCTION",
                    address=func_ea,
                    name=func_name,
                    raw_code=None,
                    is_stale=True,
                )
                node = self.graph_store.queue_node_for_batch(node)

                for callee_ea, callee_name in call_targets:
                    callee_id = self.graph_store.get_cached_node_id(binary_hash, callee_ea)
                    if not callee_id:
                        callee_node = GraphNode(
                            binary_hash=binary_hash,
                            node_type="FUNCTION",
                            address=callee_ea,
                            name=callee_name,
                            is_stale=True,
                        )
                        callee_node = self.graph_store.queue_node_for_batch(callee_node)
                        callee_id = callee_node.id
                    self.graph_store.queue_edge_for_batch(
                        node.id, callee_id, EdgeType.CALLS, binary_hash
                    )

                result.functions_extracted += 1

                if progress_callback and (i % 10 == 0 or i == total - 1):
                    progress_callback(i + 1, total, f"Phase 1: {i + 1}/{total} functions")

            except Exception as e:
                log.log_warn(f"Failed to extract function at 0x{func_ea:x}: {e}")

            if (i + 1) % 500 == 0:
                self.graph_store.flush_all_batches()

        self.graph_store.flush_all_batches()

        edges = self.graph_store.get_edges_by_types(binary_hash, [EdgeType.CALLS.value])
        result.edges_created = len(edges)

        log.log_info(f"Phase 1 complete: {result.functions_extracted} functions, {result.edges_created} edges")
        return result

    def enrich_all(
        self,
        binary_hash: str,
        progress_callback: Optional[Callable[[int, int, str], None]] = None
    ) -> int:
        """
        Phase 2: Enrich all stale nodes with decompiled code and security features.

        IDA's Hex-Rays is synchronous, so this is straightforward.
        """
        self._cancelled = False

        stale_nodes = self.graph_store.get_stale_nodes(binary_hash)
        total = len(stale_nodes)

        if total == 0:
            return 0

        log.log_info(f"Phase 2: Enriching {total} functions with decompilation")

        if progress_callback:
            progress_callback(0, total, f"Phase 2: Decompiling...")

        enriched = 0
        for i, node in enumerate(stale_nodes):
            if self._cancelled:
                break

            try:
                # Check function existence and get name on main thread
                ida_data = [None]

                def _gather_enrich():
                    try:
                        func = ida_funcs.get_func(node.address)
                        if not func:
                            ida_data[0] = (False, None)
                            return
                        fn = ida_funcs.get_func_name(node.address) or node.name
                        ida_data[0] = (True, fn)
                    except Exception:
                        ida_data[0] = (False, None)

                execute_on_main_thread(_gather_enrich)
                func_exists, func_name_result = ida_data[0]

                if not func_exists:
                    continue

                # _get_raw_code already uses execute_on_main_thread internally
                raw_code = self._get_raw_code(node.address)
                if raw_code:
                    node.raw_code = raw_code

                func_name = func_name_result
                features = self.security_extractor.extract_features_from_code(func_name, raw_code)
                node.network_apis = sorted(features.network_apis)
                node.file_io_apis = sorted(features.file_io_apis)
                node.ip_addresses = sorted(features.ip_addresses)
                node.urls = sorted(features.urls)
                node.file_paths = sorted(features.file_paths)
                node.domains = sorted(features.domains)
                node.registry_keys = sorted(features.registry_keys)
                node.activity_profile = features.get_activity_profile()
                node.risk_level = features.get_risk_level()
                node.security_flags = features.generate_security_flags()
                node.is_stale = False

                self.graph_store.upsert_node(node)
                enriched += 1

                if progress_callback and (i % 10 == 0 or i == total - 1):
                    progress_callback(i + 1, total, f"Phase 2: {i + 1}/{total} decompiled")

            except Exception as e:
                log.log_warn(f"Failed to enrich {node.name}: {e}")

        log.log_info(f"Phase 2 complete: {enriched} functions enriched")
        return enriched

    def extract_all(
        self,
        binary_hash: str,
        progress_callback: Optional[Callable[[int, int, str], None]] = None
    ) -> ExtractionResult:
        """Extract all functions and their relationships."""
        result = ExtractionResult()

        func_eas_holder = [[]]

        def _get_funcs():
            func_eas_holder[0] = list(idautils.Functions())

        execute_on_main_thread(_get_funcs)
        func_eas = func_eas_holder[0]
        total = len(func_eas)

        if progress_callback:
            progress_callback(0, total, f"Extracting {total} functions...")

        for i, func_ea in enumerate(func_eas):
            try:
                node = self.extract_function(func_ea, binary_hash)
                if node:
                    result.functions_extracted += 1

                if progress_callback and (i % 10 == 0 or i == total - 1):
                    name_holder = [f"sub_{func_ea:x}"]

                    def _get_name():
                        name_holder[0] = ida_funcs.get_func_name(func_ea) or f"sub_{func_ea:x}"

                    execute_on_main_thread(_get_name)
                    progress_callback(i + 1, total, f"Extracted {name_holder[0]}")

            except Exception as e:
                log.log_warn(f"Failed to extract function at 0x{func_ea:x}: {e}")

        edges = self.graph_store.get_edges_by_types(binary_hash, [EdgeType.CALLS.value])
        result.edges_created = len(edges)

        if progress_callback:
            progress_callback(total, total, "Extraction complete")

        log.log_info(f"Structure extraction complete: {result.functions_extracted} functions, {result.edges_created} edges")
        return result

    def extract_all_parallel(
        self,
        binary_hash: str,
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
        thread_count: int = DEFAULT_THREAD_COUNT
    ) -> ExtractionResult:
        """Two-phase extraction with progress on both phases."""
        # Phase 1: Structure (fast)
        result = self.extract_structure(binary_hash, progress_callback)

        if self._cancelled:
            return result

        # Phase 2: Enrichment (slower - decompilation)
        self.enrich_all(binary_hash, progress_callback)

        return result

    def _get_raw_code(self, address: int) -> Optional[str]:
        """Get decompiled or disassembled code for a function.

        All IDA API calls are marshalled to the main thread.
        """
        if not address:
            return None

        result = [None]

        def _do():
            # Try Hex-Rays decompilation first
            try:
                cfunc = ida_hexrays.decompile(address)
                if cfunc:
                    result[0] = str(cfunc)
                    return
            except Exception:
                pass

            # Fall back to assembly
            try:
                func = ida_funcs.get_func(address)
                if func:
                    lines = []
                    for item_ea in idautils.FuncItems(func.start_ea):
                        disasm = idc.generate_disasm_line(item_ea, 0)
                        if disasm:
                            lines.append(f"0x{item_ea:08x}  {disasm}")
                    if lines:
                        result[0] = "\n".join(lines)
            except Exception:
                pass

        execute_on_main_thread(_do)
        return result[0]
