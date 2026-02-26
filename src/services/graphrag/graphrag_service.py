#!/usr/bin/env python3

from typing import Optional

from .graph_store import GraphStore
from .models import GraphNode, GraphEdge
from .structure_extractor import StructureExtractor
from .semantic_extractor import SemanticExtractor, ExtractionResult
from ..analysis_db_service import AnalysisDBService

from src.ida_compat import log


class GraphRAGService:
    """
    High-level facade for GraphRAG storage.

    This is a minimal skeleton to be expanded with extractors, caching,
    and background semantic analysis in subsequent phases.
    """

    _instance = None

    def __init__(self, analysis_db: Optional[AnalysisDBService] = None):
        self.analysis_db = analysis_db or AnalysisDBService()
        self.store = GraphStore(self.analysis_db)

    @classmethod
    def get_instance(cls, analysis_db: Optional[AnalysisDBService] = None) -> "GraphRAGService":
        if cls._instance is None:
            cls._instance = GraphRAGService(analysis_db)
        return cls._instance

    def get_node_by_address(self, binary_hash: str, node_type: str, address: int) -> Optional[GraphNode]:
        return self.store.get_node_by_address(binary_hash, node_type, address)

    def upsert_node(self, node: GraphNode) -> GraphNode:
        return self.store.upsert_node(node)

    def add_edge(self, edge: GraphEdge) -> GraphEdge:
        return self.store.add_edge(edge)

    def search_nodes(self, binary_hash: str, query: str, limit: int = 10):
        return self.store.search_nodes(binary_hash, query, limit)

    def index_function(self, binary_view, function, binary_hash: str) -> Optional[GraphNode]:
        extractor = StructureExtractor(binary_view, self.store)
        return extractor.extract_function(function, binary_hash)

    async def summarize_stale_nodes(self, binary_view, binary_hash: str, provider,
                                    limit: int = 0, progress_callback=None) -> ExtractionResult:
        extractor = SemanticExtractor(provider, self.store, binary_view, binary_hash)
        return await extractor.summarize_stale_nodes(limit, progress_callback)
