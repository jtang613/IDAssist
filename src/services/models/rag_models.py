#!/usr/bin/env python3

from typing import List, Dict, Any, Optional, NamedTuple
from dataclasses import dataclass
from enum import Enum


class SearchType(Enum):
    """Search type enumeration"""
    TEXT = "text"
    VECTOR = "vector"
    HYBRID = "hybrid"


@dataclass
class SearchResult:
    """Container for search results"""
    filename: str
    snippet: str
    score: float
    chunk_id: int
    search_type: SearchType = SearchType.HYBRID
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class DocumentMetadata:
    """Container for document metadata"""
    filename: str
    file_path: str
    chunk_count: int
    ingested_at: str
    file_size: int
    file_hash: str


@dataclass
class EmbeddingData:
    """Container for embedding data"""
    embedding: List[float]
    provider_name: str
    model_name: str
    chunk_id: int
    created_at: str


@dataclass
class RAGStats:
    """Container for RAG statistics"""
    indexed_documents: int
    total_chunks: int
    cached_embeddings: int
    index_path: str
    index_size_mb: float


@dataclass
class IngestRequest:
    """Container for document ingestion request"""
    file_paths: List[str]
    generate_embeddings: bool = True
    chunk_size: int = 500
    max_snippet_length: int = 500


@dataclass
class SearchRequest:
    """Container for search request"""
    query: str
    search_type: SearchType = SearchType.HYBRID
    max_results: int = 10
    similarity_threshold: float = 0.5
    include_metadata: bool = False
