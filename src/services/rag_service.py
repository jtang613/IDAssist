#!/usr/bin/env python3

import os
import json
import math
import pickle
import threading
import hashlib
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
from datetime import datetime

from whoosh import fields, index
from whoosh.qparser import QueryParser
from whoosh.query import Query, Term, And, Or, NumericRange
from whoosh.scoring import BM25F
from whoosh.analysis import StandardAnalyzer

from src.ida_compat import log, get_user_data_dir
from .models.rag_models import (
    SearchResult, DocumentMetadata, EmbeddingData, RAGStats,
    IngestRequest, SearchRequest, SearchType
)
from .settings_service import SettingsService
from .llm_providers.provider_factory import LLMProviderFactory


class RAGService:
    """
    Whoosh-based RAG service with hybrid search capabilities.

    Features:
    - BM25 full-text search using Whoosh
    - Vector similarity search using LLM provider embeddings
    - Hybrid search combining both approaches
    - Embedding caching for performance
    - Thread-safe operations
    - Document management (ingest, delete, list)
    """

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        """Singleton pattern implementation"""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        """Initialize the RAG service"""
        if hasattr(self, '_initialized'):
            return

        self._initialized = True
        self.settings_service = SettingsService()
        self.llm_factory = LLMProviderFactory()

        # Setup paths
        self._setup_paths()

        # Thread safety
        self._operation_lock = threading.RLock()

        # Initialize components
        self._schema = self._create_schema()
        self._index = self._get_or_create_index()
        self._embeddings_cache: Dict[str, EmbeddingData] = {}
        self._metadata: Dict[str, DocumentMetadata] = {}

        # TF-IDF vocabulary for consistent embeddings
        self._tfidf_vocabulary: Dict[str, int] = {}
        self._tfidf_document_corpus: List[List[str]] = []

        # Load existing data
        self._load_embeddings_cache()
        self._load_metadata()
        self._load_vocabulary()

        # Verify consistency between cache and index
        self._verify_cache_consistency()

        # Configuration
        self.chunk_size = 500
        self.max_snippet_length = 500

        log.log_info(f"RAG service initialized with index at: {self.index_path}")

    def _setup_paths(self):
        """Setup file paths for index and caches"""
        try:
            idassist_dir = get_user_data_dir()

            # IDAssist directory is already created by get_user_data_dir()

            self.index_path = Path(idassist_dir) / 'rag_index'
            self.embeddings_path = self.index_path / 'embeddings.pkl'
            self.metadata_path = self.index_path / 'metadata.json'
            self.vocabulary_path = self.index_path / 'vocabulary.json'

            # Create index directory
            self.index_path.mkdir(parents=True, exist_ok=True)

        except Exception as e:
            raise RuntimeError(f"Failed to setup RAG service paths: {e}")

    def _create_schema(self) -> fields.Schema:
        """Create the Whoosh schema for documents"""
        return fields.Schema(
            filename=fields.TEXT(stored=True, phrase=False),
            chunk_id=fields.NUMERIC(stored=True),
            content=fields.TEXT(stored=True, analyzer=StandardAnalyzer()),
            doc_hash=fields.ID(stored=True, unique=True),
            file_path=fields.TEXT(stored=True),
            ingested_at=fields.DATETIME(stored=True)
        )

    def _get_or_create_index(self) -> index.Index:
        """Get existing index or create a new one"""
        try:
            if index.exists_in(str(self.index_path)):
                log.log_debug("Opening existing Whoosh index")
                return index.open_dir(str(self.index_path))
            else:
                log.log_debug("Creating new Whoosh index")
                return index.create_in(str(self.index_path), self._schema)
        except Exception as e:
            log.log_error(f"Error with index: {e}")
            # Try to create a new index
            return index.create_in(str(self.index_path), self._schema)

    def _load_embeddings_cache(self) -> None:
        """Load embeddings cache from disk"""
        try:
            if self.embeddings_path.exists():
                with open(self.embeddings_path, 'rb') as f:
                    cache_data = pickle.load(f)
                    # Convert to EmbeddingData objects if needed
                    for key, value in cache_data.items():
                        if isinstance(value, dict):
                            self._embeddings_cache[key] = EmbeddingData(**value)
                        else:
                            self._embeddings_cache[key] = value
                log.log_debug(f"Loaded {len(self._embeddings_cache)} embeddings from cache")
        except Exception as e:
            log.log_warn(f"Error loading embeddings cache: {e}")
            self._embeddings_cache = {}

    def _save_embeddings_cache(self) -> None:
        """Save embeddings cache to disk"""
        try:
            # Convert EmbeddingData objects to dicts for serialization
            cache_data = {}
            for key, embedding_data in self._embeddings_cache.items():
                if hasattr(embedding_data, '__dict__'):
                    cache_data[key] = embedding_data.__dict__
                else:
                    cache_data[key] = embedding_data

            with open(self.embeddings_path, 'wb') as f:
                pickle.dump(cache_data, f)
            log.log_debug(f"Saved {len(self._embeddings_cache)} embeddings to cache")
        except Exception as e:
            log.log_error(f"Error saving embeddings cache: {e}")

    def _load_metadata(self) -> None:
        """Load metadata from disk"""
        try:
            if self.metadata_path.exists():
                with open(self.metadata_path, 'r') as f:
                    metadata_dict = json.load(f)
                    # Convert to DocumentMetadata objects
                    for filename, metadata in metadata_dict.items():
                        if isinstance(metadata, dict):
                            self._metadata[filename] = DocumentMetadata(**metadata)
                        else:
                            self._metadata[filename] = metadata
                log.log_debug(f"Loaded metadata for {len(self._metadata)} documents")
        except Exception as e:
            log.log_warn(f"Error loading metadata: {e}")
            self._metadata = {}

    def _save_metadata(self) -> None:
        """Save metadata to disk"""
        try:
            # Convert DocumentMetadata objects to dicts for serialization
            metadata_dict = {}
            for filename, doc_metadata in self._metadata.items():
                if hasattr(doc_metadata, '__dict__'):
                    metadata_dict[filename] = doc_metadata.__dict__
                else:
                    metadata_dict[filename] = doc_metadata

            with open(self.metadata_path, 'w') as f:
                json.dump(metadata_dict, f, indent=2, default=str)
            log.log_debug(f"Saved metadata for {len(self._metadata)} documents")
        except Exception as e:
            log.log_error(f"Error saving metadata: {e}")

    def _load_vocabulary(self) -> None:
        """Load TF-IDF vocabulary from disk"""
        try:
            log.log_info(f"Attempting to load vocabulary from: {self.vocabulary_path}")
            if self.vocabulary_path.exists():
                log.log_info(f"Vocabulary file exists, size: {self.vocabulary_path.stat().st_size} bytes")
                with open(self.vocabulary_path, 'r') as f:
                    vocab_data = json.load(f)
                    self._tfidf_vocabulary = vocab_data.get('vocabulary', {})
                    # Convert string keys to int values for vocabulary
                    self._tfidf_vocabulary = {k: int(v) for k, v in self._tfidf_vocabulary.items()}
                    # Load tokenized corpus for IDF calculation
                    corpus_data = vocab_data.get('corpus', [])
                    self._tfidf_document_corpus = corpus_data
                log.log_info(f"Loaded TF-IDF vocabulary: {len(self._tfidf_vocabulary)} terms, {len(self._tfidf_document_corpus)} docs")
            else:
                log.log_warn(f"Vocabulary file does not exist: {self.vocabulary_path}")
                self._tfidf_vocabulary = {}
                self._tfidf_document_corpus = []
        except Exception as e:
            log.log_error(f"Error loading vocabulary: {e}")
            self._tfidf_vocabulary = {}
            self._tfidf_document_corpus = []

    def _save_vocabulary(self) -> None:
        """Save TF-IDF vocabulary to disk"""
        try:
            vocab_data = {
                'vocabulary': self._tfidf_vocabulary,
                'corpus': self._tfidf_document_corpus
            }
            with open(self.vocabulary_path, 'w') as f:
                json.dump(vocab_data, f, indent=2)
            log.log_debug(f"Saved TF-IDF vocabulary: {len(self._tfidf_vocabulary)} terms")
        except Exception as e:
            log.log_error(f"Error saving vocabulary: {e}")

    def _chunk_content(self, content: str, chunk_size: int = None) -> List[str]:
        """Split content into chunks with intelligent boundary detection"""
        if chunk_size is None:
            chunk_size = self.chunk_size

        chunks = []
        start = 0

        while start < len(content):
            end = start + chunk_size
            if end >= len(content):
                chunks.append(content[start:])
                break

            # Try to split at paragraph boundary
            split_pos = content.find('\n\n', end)
            if split_pos == -1 or split_pos > start + chunk_size * 1.5:
                # Try to split at sentence boundary
                split_pos = content.rfind('.', start, end)
                if split_pos == -1 or split_pos < start + chunk_size * 0.5:
                    # No good split point, just use the chunk size
                    chunks.append(content[start:end])
                    start = end
                else:
                    chunks.append(content[start:split_pos + 1])
                    start = split_pos + 1
            else:
                chunks.append(content[start:split_pos + 2])
                start = split_pos + 2

        return chunks

    def _generate_doc_hash(self, filename: str, chunk_id: int) -> str:
        """Generate a unique hash for a document chunk"""
        hash_input = f"{filename}_{chunk_id}"
        return hashlib.md5(hash_input.encode()).hexdigest()

    def _generate_file_hash(self, file_path: str) -> str:
        """Generate a hash for the file content"""
        try:
            hasher = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()[:16]
        except Exception as e:
            log.log_warn(f"Failed to generate file hash for {file_path}: {e}")
            return hashlib.sha256(f"fallback:{file_path}:{datetime.now().isoformat()}".encode()).hexdigest()[:16]

    def _update_tfidf_corpus(self, texts: List[str]) -> None:
        """Update the TF-IDF corpus and vocabulary with new texts"""
        import re
        from collections import Counter

        # Tokenize new texts
        new_tokenized = []
        for text in texts:
            tokens = re.findall(r'\b\w+\b', text.lower())
            new_tokenized.append(tokens)
            self._tfidf_document_corpus.append(tokens)

        # Rebuild vocabulary from entire corpus
        word_counts = Counter()
        for tokens in self._tfidf_document_corpus:
            word_counts.update(set(tokens))  # Only count once per document

        # Take top N most common words to limit dimension
        vocab_size = min(1000, len(word_counts))
        self._tfidf_vocabulary = {}
        for i, (word, _) in enumerate(word_counts.most_common(vocab_size)):
            self._tfidf_vocabulary[word] = i

        log.log_info(f"Updated TF-IDF vocabulary: {len(self._tfidf_vocabulary)} terms, corpus: {len(self._tfidf_document_corpus)} docs")

        # Immediately save the vocabulary after updating
        self._save_vocabulary()

    def _generate_tfidf_embedding(self, text: str) -> List[float]:
        """Generate a single TF-IDF embedding using the stored vocabulary"""
        import re
        import math
        from collections import Counter

        if not self._tfidf_vocabulary:
            log.log_warn(f"No TF-IDF vocabulary available. Vocab size: {len(self._tfidf_vocabulary)}, Corpus size: {len(self._tfidf_document_corpus)}")
            # Try to reload vocabulary
            self._load_vocabulary()
            if not self._tfidf_vocabulary:
                log.log_error("Failed to load vocabulary even after retry")
                return [0.0] * 1000  # Return zero vector
            else:
                log.log_info(f"Successfully reloaded vocabulary: {len(self._tfidf_vocabulary)} terms")

        # Tokenize the text
        tokens = re.findall(r'\b\w+\b', text.lower())

        # Initialize vector
        vector = [0.0] * len(self._tfidf_vocabulary)

        # Calculate term frequencies
        token_counts = Counter(tokens)
        total_tokens = len(tokens)

        for word, tf_count in token_counts.items():
            if word in self._tfidf_vocabulary:
                # Term frequency
                tf = tf_count / total_tokens if total_tokens > 0 else 0

                # Document frequency
                df = sum(1 for doc_tokens in self._tfidf_document_corpus if word in doc_tokens)

                # Inverse document frequency
                idf = math.log(len(self._tfidf_document_corpus) / df) if df > 0 else 0

                # TF-IDF score
                tfidf = tf * idf
                vector[self._tfidf_vocabulary[word]] = tfidf

        # Normalize vector (L2 normalization)
        norm = math.sqrt(sum(x * x for x in vector))
        if norm > 0:
            vector = [x / norm for x in vector]

        return vector

    def _verify_cache_consistency(self) -> None:
        """Verify that cached embeddings match what's in the index"""
        try:
            with self._index.searcher() as searcher:
                index_doc_count = searcher.doc_count()
                cache_count = len(self._embeddings_cache)

                log.log_info(f"Index has {index_doc_count} documents, cache has {cache_count} embeddings")

                if cache_count > 0 and index_doc_count == 0:
                    log.log_warn("Embeddings cache exists but index is empty - clearing stale cache")
                    self._embeddings_cache.clear()
                    self._metadata.clear()
                    self._tfidf_vocabulary.clear()
                    self._tfidf_document_corpus.clear()
                    self._save_embeddings_cache()
                    self._save_metadata()
                    self._save_vocabulary()
                elif cache_count != index_doc_count:
                    log.log_warn(f"Cache/index mismatch: {cache_count} cached vs {index_doc_count} indexed")

        except Exception as e:
            log.log_error(f"Error verifying cache consistency: {e}")

    # Public API Methods

    def ingest_documents(self, request: IngestRequest) -> bool:
        """Ingest documents into the RAG index"""
        log.log_info(f"Ingesting {len(request.file_paths)} documents")

        with self._operation_lock:
            writer = self._index.writer()

            try:
                active_provider = None
                provider_instance = None
                if request.generate_embeddings:
                    active_provider = self.settings_service.get_active_llm_provider()
                    log.log_info(f"Active provider for embeddings: {active_provider}")
                    if active_provider:
                        provider_instance = self.llm_factory.create_provider(active_provider)
                        if not hasattr(provider_instance, 'get_embeddings'):
                            log.log_warn("Active LLM provider does not support embeddings")
                            active_provider = None
                            provider_instance = None
                        else:
                            log.log_info(f"Provider {active_provider.get('name', 'unknown')} supports embeddings")
                    else:
                        log.log_warn("No active LLM provider for embeddings")
                        provider_instance = None

                for file_path in request.file_paths:
                    log.log_debug(f"Processing file: {file_path}")

                    try:
                        # Read file content
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()

                        # Get file info
                        filename = os.path.basename(file_path)
                        file_stat = os.stat(file_path)
                        file_hash = self._generate_file_hash(file_path)

                        # Chunk the content
                        chunks = self._chunk_content(content, request.chunk_size)

                        # Always update TF-IDF corpus for vector search (regardless of embeddings)
                        self._update_tfidf_corpus(chunks)

                        # Process each chunk
                        embeddings_to_generate = []
                        for chunk_id, chunk in enumerate(chunks):
                            doc_hash = self._generate_doc_hash(filename, chunk_id)

                            # Add to Whoosh index
                            log.log_debug(f"Adding chunk {chunk_id} to index for {filename}")
                            writer.add_document(
                                filename=filename,
                                chunk_id=chunk_id,
                                content=chunk,
                                doc_hash=doc_hash,
                                file_path=file_path,
                                ingested_at=datetime.now()
                            )

                            # Prepare for embedding generation (always add if embeddings requested)
                            if request.generate_embeddings:
                                embeddings_to_generate.append((filename, chunk_id, chunk))

                        # Generate embeddings in batch if provider is available
                        if embeddings_to_generate and provider_instance:
                            log.log_info(f"Generating embeddings for {len(embeddings_to_generate)} chunks from {filename}")
                            self._generate_embeddings_batch(embeddings_to_generate, provider_instance, active_provider)
                        elif embeddings_to_generate:
                            log.log_warn(f"Have {len(embeddings_to_generate)} chunks to embed but no provider instance")
                            # Generate TF-IDF embeddings directly as fallback
                            log.log_info(f"Generating TF-IDF embeddings directly for {len(embeddings_to_generate)} chunks")
                            self._generate_tfidf_embeddings_batch(embeddings_to_generate)
                        else:
                            log.log_warn(f"No embeddings to generate for {filename}")

                        # Update metadata
                        self._metadata[filename] = DocumentMetadata(
                            filename=filename,
                            file_path=file_path,
                            chunk_count=len(chunks),
                            ingested_at=datetime.now().isoformat(),
                            file_size=file_stat.st_size,
                            file_hash=file_hash
                        )

                    except Exception as e:
                        log.log_error(f"Error processing file {file_path}: {e}")
                        continue

                # Commit all changes
                log.log_info("Committing changes to Whoosh index")
                writer.commit()

                # Verify the commit worked
                with self._index.searcher() as searcher:
                    doc_count = searcher.doc_count()
                    log.log_info(f"Index now contains {doc_count} documents after commit")

                self._save_embeddings_cache()
                self._save_metadata()
                self._save_vocabulary()

                log.log_info(f"Successfully ingested {len(request.file_paths)} documents")
                return True

            except Exception as e:
                log.log_error(f"Error during ingestion: {e}")
                writer.cancel()
                return False

    def _generate_embeddings_batch(self, chunks_data: List[Tuple[str, int, str]],
                                 provider_instance, provider_config: Dict[str, Any]) -> None:
        """Generate embeddings for a batch of chunks"""
        try:
            # Extract texts for batch processing
            texts = [chunk_text for _, _, chunk_text in chunks_data]
            log.log_info(f"Calling get_embeddings for {len(texts)} texts")

            # Generate embeddings
            embeddings = provider_instance.get_embeddings(texts)
            log.log_info(f"Got {len(embeddings)} embeddings back")

            # Store embeddings with metadata
            for (filename, chunk_id, _), embedding in zip(chunks_data, embeddings):
                cache_key = f"{filename}_{chunk_id}"
                self._embeddings_cache[cache_key] = EmbeddingData(
                    embedding=embedding,
                    provider_name=provider_config.get('provider_type', 'unknown'),
                    model_name=provider_config.get('model', 'unknown'),
                    chunk_id=chunk_id,
                    created_at=datetime.now().isoformat()
                )
                log.log_debug(f"Stored embedding for {cache_key}")

            log.log_info(f"Generated and cached {len(embeddings)} embeddings. Total cache size: {len(self._embeddings_cache)}")

        except Exception as e:
            log.log_error(f"Error generating embeddings: {e}")

    def _generate_tfidf_embeddings_batch(self, chunks_data: List[Tuple[str, int, str]]) -> None:
        """Generate TF-IDF embeddings directly for a batch of chunks"""
        try:
            log.log_info(f"Generating direct TF-IDF embeddings for {len(chunks_data)} chunks")

            # Generate TF-IDF embeddings for each chunk
            for filename, chunk_id, chunk_text in chunks_data:
                embedding = self._generate_tfidf_embedding(chunk_text)
                cache_key = f"{filename}_{chunk_id}"

                self._embeddings_cache[cache_key] = EmbeddingData(
                    embedding=embedding,
                    provider_name="tfidf_direct",
                    model_name="tfidf",
                    chunk_id=chunk_id,
                    created_at=datetime.now().isoformat()
                )

            log.log_info(f"Generated and cached {len(chunks_data)} TF-IDF embeddings. Total cache size: {len(self._embeddings_cache)}")

        except Exception as e:
            log.log_error(f"Error generating TF-IDF embeddings: {e}")

    def search(self, request: SearchRequest) -> List[SearchResult]:
        """Perform search based on request type"""
        if request.search_type == SearchType.TEXT:
            return self.search_text(request.query, request.max_results)
        elif request.search_type == SearchType.VECTOR:
            # Need to generate query embedding first
            return self._search_vector_with_query(request.query, request.max_results, request.similarity_threshold)
        else:  # HYBRID
            return self.search_hybrid(request.query, request.max_results)

    def search_text(self, query_str: str, max_results: int = 10) -> List[SearchResult]:
        """Perform BM25 text search using Whoosh"""
        with self._operation_lock:
            with self._index.searcher(weighting=BM25F()) as searcher:
                # Parse query
                parser = QueryParser("content", self._index.schema)
                try:
                    query = parser.parse(query_str)
                except:
                    # Fallback for complex queries
                    query = parser.parse(f'"{query_str}"')

                # Search
                results = searcher.search(query, limit=max_results * 2)  # Get more for deduplication

                # Process results and normalize scores to percentage (0-100)
                search_results = []

                # Find max score for normalization
                max_score = max([hit.score for hit in results]) if results else 1.0

                for hit in results[:max_results]:
                    filename = hit['filename']
                    content = hit['content']
                    snippet = self._generate_snippet(content, query_str)

                    # Normalize score to 0-1 range and convert to percentage
                    normalized_score = (hit.score / max_score) if max_score > 0 else 0.0

                    search_results.append(SearchResult(
                        filename=filename,
                        snippet=snippet,
                        score=normalized_score,  # Now 0-1 range like vector search
                        chunk_id=hit['chunk_id'],
                        search_type=SearchType.TEXT,
                        metadata={'file_path': hit.get('file_path', '')}
                    ))

                return search_results

    def _search_vector_with_query(self, query_str: str, max_results: int = 5,
                                threshold: float = 0.2) -> List[SearchResult]:
        """Perform vector search by first generating query embedding"""
        try:
            # Use our own TF-IDF embedding generation for consistency
            query_embedding = self._generate_tfidf_embedding(query_str)
            log.log_info(f"Generated query embedding with {len(query_embedding)} dimensions")

            if not query_embedding or all(x == 0.0 for x in query_embedding):
                log.log_warn("Query embedding is empty or all zeros")
                return []

            return self.search_vector(query_embedding, max_results, threshold)

        except Exception as e:
            log.log_error(f"Error in vector search: {e}")
            return []

    def search_vector(self, query_embedding: List[float], max_results: int = 5,
                     threshold: float = 0.2) -> List[SearchResult]:
        """Perform vector similarity search"""
        results = []

        with self._operation_lock:
            log.log_info(f"Vector search: cache has {len(self._embeddings_cache)} embeddings, threshold={threshold}")

            # Calculate similarities
            similarities = []
            max_similarity = 0.0
            total_similarities = 0
            sum_similarities = 0.0

            for cache_key, embedding_data in self._embeddings_cache.items():
                similarity = self._cosine_similarity(query_embedding, embedding_data.embedding)
                max_similarity = max(max_similarity, similarity)
                sum_similarities += similarity
                total_similarities += 1

                if similarity > threshold:
                    filename, chunk_id_str = cache_key.rsplit('_', 1)
                    chunk_id = int(chunk_id_str)
                    similarities.append((filename, chunk_id, similarity))

            avg_similarity = sum_similarities / total_similarities if total_similarities > 0 else 0.0
            log.log_info(f"Similarity stats: max={max_similarity:.4f}, avg={avg_similarity:.4f}, above_threshold={len(similarities)}")

            # Sort by similarity and return top results (no filename deduplication)
            similarities.sort(key=lambda x: x[2], reverse=True)

            for filename, chunk_id, similarity in similarities[:max_results]:
                # Get content from index
                log.log_info(f"Looking for content: {filename}:{chunk_id} (similarity: {similarity:.4f})")
                snippet = self._get_content_from_index(filename, chunk_id)

                if not snippet:
                    # If content not found, try to get it from any chunk of this file
                    log.log_warn(f"Content not found for {filename}:{chunk_id}, trying to find any chunk from {filename}")
                    snippet = self._get_any_content_from_file(filename)

                results.append(SearchResult(
                    filename=filename,
                    snippet=snippet[:self.max_snippet_length] if snippet else f"Content not found for {filename}",
                    score=similarity,
                    chunk_id=chunk_id,
                    search_type=SearchType.VECTOR
                ))

        return results

    def search_hybrid(self, query_str: str, max_results: int = 10) -> List[SearchResult]:
        """Perform hybrid search combining text and vector search"""
        log.log_debug(f"RAG hybrid search for: {query_str[:50]}...")

        # Always do text search
        text_results = self.search_text(query_str, max_results)

        # Do vector search if provider is available
        vector_results = self._search_vector_with_query(query_str, max_results)

        # Combine results
        combined_results = self._combine_search_results(text_results, vector_results, max_results)

        log.log_debug(f"RAG hybrid search returned {len(combined_results)} results")
        return combined_results

    def _combine_search_results(self, text_results: List[SearchResult],
                               vector_results: List[SearchResult],
                               max_results: int) -> List[SearchResult]:
        """Combine and rank text and vector search results"""
        # Normalize scores to [0, 1] range
        if text_results:
            max_text_score = max(r.score for r in text_results)
            if max_text_score > 0:
                for result in text_results:
                    result.score = result.score / max_text_score

        # Vector scores are already normalized (cosine similarity)

        # Combine with weights (favor text search slightly for exact matches)
        text_weight = 0.6
        vector_weight = 0.4

        # Create combined results without filename deduplication
        combined_results = []

        # Add weighted text results
        for result in text_results:
            combined_results.append(SearchResult(
                filename=result.filename,
                snippet=result.snippet,
                score=result.score * text_weight,
                chunk_id=result.chunk_id,
                search_type=SearchType.HYBRID,
                metadata=result.metadata
            ))

        # Add weighted vector results
        for result in vector_results:
            combined_results.append(SearchResult(
                filename=result.filename,
                snippet=result.snippet,
                score=result.score * vector_weight,
                chunk_id=result.chunk_id,
                search_type=SearchType.HYBRID,
                metadata=result.metadata
            ))

        # Sort by combined score and limit results
        combined_results.sort(key=lambda x: x.score, reverse=True)
        return combined_results[:max_results]

    def _cosine_similarity(self, vec_a: List[float], vec_b: List[float]) -> float:
        """Calculate cosine similarity between two vectors"""
        if len(vec_a) != len(vec_b):
            log.log_error(f"Vector dimension mismatch: {len(vec_a)} vs {len(vec_b)}")
            return 0.0

        dot_product = sum(a * b for a, b in zip(vec_a, vec_b))
        norm_a = math.sqrt(sum(a * a for a in vec_a))
        norm_b = math.sqrt(sum(b * b for b in vec_b))

        if norm_a == 0 or norm_b == 0:
            log.log_debug(f"Zero norm detected: norm_a={norm_a}, norm_b={norm_b}")
            return 0.0

        similarity = dot_product / (norm_a * norm_b)
        return similarity

    def _get_content_from_index(self, filename: str, chunk_id: int) -> str:
        """Get content for a specific chunk from the index"""
        try:
            with self._index.searcher() as searcher:
                # Use content search to get all chunks and find the matching one
                from whoosh.qparser import QueryParser
                parser = QueryParser("content", searcher.schema)
                content_query = parser.parse("*")  # Match everything
                all_chunks = searcher.search(content_query, limit=500)

                # Find the specific chunk we want
                for chunk in all_chunks:
                    if chunk['filename'] == filename and chunk['chunk_id'] == chunk_id:
                        content = chunk['content']
                        log.log_debug(f"Found chunk {filename}:{chunk_id}, length: {len(content)}")
                        return content

                log.log_debug(f"No matching chunk found for {filename}:{chunk_id}")
        except Exception as e:
            log.log_error(f"Error getting content from index for {filename}:{chunk_id}: {e}")
        return ""

    def _get_any_content_from_file(self, filename: str) -> str:
        """Get content from any chunk of the specified file"""
        try:
            with self._index.searcher() as searcher:
                query = Term("filename", filename)
                results = searcher.search(query, limit=10)

                if results:
                    log.log_info(f"Found {len(results)} chunks for {filename}")
                    for i, result in enumerate(results[:5]):  # Show first 5
                        log.log_info(f"  Chunk {i}: ID={result['chunk_id']}, content_len={len(result['content'])}")

                    content = results[0]['content']
                    chunk_id = results[0]['chunk_id']
                    log.log_info(f"Using content from {filename}:{chunk_id}, length: {len(content)}")
                    return content
                else:
                    log.log_warn(f"No content found for any chunk of {filename}")
        except Exception as e:
            log.log_error(f"Error getting fallback content for {filename}: {e}")
        return ""

    def _generate_snippet(self, content: str, query: str) -> str:
        """Generate a snippet around the query terms"""
        query_terms = query.lower().split()
        content_lower = content.lower()

        # Find the best position (first occurrence of any query term)
        best_pos = len(content)
        for term in query_terms:
            pos = content_lower.find(term)
            if pos != -1 and pos < best_pos:
                best_pos = pos

        # If no terms found, start from beginning
        if best_pos == len(content):
            best_pos = 0

        # Calculate snippet boundaries
        start = max(0, best_pos - self.max_snippet_length // 2)
        end = min(len(content), start + self.max_snippet_length)

        snippet = content[start:end]

        # Add ellipsis if truncated
        if start > 0:
            snippet = "..." + snippet
        if end < len(content):
            snippet = snippet + "..."

        return snippet

    def list_documents(self) -> List[DocumentMetadata]:
        """List all indexed documents with metadata"""
        with self._operation_lock:
            return list(self._metadata.values())

    def delete_document(self, filename: str) -> bool:
        """Delete a document from the index"""
        log.log_info(f"Deleting document: {filename}")

        with self._operation_lock:
            try:
                # Remove from Whoosh index
                writer = self._index.writer()
                try:
                    writer.delete_by_term("filename", filename)
                    writer.commit()
                except Exception as e:
                    writer.cancel()
                    raise e

                # Remove embeddings
                keys_to_remove = [k for k in self._embeddings_cache.keys() if k.startswith(f"{filename}_")]
                for key in keys_to_remove:
                    del self._embeddings_cache[key]

                # Remove metadata
                if filename in self._metadata:
                    del self._metadata[filename]

                # Save changes
                self._save_embeddings_cache()
                self._save_metadata()

                log.log_info(f"Successfully deleted document: {filename}")
                return True

            except Exception as e:
                log.log_error(f"Error deleting document {filename}: {e}")
                return False

    def delete_documents(self, filenames: List[str]) -> Dict[str, bool]:
        """Delete multiple documents from the index"""
        results = {}
        for filename in filenames:
            results[filename] = self.delete_document(filename)
        return results

    def get_stats(self) -> RAGStats:
        """Get statistics about the RAG service"""
        with self._operation_lock:
            try:
                with self._index.searcher() as searcher:
                    doc_count = searcher.doc_count()

                # Calculate index size
                index_size_mb = 0.0
                try:
                    for file_path in self.index_path.rglob('*'):
                        if file_path.is_file():
                            index_size_mb += file_path.stat().st_size
                    index_size_mb = index_size_mb / (1024 * 1024)  # Convert to MB
                except:
                    pass

                return RAGStats(
                    indexed_documents=len(self._metadata),
                    total_chunks=doc_count,
                    cached_embeddings=len(self._embeddings_cache),
                    index_path=str(self.index_path),
                    index_size_mb=index_size_mb
                )
            except Exception as e:
                log.log_error(f"Error getting RAG stats: {e}")
                return RAGStats(
                    indexed_documents=0,
                    total_chunks=0,
                    cached_embeddings=0,
                    index_path=str(self.index_path),
                    index_size_mb=0.0
                )

    def clear_index(self) -> bool:
        """Clear all documents from the index"""
        log.log_info("Clearing RAG index")

        with self._operation_lock:
            try:
                # Close current index
                self._index.close()

                # Recreate empty index
                self._index = index.create_in(str(self.index_path), self._schema)

                # Clear caches and corpus
                self._embeddings_cache.clear()
                self._metadata.clear()
                self._tfidf_vocabulary.clear()
                self._tfidf_document_corpus.clear()

                # Save empty caches
                self._save_embeddings_cache()
                self._save_metadata()
                self._save_vocabulary()

                log.log_info("Successfully cleared RAG index")
                return True

            except Exception as e:
                log.log_error(f"Error clearing RAG index: {e}")
                return False

    def close(self) -> None:
        """Close the RAG service and save state"""
        with self._operation_lock:
            try:
                self._save_embeddings_cache()
                self._save_metadata()
                self._index.close()
                log.log_info("RAG service closed successfully")
            except Exception as e:
                log.log_error(f"Error closing RAG service: {e}")


# Global instance for easy access throughout the application
rag_service = RAGService()
