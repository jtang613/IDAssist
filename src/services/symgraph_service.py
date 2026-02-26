#!/usr/bin/env python3
"""
SymGraph API Client Service for IDAssist.

This service provides a clean interface for SymGraph API integration,
following the IDAssist SOA architecture patterns.
"""

import asyncio
import re
import threading
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

from .settings_service import settings_service
from .models.symgraph_models import (
    BinaryStats, Symbol, GraphNode, GraphEdge,
    SymbolExport, GraphExport, QueryResult, PushResult,
    PullPreviewResult, ConflictEntry, ConflictAction
)

from src.ida_compat import log


# Unified default name patterns for cross-tool compatibility (Binary Ninja, Ghidra, IDA, radare2)
# Used to detect auto-generated symbol names that should be filtered during merge
DEFAULT_NAME_PATTERNS = [
    # Functions
    re.compile(r'^sub_[0-9a-fA-F]+$'),         # Binary Ninja, IDA
    re.compile(r'^FUN_[0-9a-fA-F]+$'),         # Ghidra
    re.compile(r'^fcn\.[0-9a-fA-F]+$'),        # radare2
    re.compile(r'^func_[0-9a-fA-F]+$'),        # Generic
    re.compile(r'^j_.*$'),                      # Thunks
    # Data
    re.compile(r'^(data|DAT|byte|BYTE|dword|DWORD|qword|QWORD)_[0-9a-fA-F]+$', re.IGNORECASE),
    # Variables (Ghidra decompiler patterns)
    re.compile(r'^(var|local|uVar|iVar|lVar|pVar|cVar|bVar|sVar|auVar|puVar)_?\d*$'),
    # Parameters
    re.compile(r'^(arg|param)_?\d+$'),
    re.compile(r'^a[1-9]$'),                    # IDA-style numbered args
]


def is_default_name(name: str) -> bool:
    """Check if a symbol name matches auto-generated patterns from any disassembler."""
    if not name:
        return True
    return any(p.match(name) for p in DEFAULT_NAME_PATTERNS)


class SymGraphServiceError(Exception):
    """Base exception for SymGraph service errors."""
    pass


class SymGraphAuthError(SymGraphServiceError):
    """Authentication error - API key missing or invalid."""
    pass


class SymGraphNetworkError(SymGraphServiceError):
    """Network error - unable to reach SymGraph API."""
    pass


class SymGraphAPIError(SymGraphServiceError):
    """API error - server returned an error response."""
    def __init__(self, message: str, status_code: int = None):
        super().__init__(message)
        self.status_code = status_code


class SymGraphService:
    """
    SymGraph API client service providing:
    - Binary existence checking (unauthenticated)
    - Binary stats retrieval (unauthenticated)
    - Symbol and graph data operations (authenticated)
    - Thread-safe operations
    """

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        """Singleton pattern implementation."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        """Initialize the SymGraph service."""
        if hasattr(self, '_initialized'):
            return

        self._initialized = True
        self._client_lock = threading.Lock()

        if not HTTPX_AVAILABLE:
            log.log_warn("httpx package not available - SymGraph integration disabled")

    @property
    def base_url(self) -> str:
        """Get the configured API base URL."""
        return settings_service.get_symgraph_api_url().rstrip('/')

    @property
    def api_key(self) -> Optional[str]:
        """Get the configured API key."""
        key = settings_service.get_symgraph_api_key()
        return key if key and key.strip() else None

    @property
    def has_api_key(self) -> bool:
        """Check if an API key is configured."""
        return settings_service.has_symgraph_api_key()

    def _get_headers(self, authenticated: bool = False) -> Dict[str, str]:
        """Get HTTP headers for requests."""
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'User-Agent': 'IDAssist-SymGraph/1.0'
        }
        if authenticated and self.api_key:
            headers['X-API-Key'] = self.api_key
        return headers

    def _check_httpx(self):
        """Check if httpx is available."""
        if not HTTPX_AVAILABLE:
            raise SymGraphServiceError("httpx package not installed. Install with: pip install httpx")

    def _check_auth(self):
        """Check if authentication is configured."""
        if not self.has_api_key:
            raise SymGraphAuthError("SymGraph API key not configured. Add your API key in Settings > SymGraph")

    def _is_private_network(self) -> bool:
        """Check if the API URL points to a private/internal network address."""
        try:
            parsed = urlparse(self.base_url)
            host = parsed.hostname or ''
            if host in ('localhost', '127.0.0.1', '::1'):
                return True
            # RFC 1918 private networks
            if re.match(r'^10\.', host):
                return True
            if re.match(r'^172\.(1[6-9]|2[0-9]|3[01])\.', host):
                return True
            if re.match(r'^192\.168\.', host):
                return True
        except Exception:
            pass
        return False

    def _client_kwargs(self, timeout: float = 30.0) -> dict:
        """Build common kwargs for httpx.AsyncClient."""
        kwargs = {'timeout': timeout}
        if self._is_private_network():
            kwargs['verify'] = False
        return kwargs

    # === Unauthenticated Operations ===

    async def check_binary_exists(self, sha256: str) -> bool:
        """
        Check if a binary exists in SymGraph (unauthenticated).

        Args:
            sha256: SHA256 hash of the binary

        Returns:
            True if binary exists, False otherwise
        """
        self._check_httpx()

        url = f"{self.base_url}/api/v1/binaries/{sha256}"
        log.log_debug(f"Checking binary existence: {url}")

        try:
            async with httpx.AsyncClient(**self._client_kwargs(30.0)) as client:
                response = await client.head(url, headers=self._get_headers())

                if response.status_code == 200:
                    return True
                elif response.status_code == 404:
                    return False
                else:
                    log.log_warn(f"Unexpected status checking binary: {response.status_code}")
                    return False

        except httpx.TimeoutException:
            raise SymGraphNetworkError(f"Timeout connecting to {self.base_url}")
        except httpx.RequestError as e:
            raise SymGraphNetworkError(f"Network error: {str(e)}")

    async def get_binary_stats(self, sha256: str) -> Optional[BinaryStats]:
        """
        Get binary statistics from SymGraph (unauthenticated).

        Args:
            sha256: SHA256 hash of the binary

        Returns:
            BinaryStats if binary exists, None otherwise
        """
        self._check_httpx()

        url = f"{self.base_url}/api/v1/binaries/{sha256}/stats"
        log.log_debug(f"Getting binary stats: {url}")

        try:
            async with httpx.AsyncClient(**self._client_kwargs(30.0)) as client:
                response = await client.get(url, headers=self._get_headers())

                if response.status_code == 200:
                    data = response.json()
                    return BinaryStats.from_dict(data)
                elif response.status_code == 404:
                    return None
                else:
                    log.log_warn(f"Error getting stats: {response.status_code}")
                    return None

        except httpx.TimeoutException:
            raise SymGraphNetworkError(f"Timeout connecting to {self.base_url}")
        except httpx.RequestError as e:
            raise SymGraphNetworkError(f"Network error: {str(e)}")

    async def query_binary(self, sha256: str) -> QueryResult:
        """
        Query SymGraph for binary info (unauthenticated).

        Args:
            sha256: SHA256 hash of the binary

        Returns:
            QueryResult with exists status and stats
        """
        try:
            exists = await self.check_binary_exists(sha256)
            if not exists:
                return QueryResult.not_found()

            stats = await self.get_binary_stats(sha256)
            if stats:
                return QueryResult.found(stats)
            else:
                return QueryResult(exists=True)  # Exists but no stats available

        except SymGraphServiceError as e:
            return QueryResult.error_result(str(e))

    # === Authenticated Operations ===

    async def get_symbols(self, sha256: str, symbol_type: Optional[str] = None) -> List[Symbol]:
        """
        Get symbols for a binary (authenticated).

        Args:
            sha256: SHA256 hash of the binary
            symbol_type: Optional filter by symbol type (e.g., "function", "data", "type")

        Returns:
            List of Symbol objects
        """
        self._check_httpx()
        self._check_auth()

        url = f"{self.base_url}/api/v1/binaries/{sha256}/symbols"
        if symbol_type:
            url += f"?type={symbol_type}"
        log.log_debug(f"Getting symbols: {url}")

        try:
            async with httpx.AsyncClient(**self._client_kwargs(60.0)) as client:
                response = await client.get(
                    url,
                    headers=self._get_headers(authenticated=True)
                )

                if response.status_code == 200:
                    data = response.json()
                    # Handle various response formats safely
                    if data is None:
                        return []
                    symbols_data = data.get('symbols', data) if isinstance(data, dict) else data
                    if symbols_data is None or not isinstance(symbols_data, list):
                        return []
                    return [Symbol.from_dict(s) for s in symbols_data]
                elif response.status_code == 401:
                    raise SymGraphAuthError("Invalid API key")
                elif response.status_code == 404:
                    return []
                else:
                    raise SymGraphAPIError(f"Error getting symbols: {response.status_code}", response.status_code)

        except httpx.TimeoutException:
            raise SymGraphNetworkError(f"Timeout connecting to {self.base_url}")
        except httpx.RequestError as e:
            raise SymGraphNetworkError(f"Network error: {str(e)}")

    async def push_symbols_bulk(self, sha256: str, symbols: List[Dict[str, Any]]) -> PushResult:
        """
        Push symbols to SymGraph in bulk (authenticated).

        Args:
            sha256: SHA256 hash of the binary
            symbols: List of symbol dictionaries

        Returns:
            PushResult indicating success/failure
        """
        self._check_httpx()
        self._check_auth()

        url = f"{self.base_url}/api/v1/binaries/{sha256}/symbols/bulk"
        log.log_debug(f"Pushing {len(symbols)} symbols to: {url}")

        try:
            async with httpx.AsyncClient(**self._client_kwargs(120.0)) as client:
                response = await client.post(
                    url,
                    headers=self._get_headers(authenticated=True),
                    json={'symbols': symbols}
                )

                if response.status_code in (200, 201):
                    data = response.json()
                    return PushResult.success_result(
                        symbols=data.get('symbols_created', len(symbols))
                    )
                elif response.status_code == 401:
                    raise SymGraphAuthError("Invalid API key")
                else:
                    error_msg = response.text or f"HTTP {response.status_code}"
                    raise SymGraphAPIError(f"Error pushing symbols: {error_msg}", response.status_code)

        except httpx.TimeoutException:
            raise SymGraphNetworkError(f"Timeout connecting to {self.base_url}")
        except httpx.RequestError as e:
            raise SymGraphNetworkError(f"Network error: {str(e)}")

    async def export_symbols(self, sha256: str) -> Optional[SymbolExport]:
        """
        Export all symbols for a binary (authenticated).

        Args:
            sha256: SHA256 hash of the binary

        Returns:
            SymbolExport object or None if not found
        """
        self._check_httpx()
        self._check_auth()

        url = f"{self.base_url}/api/v1/binaries/{sha256}/export"
        log.log_debug(f"Exporting symbols: {url}")

        try:
            async with httpx.AsyncClient(**self._client_kwargs(120.0)) as client:
                response = await client.get(
                    url,
                    headers=self._get_headers(authenticated=True)
                )

                if response.status_code == 200:
                    data = response.json()
                    return SymbolExport.from_dict(data)
                elif response.status_code == 401:
                    raise SymGraphAuthError("Invalid API key")
                elif response.status_code == 404:
                    return None
                else:
                    raise SymGraphAPIError(f"Error exporting symbols: {response.status_code}", response.status_code)

        except httpx.TimeoutException:
            raise SymGraphNetworkError(f"Timeout connecting to {self.base_url}")
        except httpx.RequestError as e:
            raise SymGraphNetworkError(f"Network error: {str(e)}")

    async def import_symbols(self, sha256: str, export_data: Dict[str, Any]) -> PushResult:
        """
        Import symbols to SymGraph (authenticated).

        Args:
            sha256: SHA256 hash of the binary
            export_data: Symbol export data dictionary

        Returns:
            PushResult indicating success/failure
        """
        self._check_httpx()
        self._check_auth()

        url = f"{self.base_url}/api/v1/binaries/{sha256}/import"
        log.log_debug(f"Importing symbols to: {url}")

        try:
            async with httpx.AsyncClient(**self._client_kwargs(120.0)) as client:
                response = await client.post(
                    url,
                    headers=self._get_headers(authenticated=True),
                    json=export_data
                )

                if response.status_code in (200, 201):
                    data = response.json()
                    return PushResult.success_result(
                        symbols=data.get('symbols_imported', 0)
                    )
                elif response.status_code == 401:
                    raise SymGraphAuthError("Invalid API key")
                else:
                    error_msg = response.text or f"HTTP {response.status_code}"
                    raise SymGraphAPIError(f"Error importing symbols: {error_msg}", response.status_code)

        except httpx.TimeoutException:
            raise SymGraphNetworkError(f"Timeout connecting to {self.base_url}")
        except httpx.RequestError as e:
            raise SymGraphNetworkError(f"Network error: {str(e)}")

    async def export_graph(self, sha256: str) -> Optional[GraphExport]:
        """
        Export graph data for a binary (authenticated).

        Args:
            sha256: SHA256 hash of the binary

        Returns:
            GraphExport object or None if not found
        """
        self._check_httpx()
        self._check_auth()

        url = f"{self.base_url}/api/v1/binaries/{sha256}/graph/export"
        log.log_debug(f"Exporting graph: {url}")

        try:
            async with httpx.AsyncClient(**self._client_kwargs(120.0)) as client:
                response = await client.get(
                    url,
                    headers=self._get_headers(authenticated=True)
                )

                if response.status_code == 200:
                    data = response.json()
                    return GraphExport.from_dict(data)
                elif response.status_code == 401:
                    raise SymGraphAuthError("Invalid API key")
                elif response.status_code == 404:
                    return None
                else:
                    raise SymGraphAPIError(f"Error exporting graph: {response.status_code}", response.status_code)

        except httpx.TimeoutException:
            raise SymGraphNetworkError(f"Timeout connecting to {self.base_url}")
        except httpx.RequestError as e:
            raise SymGraphNetworkError(f"Network error: {str(e)}")

    async def import_graph(self, sha256: str, export_data: Dict[str, Any]) -> PushResult:
        """
        Import graph data to SymGraph (authenticated).

        Args:
            sha256: SHA256 hash of the binary
            export_data: Graph export data dictionary

        Returns:
            PushResult indicating success/failure
        """
        self._check_httpx()
        self._check_auth()

        url = f"{self.base_url}/api/v1/binaries/{sha256}/graph/import"
        log.log_debug(f"Importing graph to: {url}")

        try:
            async with httpx.AsyncClient(**self._client_kwargs(120.0)) as client:
                response = await client.post(
                    url,
                    headers=self._get_headers(authenticated=True),
                    json=export_data
                )

                if response.status_code in (200, 201):
                    data = response.json()
                    return PushResult.success_result(
                        nodes=data.get('nodes_imported', 0),
                        edges=data.get('edges_imported', 0)
                    )
                elif response.status_code == 401:
                    raise SymGraphAuthError("Invalid API key")
                else:
                    error_msg = response.text or f"HTTP {response.status_code}"
                    raise SymGraphAPIError(f"Error importing graph: {error_msg}", response.status_code)

        except httpx.TimeoutException:
            raise SymGraphNetworkError(f"Timeout connecting to {self.base_url}")
        except httpx.RequestError as e:
            raise SymGraphNetworkError(f"Network error: {str(e)}")

    # === Fingerprint Operations ===

    async def add_fingerprint(self, sha256: str, fp_type: str, fp_value: str) -> bool:
        """
        Add a fingerprint to a binary (authenticated).

        Args:
            sha256: SHA256 hash of the binary
            fp_type: Fingerprint type (e.g., "pdb_guid", "build_id")
            fp_value: Fingerprint value

        Returns:
            True if successful, False otherwise
        """
        self._check_httpx()
        self._check_auth()

        url = f"{self.base_url}/api/v1/binaries/{sha256}/fingerprints"
        log.log_debug(f"Adding fingerprint {fp_type}={fp_value} to {sha256[:16]}...")

        try:
            async with httpx.AsyncClient(**self._client_kwargs(30.0)) as client:
                response = await client.post(
                    url,
                    headers=self._get_headers(authenticated=True),
                    json={'type': fp_type, 'value': fp_value}
                )

                if response.status_code in (200, 201):
                    log.log_info(f"Added fingerprint: {fp_type}={fp_value}")
                    return True
                elif response.status_code == 401:
                    raise SymGraphAuthError("Invalid API key")
                elif response.status_code == 409:
                    # Fingerprint already exists - not an error
                    log.log_debug(f"Fingerprint already exists: {fp_type}={fp_value}")
                    return True
                else:
                    log.log_warn(f"Failed to add fingerprint: {response.status_code}")
                    return False

        except httpx.TimeoutException:
            raise SymGraphNetworkError(f"Timeout connecting to {self.base_url}")
        except httpx.RequestError as e:
            raise SymGraphNetworkError(f"Network error: {str(e)}")

    # === Helper Methods for Pull Preview ===

    def build_conflict_entries(
        self,
        local_symbols: Dict[int, str],
        remote_symbols: List[Symbol],
        min_confidence: float = 0.0
    ) -> List[ConflictEntry]:
        """
        Build conflict entries by comparing local and remote symbols.

        Args:
            local_symbols: Dict mapping address to local name
            remote_symbols: List of remote Symbol objects
            min_confidence: Minimum confidence threshold (0.0-1.0) for remote symbols

        Returns:
            List of ConflictEntry objects for the conflict resolution table
        """
        conflicts = []
        skipped_default = 0
        skipped_confidence = 0
        skipped_duplicate = 0

        # Deduplicate by address: keep the best symbol per address.
        # Prefer named symbols (function/variable) over comments,
        # and higher confidence over lower.
        best_by_address: Dict[int, Symbol] = {}
        for remote_sym in remote_symbols:
            display_name = remote_sym.display_name
            is_comment = remote_sym.symbol_type == 'comment'

            # Skip symbols with no useful display name
            if not display_name:
                skipped_default += 1
                continue

            # Skip non-comment symbols with default/auto-generated names
            if not is_comment and is_default_name(remote_sym.name):
                skipped_default += 1
                continue

            # Skip remote symbols below minimum confidence threshold
            if remote_sym.confidence < min_confidence:
                skipped_confidence += 1
                continue

            addr = remote_sym.address
            existing = best_by_address.get(addr)
            if existing is None:
                best_by_address[addr] = remote_sym
            else:
                existing_is_comment = existing.symbol_type == 'comment'
                if existing_is_comment and not is_comment:
                    best_by_address[addr] = remote_sym
                    skipped_duplicate += 1
                elif not existing_is_comment and is_comment:
                    skipped_duplicate += 1
                elif remote_sym.confidence > existing.confidence:
                    best_by_address[addr] = remote_sym
                    skipped_duplicate += 1
                else:
                    skipped_duplicate += 1

        for addr, remote_sym in best_by_address.items():
            local_name = local_symbols.get(addr)
            local_is_default = is_default_name(local_name) if local_name else True

            if local_name is None or local_is_default:
                # Remote only OR local has default name - NEW (safe to apply)
                conflicts.append(ConflictEntry.create_new(addr, remote_sym))
            elif local_name == remote_sym.display_name:
                # Same value - SAME
                conflicts.append(ConflictEntry.create_same(addr, local_name, remote_sym))
            else:
                # Different values (both user-defined) - CONFLICT
                conflicts.append(ConflictEntry.create_conflict(addr, local_name, remote_sym))

        if skipped_default > 0 or skipped_confidence > 0 or skipped_duplicate > 0:
            log.log_info(f"Filtered out {skipped_default} default names, {skipped_confidence} low confidence, {skipped_duplicate} duplicates")

        return conflicts


# Singleton instance
symgraph_service = SymGraphService()
