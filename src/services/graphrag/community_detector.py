#!/usr/bin/env python3

"""
Community Detector - Label Propagation algorithm for function clustering
Groups related functions based on call relationships
"""

import uuid
from collections import Counter, defaultdict
from typing import Callable, Dict, List, Optional, Set, Tuple

from .graph_store import GraphStore
from .models import GraphNode, EdgeType

from src.ida_compat import log


# Purpose inference patterns - keywords that suggest function purpose
PURPOSE_PATTERNS = {
    'network': ['socket', 'connect', 'send', 'recv', 'http', 'dns', 'net', 'tcp', 'udp',
                'inet', 'listen', 'accept', 'bind', 'gethost', 'gethostbyname', 'WSA'],
    'file_io': ['file', 'read', 'write', 'open', 'close', 'fopen', 'fwrite', 'fread',
                'fclose', 'fseek', 'ftell', 'fgets', 'fputs', 'CreateFile', 'ReadFile',
                'WriteFile', 'CloseHandle'],
    'crypto': ['crypt', 'aes', 'sha', 'md5', 'encrypt', 'decrypt', 'hash', 'rsa',
               'cipher', 'hmac', 'base64', 'encode', 'decode'],
    'memory': ['alloc', 'malloc', 'free', 'heap', 'realloc', 'calloc', 'mmap',
               'VirtualAlloc', 'VirtualFree', 'HeapAlloc', 'HeapFree'],
    'string': ['str', 'sprintf', 'strcpy', 'strcat', 'strlen', 'strcmp', 'string',
               'wcs', 'wstr', 'memcpy', 'memset', 'memmove'],
    'process': ['thread', 'process', 'exec', 'spawn', 'fork', 'CreateProcess',
                'CreateThread', 'TerminateProcess', 'ExitProcess', 'WaitFor'],
    'registry': ['reg', 'registry', 'hkey', 'RegOpen', 'RegQuery', 'RegSet',
                 'RegCreate', 'RegDelete'],
    'init': ['init', 'setup', 'start', 'main', 'entry', 'constructor', 'ctor',
             'initialize', 'DllMain', 'WinMain'],
    'error': ['error', 'exception', 'handler', 'catch', 'throw', 'abort', 'exit',
              'fail', 'panic'],
    'gui': ['window', 'dialog', 'button', 'menu', 'paint', 'draw', 'CreateWindow',
            'ShowWindow', 'MessageBox', 'SendMessage'],
}


class CommunityDetector:
    """
    Detects function communities using Label Propagation algorithm.

    The algorithm:
    1. Initialize each node with a unique label (its node ID)
    2. Iteratively update labels - each node adopts the most frequent label among neighbors
    3. Converge when no labels change (or max iterations reached)
    4. Merge small communities below threshold
    """

    def __init__(self, graph_store: GraphStore, binary_hash: str):
        self.graph_store = graph_store
        self.binary_hash = binary_hash
        self._cancelled = False

        # Build adjacency list from edges
        self._adjacency: Dict[str, Set[str]] = defaultdict(set)
        self._nodes: Dict[str, GraphNode] = {}

    def cancel(self):
        """Cancel the detection process."""
        self._cancelled = True

    def detect_communities(
        self,
        min_size: int = 2,
        max_iterations: int = 100,
        force: bool = False,
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> int:
        """
        Detect communities using Label Propagation.

        Args:
            min_size: Minimum community size. Smaller communities are merged.
            max_iterations: Maximum iterations before stopping.
            force: If True, re-detect even if communities exist.
            progress_callback: Optional callback(iteration, max_iterations)

        Returns:
            Number of communities detected
        """
        self._cancelled = False

        # Check if communities already exist
        if not force and self.graph_store.communities_exist(self.binary_hash):
            log.log_info("Communities already exist. Use force=True to re-detect.")
            return len(self.graph_store.get_communities(self.binary_hash))

        # Delete existing communities if re-detecting
        if force:
            deleted = self.graph_store.delete_communities(self.binary_hash)
            if deleted > 0:
                log.log_info(f"Deleted {deleted} existing communities for re-detection")

        # Build graph from edges
        self._build_graph()

        if not self._nodes:
            log.log_warn("No nodes found for community detection")
            return 0

        log.log_info(f"Starting community detection on {len(self._nodes)} nodes")

        # Initialize labels (each node starts with its own ID as label)
        labels = self._initialize_labels()

        # Run label propagation
        for iteration in range(max_iterations):
            if self._cancelled:
                log.log_info("Community detection cancelled")
                return 0

            labels, changed = self._propagate_labels(labels)

            if progress_callback:
                progress_callback(iteration + 1, max_iterations)

            if not changed:
                log.log_info(f"Label propagation converged after {iteration + 1} iterations")
                break
        else:
            log.log_info(f"Label propagation reached max iterations ({max_iterations})")

        if self._cancelled:
            return 0

        # Merge small communities
        labels = self._merge_small_communities(labels, min_size)

        # Store communities (only those meeting min_size)
        count = self._store_communities(labels, min_size)

        log.log_info(f"Detected {count} communities")
        return count

    def _build_graph(self):
        """Build adjacency list from edges."""
        # Get all nodes
        nodes = self.graph_store.get_nodes_by_type(self.binary_hash, "FUNCTION")
        self._nodes = {node.id: node for node in nodes}

        # Get CALLS and CALLS_VULNERABLE edges
        edges = self.graph_store.get_edges_by_types(
            self.binary_hash,
            [EdgeType.CALLS.value, EdgeType.CALLS_VULNERABLE.value]
        )

        # Build undirected adjacency list
        for edge in edges:
            if edge.source_id in self._nodes and edge.target_id in self._nodes:
                self._adjacency[edge.source_id].add(edge.target_id)
                self._adjacency[edge.target_id].add(edge.source_id)

        log.log_info(f"Built graph with {len(self._nodes)} nodes and {len(edges)} edges")

    def _initialize_labels(self) -> Dict[str, str]:
        """Initialize each node with its own ID as label."""
        return {node_id: node_id for node_id in self._nodes.keys()}

    def _propagate_labels(self, labels: Dict[str, str]) -> Tuple[Dict[str, str], bool]:
        """
        Propagate labels - each node adopts most frequent neighbor label.

        Returns:
            Tuple of (new_labels, changed) where changed is True if any label changed
        """
        new_labels = {}
        changed = False

        for node_id in self._nodes.keys():
            neighbors = self._adjacency.get(node_id, set())

            if not neighbors:
                # Isolated node keeps its label
                new_labels[node_id] = labels[node_id]
                continue

            # Count neighbor labels
            neighbor_labels = [labels[n] for n in neighbors if n in labels]

            if not neighbor_labels:
                new_labels[node_id] = labels[node_id]
                continue

            # Find most common label among neighbors
            label_counts = Counter(neighbor_labels)
            most_common = label_counts.most_common(1)[0][0]

            # Tie-breaker: if current label is tied for most common, keep it
            current_label = labels[node_id]
            if label_counts[current_label] == label_counts[most_common]:
                new_labels[node_id] = current_label
            else:
                new_labels[node_id] = most_common
                if most_common != current_label:
                    changed = True

        return new_labels, changed

    def _merge_small_communities(self, labels: Dict[str, str], min_size: int) -> Dict[str, str]:
        """Merge communities smaller than min_size into their largest neighbor community."""
        # Group nodes by label
        communities: Dict[str, List[str]] = defaultdict(list)
        for node_id, label in labels.items():
            communities[label].append(node_id)

        # Find small communities
        small_communities = {
            label: members
            for label, members in communities.items()
            if len(members) < min_size
        }

        if not small_communities:
            return labels

        log.log_info(f"Merging {len(small_communities)} small communities (< {min_size} members)")

        new_labels = dict(labels)

        for small_label, small_members in small_communities.items():
            # Find neighboring communities
            neighbor_communities: Counter = Counter()

            for node_id in small_members:
                for neighbor in self._adjacency.get(node_id, set()):
                    neighbor_label = labels.get(neighbor)
                    if neighbor_label and neighbor_label != small_label:
                        neighbor_communities[neighbor_label] += 1

            if neighbor_communities:
                # Merge into most connected neighbor community
                target_label = neighbor_communities.most_common(1)[0][0]
                for node_id in small_members:
                    new_labels[node_id] = target_label
            # If no neighbors, keep as separate (will be named as misc)

        return new_labels

    def _store_communities(self, labels: Dict[str, str], min_size: int) -> int:
        """Store detected communities in database, skipping those below min_size."""
        # Group nodes by final label
        communities: Dict[str, List[str]] = defaultdict(list)
        for node_id, label in labels.items():
            communities[label].append(node_id)

        count = 0
        skipped = 0
        for idx, (label, member_ids) in enumerate(communities.items()):
            if self._cancelled:
                return count

            # Skip communities that don't meet minimum size
            if len(member_ids) < min_size:
                skipped += 1
                continue

            # Get member nodes
            member_nodes = [self._nodes[nid] for nid in member_ids if nid in self._nodes]

            # Infer purpose from function names
            purpose = self._infer_community_purpose(member_nodes)
            name = self._generate_community_name(purpose, count + 1)
            summary = self._generate_community_summary(purpose, member_nodes)

            # Save community
            community_id = self.graph_store.save_community(self.binary_hash, {
                'id': str(uuid.uuid4()),
                'level': 0,
                'name': name,
                'summary': summary,
                'member_count': len(member_ids),
                'is_stale': False,
            })

            # Add members to community
            # Note: Community membership is tracked in the community_members table,
            # not as graph edges, since communities are not regular graph nodes
            for node_id in member_ids:
                self.graph_store.add_community_member(community_id, node_id, 1.0)

            count += 1

        if skipped > 0:
            log.log_info(f"Skipped {skipped} communities below minimum size ({min_size})")

        return count

    def _infer_community_purpose(self, member_nodes: List[GraphNode]) -> str:
        """Infer community purpose from function names."""
        # Collect all function names (lowercase)
        names = []
        for node in member_nodes:
            if node.name:
                names.append(node.name.lower())

        if not names:
            return 'misc'

        # Count pattern matches
        pattern_scores: Counter = Counter()

        for name in names:
            for purpose, keywords in PURPOSE_PATTERNS.items():
                for keyword in keywords:
                    if keyword.lower() in name:
                        pattern_scores[purpose] += 1
                        break  # Only count once per name per purpose

        if pattern_scores:
            return pattern_scores.most_common(1)[0][0]

        return 'misc'

    def _generate_community_name(self, purpose: str, index: int) -> str:
        """Generate a community name based on inferred purpose."""
        purpose_names = {
            'network': 'Network I/O Module',
            'file_io': 'File Operations Module',
            'crypto': 'Cryptography Module',
            'memory': 'Memory Management Module',
            'string': 'String Operations Module',
            'process': 'Process/Thread Module',
            'registry': 'Registry Operations Module',
            'init': 'Initialization Module',
            'error': 'Error Handling Module',
            'gui': 'GUI/Window Module',
            'misc': f'Function Group {index}',
        }

        base_name = purpose_names.get(purpose, f'Module {index}')

        # Add index if not misc to handle multiple modules of same type
        if purpose != 'misc':
            return f"{base_name} #{index}"

        return base_name

    def _generate_community_summary(self, purpose: str, member_nodes: List[GraphNode]) -> str:
        """Generate a summary description for the community."""
        member_count = len(member_nodes)

        purpose_descriptions = {
            'network': 'Functions related to network communication and socket operations',
            'file_io': 'Functions for file input/output and filesystem operations',
            'crypto': 'Functions implementing cryptographic algorithms and encoding',
            'memory': 'Functions for memory allocation and management',
            'string': 'Functions for string manipulation and memory operations',
            'process': 'Functions for process and thread management',
            'registry': 'Functions for Windows registry operations',
            'init': 'Functions for initialization and startup routines',
            'error': 'Functions for error handling and exception management',
            'gui': 'Functions for graphical user interface and window management',
            'misc': 'General utility functions',
        }

        description = purpose_descriptions.get(purpose, 'Grouped functions')

        # Add sample function names
        sample_names = []
        for node in member_nodes[:5]:
            if node.name:
                sample_names.append(node.name)

        if sample_names:
            samples = ', '.join(sample_names)
            if member_count > 5:
                samples += f', ... (+{member_count - 5} more)'
            return f"{description}. Contains {member_count} functions including: {samples}"

        return f"{description}. Contains {member_count} functions."
