#!/usr/bin/env python3
"""
Chat Edit Manager for IDAssist Query Tab

Provides robust edit/save functionality using chunk-based diff system.
Handles message-to-markdown mapping, change detection, and selective database updates.
"""

import re
import hashlib
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum

from src.ida_compat import log


class ChangeType(Enum):
    """Types of changes detected during editing"""
    MODIFIED = "modified"
    DELETED = "deleted"
    ADDED = "added"
    MOVED = "moved"


@dataclass
class ChatMessage:
    """Represents a single chat message with metadata"""
    db_id: Optional[int]        # Database row ID (None for new messages)
    role: str                   # user/assistant/tool_call/tool_response/error
    content: str                # Message content
    timestamp: str              # Original timestamp
    order: int                  # Message order in conversation

    def __post_init__(self):
        """Generate unique chunk identifier"""
        # Create stable chunk ID that survives edits
        content_hash = hashlib.md5(self.content.encode()).hexdigest()[:8]
        self.chunk_id = f"msg_{self.db_id or 'new'}_{self.role}_{self.order}_{content_hash}"

    def get_role_header(self) -> str:
        """Get appropriate markdown header for role"""
        if self.role == "user":
            return f"## User ({self.timestamp})"
        elif self.role == "assistant":
            return f"## IDAssist ({self.timestamp})"
        elif self.role == "tool_call":
            return f"### 🔧 Tool Call ({self.timestamp})"
        elif self.role == "tool_response":
            return f"### 📊 Tool Response ({self.timestamp})"
        elif self.role == "error":
            return f"## Error ({self.timestamp})"
        else:
            return f"## {self.role.title()} ({self.timestamp})"

    def to_markdown_chunk(self) -> str:
        """Convert to markdown with embedded chunk tracking"""
        header = self.get_role_header()
        # Include hidden HTML comment with chunk metadata for tracking
        chunk_marker = f"<!-- CHUNK:{self.chunk_id} -->"
        return f"{chunk_marker}\n{header}\n{self.content}\n\n"


@dataclass
class ChatChange:
    """Represents a detected change in chat content"""
    change_type: ChangeType
    chunk_id: Optional[str] = None
    old_content: Optional[str] = None
    new_content: Optional[str] = None
    db_id: Optional[int] = None
    new_order: Optional[int] = None
    role: Optional[str] = None
    timestamp: Optional[str] = None


class ChatEditManager:
    """
    Manages robust editing of chat conversations with chunk-based tracking.

    Provides:
    - Message-to-markdown mapping with unique identifiers
    - Change detection using diff algorithms
    - Selective database updates
    - Error recovery and validation
    """

    def __init__(self):
        self.message_map: Dict[str, ChatMessage] = {}          # chunk_id -> ChatMessage
        self.original_chunks: Dict[str, str] = {}              # chunk_id -> original_markdown
        self.chat_title: str = ""
        self.conversation_pair_count: int = 0

    def generate_editable_content(self, chat: Dict[str, Any]) -> str:
        """
        Generate markdown content with embedded chunk tracking.

        Args:
            chat: Chat dictionary with 'name' and 'messages' keys

        Returns:
            Markdown content with hidden chunk identifiers
        """
        try:
            self.message_map.clear()
            self.original_chunks.clear()
            self.chat_title = chat.get("name", "Untitled Chat")

            messages = chat.get("messages", [])
            if not messages:
                return f"# {self.chat_title}\n\n*No messages yet. Enter your query below.*\n"

            content = f"# {self.chat_title}\n\n"
            self.conversation_pair_count = 0

            for i, message_data in enumerate(messages):
                # Create ChatMessage object
                chat_msg = ChatMessage(
                    db_id=message_data.get("db_id"),  # May be None for unsaved messages
                    role=message_data["role"],
                    content=message_data["content"],
                    timestamp=message_data["timestamp"],
                    order=i
                )

                # Add horizontal rule before conversation pairs (except first)
                if chat_msg.role == "user" and self.conversation_pair_count > 0:
                    content += "---\n\n"

                # Generate markdown chunk
                chunk_markdown = chat_msg.to_markdown_chunk()

                # Store mappings
                self.message_map[chat_msg.chunk_id] = chat_msg
                self.original_chunks[chat_msg.chunk_id] = chunk_markdown

                # Add to content
                content += chunk_markdown

                # Track conversation pairs
                if chat_msg.role == "user":
                    self.conversation_pair_count += 1

            log.log_info(f"Generated editable content with {len(self.message_map)} tracked chunks")
            return content

        except Exception as e:
            log.log_error(f"Error generating editable content: {e}")
            return f"# {self.chat_title}\n\n**Error**: Failed to load chat content for editing.\n"

    def parse_edited_content(self, edited_content: str) -> List[ChatChange]:
        """
        Parse edited content and detect changes using chunk tracking.

        Args:
            edited_content: The edited markdown content from user

        Returns:
            List of detected changes
        """
        try:
            changes = []

            # Check for title changes
            edited_title = self._extract_title_from_content(edited_content)
            if edited_title and edited_title != self.chat_title:
                # Title was changed - we'll need to update the chat name
                changes.append(ChatChange(
                    change_type=ChangeType.MODIFIED,
                    chunk_id="title",
                    old_content=self.chat_title,
                    new_content=edited_title,
                    role="title"
                ))
                log.log_info(f"Detected title change: '{self.chat_title}' -> '{edited_title}'")

            # Extract chunk markers and content from edited text
            edited_chunks = self._extract_chunks_from_content(edited_content)

            # Find all chunk IDs that were originally present
            original_chunk_ids = set(self.original_chunks.keys())
            edited_chunk_ids = set(edited_chunks.keys())

            # Detect deleted chunks
            deleted_chunks = original_chunk_ids - edited_chunk_ids
            for chunk_id in deleted_chunks:
                original_msg = self.message_map[chunk_id]
                changes.append(ChatChange(
                    change_type=ChangeType.DELETED,
                    chunk_id=chunk_id,
                    db_id=original_msg.db_id,
                    old_content=original_msg.content
                ))
                log.log_info(f"Detected deletion of chunk {chunk_id}")

            # Detect modified chunks
            for chunk_id in edited_chunk_ids:
                if chunk_id in original_chunk_ids:
                    original_content = self.message_map[chunk_id].content
                    edited_content_chunk = edited_chunks[chunk_id]

                    if original_content != edited_content_chunk:
                        original_msg = self.message_map[chunk_id]
                        changes.append(ChatChange(
                            change_type=ChangeType.MODIFIED,
                            chunk_id=chunk_id,
                            db_id=original_msg.db_id,
                            old_content=original_content,
                            new_content=edited_content_chunk,
                            role=original_msg.role,
                            timestamp=original_msg.timestamp
                        ))
                        log.log_info(f"Detected modification of chunk {chunk_id}")

            # Detect new content (content without chunk markers)
            new_content_blocks = self._extract_new_content(edited_content)
            for i, (role, content, timestamp) in enumerate(new_content_blocks):
                changes.append(ChatChange(
                    change_type=ChangeType.ADDED,
                    new_content=content,
                    role=role,
                    timestamp=timestamp or "edited",
                    new_order=len(self.message_map) + i
                ))
                log.log_info(f"Detected new content block: {role}")

            log.log_info(f"Detected {len(changes)} total changes")
            return changes

        except Exception as e:
            log.log_error(f"Error parsing edited content: {e}")
            return []

    def _extract_chunks_from_content(self, content: str) -> Dict[str, str]:
        """Extract chunk markers and their associated content"""
        chunks = {}

        # Find all chunk markers and capture content until next marker or end
        chunk_pattern = r'<!-- CHUNK:([^>]+) -->\s*\n(.*?)(?=<!-- CHUNK:|$)'
        matches = re.findall(chunk_pattern, content, re.DOTALL)

        for chunk_id, chunk_content in matches:
            # Extract just the message content (skip the header line)
            lines = chunk_content.strip().split('\n')
            if len(lines) > 1:
                # Skip the first line (header) and rejoin the rest
                content_lines = lines[1:]

                # Remove trailing structural elements (horizontal rules, etc.)
                while content_lines and content_lines[-1].strip() in ['---', '===', '']:
                    content_lines.pop()

                message_content = '\n'.join(content_lines).strip()
                chunks[chunk_id] = message_content

        return chunks

    def _extract_new_content(self, content: str) -> List[Tuple[str, str, Optional[str]]]:
        """Extract content that doesn't have chunk markers (new content)"""
        new_blocks = []

        # Split content into sections based on headers, keeping track of what's chunked vs new
        header_pattern = r'^(##?\s+(?:User|IDAssist|Error)(?:\s*\([^)]*\))?|###\s+🔧\s+Tool Call(?:\s*\([^)]*\))?|###\s+📊\s+Tool Response(?:\s*\([^)]*\))?)$'

        # Find all sections with headers
        sections = re.split(f'({header_pattern})', content, flags=re.MULTILINE)

        # Get set of chunk IDs that are present in the edited content
        edited_chunk_ids = set(self._extract_chunks_from_content(content).keys())

        i = 0
        while i < len(sections):
            section = sections[i]

            # Look for header patterns
            header_match = re.match(header_pattern, section, re.MULTILINE)
            if header_match and i + 1 < len(sections):
                header = section.strip()
                message_content = sections[i + 1].strip()

                # Check if this section is preceded by a chunk marker
                chunk_marker_pattern = r'<!-- CHUNK:([^>]+) -->\s*$'
                preceding_text = sections[i - 1] if i > 0 else ""
                chunk_match = re.search(chunk_marker_pattern, preceding_text)

                is_tracked_content = chunk_match is not None

                # Only add as new content if:
                # 1. It's not tracked content (no chunk marker before it)
                # 2. It has substantial content
                # 3. It's not just separators
                if (not is_tracked_content and
                    message_content and
                    len(message_content) > 5 and
                    not re.match(r'^[-=\s]*$', message_content)):

                    # Extract role and timestamp from header
                    role, timestamp = self._parse_header(header)
                    if role:
                        new_blocks.append((role, message_content, timestamp))

                i += 2  # Skip header and content
            else:
                i += 1

        return new_blocks

    def _extract_title_from_content(self, content: str) -> Optional[str]:
        """Extract the title (first H1 header) from markdown content"""
        try:
            lines = content.split('\n')
            for line in lines:
                line = line.strip()
                if line.startswith('# ') and not line.startswith('## '):
                    # Extract title text after the "# "
                    title = line[2:].strip()
                    return title if title else None
            return None
        except Exception:
            return None

    def _parse_header(self, header: str) -> Tuple[Optional[str], Optional[str]]:
        """Parse role and timestamp from a message header"""
        header = header.strip()

        # Extract timestamp if present
        timestamp_match = re.search(r'\(([^)]+)\)', header)
        timestamp = timestamp_match.group(1) if timestamp_match else None

        # Determine role
        if "User" in header:
            return "user", timestamp
        elif "IDAssist" in header:
            return "assistant", timestamp
        elif "Tool Call" in header:
            return "tool_call", timestamp
        elif "Tool Response" in header:
            return "tool_response", timestamp
        elif "Error" in header:
            return "error", timestamp
        else:
            return None, timestamp
