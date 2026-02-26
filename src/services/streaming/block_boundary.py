#!/usr/bin/env python3

import re


_ATX_HEADING = re.compile(r"^#{1,6}\s")
_THEMATIC_BREAK = re.compile(r"^(\*{3,}|-{3,}|_{3,})\s*$")
_FENCE_OPEN = re.compile(r"^(`{3,}|~{3,})")
_LIST_ITEM = re.compile(r"^(\s*([-*+]|\d+[.)]))\s")
_BLOCK_QUOTE = re.compile(r"^>\s?")
_TABLE_ROW = re.compile(r"^\|.*\|\s*$")


class BlockBoundaryDetector:

    @classmethod
    def find_last_stable_boundary(cls, pending_markdown: str) -> int:
        if not pending_markdown:
            return 0

        lines = pending_markdown.split("\n", -1)
        last_stable_boundary = 0
        current_offset = 0
        in_fence = False
        fence_marker: str | None = None

        for i, line in enumerate(lines):
            line_end = current_offset + len(line)
            has_newline = line_end < len(pending_markdown)

            if not has_newline and i == len(lines) - 1:
                # Last line without trailing newline - potentially incomplete
                break

            if in_fence:
                if cls._is_closing_fence(line, fence_marker):
                    in_fence = False
                    fence_marker = None
                    last_stable_boundary = line_end + 1
            else:
                fence_match = _FENCE_OPEN.match(line)
                if fence_match:
                    fence_marker = fence_match.group(1)
                    in_fence = True
                elif cls._is_block_boundary(line):
                    last_stable_boundary = line_end + 1

            current_offset = line_end + 1

        return min(last_stable_boundary, len(pending_markdown))

    @classmethod
    def _is_closing_fence(cls, line: str, fence_marker: str | None) -> bool:
        if fence_marker is None:
            return False
        trimmed = line.strip()
        if not trimmed:
            return False
        fence_char = fence_marker[0]
        if not all(c == fence_char for c in trimmed):
            return False
        return len(trimmed) >= len(fence_marker)

    @classmethod
    def _is_block_boundary(cls, line: str) -> bool:
        # Table rows are never boundaries
        if _TABLE_ROW.match(line):
            return False

        # Blank line
        if not line.strip():
            return True

        # ATX heading
        if _ATX_HEADING.match(line):
            return True

        # Thematic break
        if _THEMATIC_BREAK.match(line):
            return True

        # List item start
        if _LIST_ITEM.match(line):
            return True

        # Block quote
        if _BLOCK_QUOTE.match(line):
            return True

        return False
