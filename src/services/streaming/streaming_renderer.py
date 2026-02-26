#!/usr/bin/env python3

from typing import Callable

import markdown

from .block_boundary import BlockBoundaryDetector
from .render_update import RenderUpdate

_EXTENSIONS = ["codehilite", "fenced_code", "tables", "sane_lists"]
_EXTENSION_CONFIGS = {
    "codehilite": {"css_class": "highlight", "guess_lang": False},
}

# Shared CSS for markdown rendering - used by both streaming and final render
MARKDOWN_CSS = """
<style>
    table { border-collapse: collapse; margin: 10px 0; width: auto; }
    th, td { border: 1px solid rgba(128, 128, 128, 0.4); padding: 6px 10px; text-align: left; }
    th { background-color: rgba(128, 128, 128, 0.2); font-weight: bold; }
    tr:nth-child(even) { background-color: rgba(128, 128, 128, 0.1); }
    p { font-size: 12px; margin: 8px 0; }
    strong { font-size: inherit; }
    h1 { font-size: 18px; margin: 12px 0 8px 0; }
    h2 { font-size: 16px; margin: 10px 0 6px 0; }
    h3 { font-size: 14px; margin: 8px 0 4px 0; }
    h4, h5, h6 { font-size: 12px; margin: 6px 0 4px 0; }
</style>
"""


def preprocess_markdown_tables(text: str) -> str:
    """
    Ensure markdown tables have a blank line before them.

    The markdown 'tables' extension requires a blank line before the table
    for proper parsing. LLMs often output tables immediately after text.
    """
    lines = text.split('\n')
    result = []
    prev_was_blank = True

    for i, line in enumerate(lines):
        stripped = line.strip()
        is_table_line = stripped.startswith('|') and '|' in stripped[1:]

        if is_table_line and not prev_was_blank:
            if result and not (result[-1].strip().startswith('|') and '|' in result[-1].strip()[1:]):
                result.append('')

        result.append(line)
        prev_was_blank = (stripped == '')

    return '\n'.join(result)


def preprocess_markdown_hrs(text: str) -> str:
    """
    Ensure horizontal rules (---) have a blank line before them.

    In markdown, '---' directly below text turns that text into a heading.
    For '---' to render as a horizontal rule <hr>, it needs a blank line above.
    """
    lines = text.split('\n')
    result = []

    for i, line in enumerate(lines):
        stripped = line.strip()

        is_hr = stripped in ('---', '***', '___') or \
                (len(stripped) >= 3 and set(stripped) <= {'-', ' '} and stripped.count('-') >= 3) or \
                (len(stripped) >= 3 and set(stripped) <= {'*', ' '} and stripped.count('*') >= 3) or \
                (len(stripped) >= 3 and set(stripped) <= {'_', ' '} and stripped.count('_') >= 3)

        if is_hr and result and result[-1].strip() != '':
            result.append('')

        result.append(line)

    return '\n'.join(result)


def render_markdown_to_html(markdown_text: str, include_css: bool = True) -> str:
    """
    Render markdown text to HTML with preprocessing and extensions.

    This is the shared utility for static (non-streaming) markdown rendering,
    used by controllers for history rendering and full-replace operations.

    Args:
        markdown_text: The markdown text to render
        include_css: Whether to wrap output with MARKDOWN_CSS (default True)
    """
    try:
        preprocessed = preprocess_markdown_tables(markdown_text)
        preprocessed = preprocess_markdown_hrs(preprocessed)

        md = markdown.Markdown(
            extensions=_EXTENSIONS,
            extension_configs=_EXTENSION_CONFIGS
        )
        html = md.convert(preprocessed)

        if include_css:
            return f"{MARKDOWN_CSS}<div>{html}</div>"
        return html
    except Exception:
        return f"<pre>{markdown_text}</pre>"


class StreamingMarkdownRenderer:

    def __init__(self, update_callback: Callable[[RenderUpdate], None]):
        self._update_callback = update_callback
        self._committed_markdown: list[str] = []
        self._pending_markdown: str = ""
        self._md = markdown.Markdown(
            extensions=_EXTENSIONS, extension_configs=_EXTENSION_CONFIGS
        )

    def on_chunk(self, chunk: str) -> None:
        self._pending_markdown += chunk

        boundary = BlockBoundaryDetector.find_last_stable_boundary(self._pending_markdown)

        committed_html = ""
        if boundary > 0:
            stable_text = self._pending_markdown[:boundary]
            self._committed_markdown.append(stable_text)
            self._pending_markdown = self._pending_markdown[boundary:]

            self._md.reset()
            committed_html = self._md.convert(stable_text)

        pending_html = ""
        if self._pending_markdown:
            self._md.reset()
            pending_html = self._md.convert(self._pending_markdown)

        self._update_callback(RenderUpdate.incremental(committed_html, pending_html))

    def on_stream_complete(self) -> None:
        # Promote all remaining pending to committed
        if self._pending_markdown:
            self._committed_markdown.append(self._pending_markdown)
            self._pending_markdown = ""

        # Full re-parse of all committed markdown for cross-block consistency
        full_markdown = "".join(self._committed_markdown)
        full_html = render_markdown_to_html(full_markdown)

        self._update_callback(RenderUpdate.full_replace(full_html))

    def reset(self) -> None:
        self._committed_markdown = []
        self._pending_markdown = ""
        self._md.reset()

    def get_full_markdown(self) -> str:
        """Return accumulated markdown for copy/edit operations."""
        return "".join(self._committed_markdown) + self._pending_markdown
