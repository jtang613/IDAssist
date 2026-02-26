#!/usr/bin/env python3
"""Filter <reasoning>...</reasoning> blocks from streaming content."""

from typing import Callable, Optional
from enum import Enum, auto


class FilterState(Enum):
    NORMAL = auto()
    IN_REASONING = auto()


class ReasoningFilter:
    """
    Streaming filter that removes <reasoning>...</reasoning> blocks.
    Shows "Thinking..." placeholder during reasoning.
    """

    REASONING_OPEN = "<reasoning>"
    REASONING_CLOSE = "</reasoning>"

    def __init__(
        self,
        on_content: Callable[[str], None],
        on_thinking_start: Optional[Callable[[], None]] = None,
    ):
        self._on_content = on_content
        self._on_thinking_start = on_thinking_start
        self._state = FilterState.NORMAL
        self._buffer = ""
        self._thinking_emitted = False

    def feed(self, chunk: str) -> None:
        """Feed a chunk from the LLM stream."""
        self._buffer += chunk
        self._process_buffer()

    def complete(self) -> None:
        """Signal stream completion - flush remaining buffer."""
        if self._state == FilterState.NORMAL and self._buffer:
            self._on_content(self._buffer)
        self._buffer = ""

    def reset(self) -> None:
        """Reset for new stream."""
        self._buffer = ""
        self._state = FilterState.NORMAL
        self._thinking_emitted = False

    def _process_buffer(self) -> None:
        while self._buffer:
            if self._state == FilterState.NORMAL:
                idx = self._buffer.find("<")
                if idx == -1:
                    self._on_content(self._buffer)
                    self._buffer = ""
                elif idx > 0:
                    self._on_content(self._buffer[:idx])
                    self._buffer = self._buffer[idx:]
                else:
                    if self._buffer.startswith(self.REASONING_OPEN):
                        self._state = FilterState.IN_REASONING
                        self._buffer = self._buffer[len(self.REASONING_OPEN):]
                        if self._on_thinking_start and not self._thinking_emitted:
                            self._on_thinking_start()
                            self._thinking_emitted = True
                    elif len(self._buffer) < len(self.REASONING_OPEN):
                        break  # Wait for more
                    else:
                        self._on_content("<")
                        self._buffer = self._buffer[1:]

            elif self._state == FilterState.IN_REASONING:
                idx = self._buffer.find("</")
                if idx == -1:
                    self._buffer = ""  # Discard reasoning
                elif idx > 0:
                    self._buffer = self._buffer[idx:]
                else:
                    if self._buffer.startswith(self.REASONING_CLOSE):
                        self._state = FilterState.NORMAL
                        self._buffer = self._buffer[len(self.REASONING_CLOSE):]
                    elif len(self._buffer) < len(self.REASONING_CLOSE):
                        break
                    else:
                        self._buffer = self._buffer[2:]
