#!/usr/bin/env python3
"""
Context Window Management Models for IDAssist

This module provides data models for managing LLM context windows,
including configuration and status tracking.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class ContextWindowConfig:
    """Configuration for context window management"""

    # Maximum tokens for the model's context window
    context_limit_tokens: int = 150000  # Conservative default for Anthropic

    # Threshold percentage at which to trigger compression
    threshold_percent: float = 0.75  # Compress at 75% usage

    # Minimum recent messages to always preserve (excluding system)
    min_recent_messages: int = 4

    # Minimum recent tool call/result pairs to preserve
    min_recent_tool_pairs: int = 2

    # Maximum tokens for individual tool results (truncate if exceeded)
    max_tool_result_tokens: int = 10000

    # Target size for generated summaries
    summary_target_tokens: int = 2000

    # Whether to use LLM for summarization (vs extractive)
    use_llm_summary: bool = True

    @property
    def trigger_threshold(self) -> int:
        """Token count that triggers compression"""
        return int(self.context_limit_tokens * self.threshold_percent)


@dataclass
class ContextStatus:
    """Current status of context window usage"""

    # Current token count
    total_tokens: int

    # Configured limit
    limit_tokens: int

    # Percentage of context used (0.0 - 1.0)
    percent_used: float

    # Whether compression is needed
    needs_compression: bool

    # Number of messages in history
    message_count: int

    # Number of tool call/result pairs
    tool_pair_count: int

    # Optional: tokens saved by last compression
    tokens_saved: Optional[int] = None

    def __str__(self) -> str:
        return (
            f"ContextStatus(tokens={self.total_tokens:,}/{self.limit_tokens:,} "
            f"({self.percent_used:.1%}), messages={self.message_count}, "
            f"tool_pairs={self.tool_pair_count}, needs_compression={self.needs_compression})"
        )
