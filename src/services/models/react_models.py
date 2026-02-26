#!/usr/bin/env python3

"""
ReAct Agent Data Models

Data structures for the ReAct autonomous agent including
todo list management, findings accumulation, and result tracking.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum
from datetime import datetime


class TodoStatus(Enum):
    """Status of investigation todo items"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETE = "complete"


class ReActStatus(Enum):
    """Status of ReAct agent execution"""
    SUCCESS = "success"              # Completed all todos or ready to answer
    MAX_ITERATIONS = "max_iterations"  # Hit iteration limit
    CANCELLED = "cancelled"          # User cancelled
    ERROR = "error"                  # Exception occurred


@dataclass
class Todo:
    """Individual investigation step"""
    task: str
    status: TodoStatus = TodoStatus.PENDING
    evidence: Optional[str] = None
    tools_used: List[str] = field(default_factory=list)

    def mark_in_progress(self):
        """Mark this todo as in progress"""
        self.status = TodoStatus.IN_PROGRESS

    def mark_complete(self, evidence: str = None):
        """Mark this todo as complete with optional evidence"""
        self.status = TodoStatus.COMPLETE
        if evidence:
            self.evidence = evidence


@dataclass
class Finding:
    """Individual discovery from investigation"""
    fact: str
    evidence: str
    tool_used: Optional[str] = None
    relevance: int = 5  # 1-10 score
    timestamp: datetime = field(default_factory=datetime.now)
    iteration: int = 0


@dataclass
class ReActResult:
    """Result from ReAct agent execution"""
    status: ReActStatus
    answer: str
    findings: List[Finding] = field(default_factory=list)
    iteration_count: int = 0
    tool_call_count: int = 0
    duration_seconds: float = 0.0
    iteration_summaries: List[str] = field(default_factory=list)

    @classmethod
    def cancelled(cls) -> 'ReActResult':
        """Create a cancelled result"""
        return cls(status=ReActStatus.CANCELLED, answer="Investigation cancelled by user")

    @classmethod
    def error(cls, error_msg: str) -> 'ReActResult':
        """Create an error result"""
        return cls(status=ReActStatus.ERROR, answer=f"Error: {error_msg}")


@dataclass
class ReActConfig:
    """Configuration for ReAct agent behavior"""
    max_iterations: int = 15
    tool_timeout: float = 30.0
    reflection_enabled: bool = True
    min_findings_for_ready: int = 5

    # Context window management settings
    context_window_tokens: int = 150000  # Conservative limit for Anthropic models
    context_threshold_percent: float = 0.75  # Trigger compression at 75%
    max_tool_result_tokens: int = 10000  # Truncate individual results exceeding this
    min_recent_tool_pairs: int = 2  # Preserve at least this many recent tool pairs

    # Network error retry settings
    max_retries: int = 3  # Number of retries for transient network errors
    retry_delay: float = 2.0  # Initial delay between retries (doubles each retry)
