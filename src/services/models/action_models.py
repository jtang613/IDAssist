#!/usr/bin/env python3

"""
Action Models - Simple data structures for Actions tab
"""

from dataclasses import dataclass
from typing import List, Dict, Any, Optional
from enum import Enum


class ActionType(Enum):
    """Available action types"""
    RENAME_FUNCTION = "rename_function"
    RENAME_VARIABLE = "rename_variable"
    RETYPE_VARIABLE = "retype_variable"
    AUTO_CREATE_STRUCT = "auto_create_struct"


@dataclass
class ActionProposal:
    """A proposed action"""
    action_type: ActionType
    target: str  # Function/variable name being acted upon
    current_value: str  # Current name/type
    proposed_value: str  # Proposed new name/type
    confidence: float  # 0.0 to 1.0
    rationale: str  # Why this change is suggested


@dataclass
class ActionResult:
    """Result of applying an action"""
    success: bool
    message: str
    action_type: ActionType
    target: str
    old_value: Optional[str] = None
    new_value: Optional[str] = None
    error: Optional[str] = None
