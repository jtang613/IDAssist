#!/usr/bin/env python3

"""
Reasoning Effort Configuration Models

Provider-agnostic configuration for LLM extended thinking/reasoning effort.
Based on GhidrAssist's ReasoningConfig implementation.
"""

from enum import Enum
from typing import Optional
from dataclasses import dataclass


class EffortLevel(Enum):
    """
    Reasoning effort levels.

    NONE: No extended thinking (default)
    LOW: Minimal reasoning (~2K tokens)
    MEDIUM: Balanced reasoning (~10K tokens)
    HIGH: Maximum reasoning depth (~25K tokens)
    """
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class ReasoningConfig:
    """
    Provider-agnostic reasoning configuration.

    Handles conversion to provider-specific formats:
    - Anthropic: thinking.budget_tokens
    - OpenAI: reasoning_effort string
    - Ollama: think parameter (experimental)
    """

    # Anthropic token budgets for each effort level
    ANTHROPIC_BUDGETS = {
        EffortLevel.NONE: 0,
        EffortLevel.LOW: 2000,
        EffortLevel.MEDIUM: 10000,
        EffortLevel.HIGH: 25000
    }

    effort_level: EffortLevel = EffortLevel.NONE
    max_tokens: int = 4096  # Used for budget constraint validation

    def is_enabled(self) -> bool:
        """Check if reasoning is enabled (not NONE)"""
        return self.effort_level != EffortLevel.NONE

    def get_effort_string(self) -> Optional[str]:
        """
        Get lowercase effort string for API parameters.

        Returns:
            "low", "medium", "high", or None if disabled
        """
        if not self.is_enabled():
            return None
        return self.effort_level.value

    def get_anthropic_budget(self) -> Optional[int]:
        """
        Get token budget for Anthropic extended thinking.

        CRITICAL CONSTRAINT: budget_tokens MUST be < max_tokens

        Applies safety margin of 1000 tokens to ensure output tokens available.
        Minimum budget is 1024 tokens for meaningful reasoning.

        Returns:
            Token budget, or None if reasoning disabled
        """
        if not self.is_enabled():
            return None

        # Get base budget for effort level
        base_budget = self.ANTHROPIC_BUDGETS.get(self.effort_level, 0)
        if base_budget == 0:
            return None

        # Calculate maximum safe budget (reserve 1000 tokens for completion)
        max_safe_budget = max(1024, self.max_tokens - 1000)

        # Return minimum of requested budget and safe maximum
        return min(base_budget, max_safe_budget)

    def get_openai_reasoning_effort(self) -> Optional[str]:
        """
        Get reasoning effort parameter for OpenAI o1/o3 models.

        Returns:
            "low", "medium", or "high" string, or None if disabled
        """
        return self.get_effort_string()

    def get_ollama_think_value(self) -> Optional[str]:
        """
        Get think parameter for Ollama models (experimental).

        Note: Support varies by model. May be ignored if unsupported.

        Returns:
            Effort string or None
        """
        return self.get_effort_string()

    def get_lmstudio_reasoning_params(self) -> Optional[dict]:
        """
        Get reasoning parameters for LMStudio provider.

        Returns:
            Dictionary with effort field, or None if disabled
        """
        effort = self.get_effort_string()
        if effort is None:
            return None
        return {"effort": effort}

    @staticmethod
    def from_string(effort_str: str, max_tokens: int = 4096) -> 'ReasoningConfig':
        """
        Create ReasoningConfig from string value (e.g., from database or UI).

        Args:
            effort_str: "none", "low", "medium", "high" (case-insensitive)
            max_tokens: Maximum token limit for budget validation

        Returns:
            ReasoningConfig instance, defaults to NONE if invalid value
        """
        if not effort_str:
            return ReasoningConfig(EffortLevel.NONE, max_tokens)

        try:
            effort_level = EffortLevel(effort_str.lower().strip())
        except (ValueError, AttributeError):
            # Invalid value - fall back to NONE (safe default)
            effort_level = EffortLevel.NONE

        return ReasoningConfig(effort_level, max_tokens)

    @staticmethod
    def parse_effort(value: str) -> EffortLevel:
        """
        Parse effort level from string.

        Args:
            value: String representation of effort level

        Returns:
            EffortLevel enum, defaults to NONE if invalid
        """
        if not value:
            return EffortLevel.NONE

        try:
            return EffortLevel(value.lower().strip())
        except (ValueError, AttributeError):
            return EffortLevel.NONE

    def __repr__(self) -> str:
        if not self.is_enabled():
            return "ReasoningConfig(NONE)"

        budget = self.get_anthropic_budget()
        return f"ReasoningConfig({self.effort_level.value.upper()}, budget={budget})"
