#!/usr/bin/env python3

"""
Findings Cache for ReAct Agent

Accumulates discoveries with relevance scoring and formats
them for prompt injection and final synthesis.
"""

from typing import List, Optional
from datetime import datetime

from ..models.react_models import Finding

from src.ida_compat import log


class FindingsCache:
    """Accumulates investigation findings for ReAct agent"""

    # Keywords for relevance scoring
    HIGH_RELEVANCE_KEYWORDS = [
        "vulnerability", "vulnerabilities", "unsafe", "overflow", "exploit",
        "backdoor", "malware", "suspicious", "dangerous", "critical",
        "injection", "xss", "sqli", "rce", "arbitrary", "remote code",
        "buffer overflow", "use after free", "memory corruption",
        "authentication bypass", "privilege escalation"
    ]

    MEDIUM_RELEVANCE_KEYWORDS = [
        "function", "calls", "address", "reference", "xref",
        "import", "export", "string", "symbol", "variable",
        "parameter", "return", "struct", "pointer", "array"
    ]

    def __init__(self):
        self.findings: List[Finding] = []
        self.iteration_summaries: List[str] = []

    def add_finding(self, fact: str, evidence: str, tool_used: str = None,
                    relevance: int = 5, iteration: int = 0):
        """Add a new finding to the cache"""
        finding = Finding(
            fact=fact,
            evidence=evidence,
            tool_used=tool_used,
            relevance=min(10, max(1, relevance)),  # Clamp 1-10
            iteration=iteration,
            timestamp=datetime.now()
        )
        self.findings.append(finding)
        log.log_debug(f"FindingsCache: Added finding (relevance={relevance}): {fact[:50]}...")

    def add_iteration_summary(self, summary: str):
        """Store LLM's summary for each iteration"""
        self.iteration_summaries.append(summary)
        log.log_debug(f"FindingsCache: Added iteration summary #{len(self.iteration_summaries)}")

    def extract_from_tool_output(self, tool_name: str, output: str, iteration: int = 0):
        """
        Extract findings from tool output using heuristics.

        Assigns relevance score based on keyword presence.
        """
        if not output or not output.strip():
            return

        # Calculate relevance based on keywords
        output_lower = output.lower()
        relevance = 3  # Default low relevance

        # Check for high relevance content
        for keyword in self.HIGH_RELEVANCE_KEYWORDS:
            if keyword in output_lower:
                relevance = 9
                log.log_debug(f"FindingsCache: High relevance keyword found: {keyword}")
                break

        # Check for medium relevance if not already high
        if relevance < 9:
            for keyword in self.MEDIUM_RELEVANCE_KEYWORDS:
                if keyword in output_lower:
                    relevance = 6
                    break

        # Store more of the output for better context (increased from 200 to 1000)
        if len(output) > 1000:
            fact = f"Tool {tool_name} returned: {output[:1000]}..."
        else:
            fact = f"Tool {tool_name} returned: {output}"

        self.add_finding(
            fact=fact,
            evidence=output,  # Full output stored in evidence
            tool_used=tool_name,
            relevance=relevance,
            iteration=iteration
        )

    def format_for_prompt(self, max_findings: int = 50) -> str:
        """
        Format findings for prompt injection.

        Returns top findings sorted by relevance.
        Now includes more findings with less truncation for better context.
        """
        if not self.findings:
            return "*No findings yet*"

        # Sort by relevance and take top findings (increased from 10 to 50)
        sorted_findings = sorted(
            self.findings,
            key=lambda f: f.relevance,
            reverse=True
        )[:max_findings]

        lines = ["**Key Findings:**"]
        for i, finding in enumerate(sorted_findings, 1):
            # Increased truncation limit from 150 to 500 characters for better context
            fact = finding.fact[:500] + "..." if len(finding.fact) > 500 else finding.fact
            lines.append(f"{i}. {fact}")

        return "\n".join(lines)

    def format_detailed(self) -> str:
        """
        Format for final synthesis with iteration summaries.

        Includes all findings and iteration history with minimal truncation.
        """
        # Include many more findings for synthesis (increased from 15 to 100)
        output = self.format_for_prompt(max_findings=100)

        if self.iteration_summaries:
            output += "\n\n**Investigation History:**\n"
            for i, summary in enumerate(self.iteration_summaries, 1):
                # Increased summary limit from 500 to 2000 for better synthesis context
                summary_short = summary[:2000] + "..." if len(summary) > 2000 else summary
                output += f"\n*Iteration {i}:* {summary_short}\n"

        return output

    def get_findings_count(self) -> int:
        """Get total number of findings"""
        return len(self.findings)

    def get_high_relevance_findings(self, min_relevance: int = 7) -> List[Finding]:
        """Get findings above a relevance threshold"""
        return [f for f in self.findings if f.relevance >= min_relevance]

    def get_findings_by_tool(self, tool_name: str) -> List[Finding]:
        """Get findings from a specific tool"""
        return [f for f in self.findings if f.tool_used == tool_name]

    def clear(self):
        """Clear all findings and summaries"""
        self.findings.clear()
        self.iteration_summaries.clear()
        log.log_debug("FindingsCache: Cleared all findings and summaries")
