#!/usr/bin/env python3

from dataclasses import dataclass
import re
from typing import List


@dataclass
class ComplexityMetrics:
    line_count: int
    branch_count: int
    call_count: int
    loop_count: int
    level: str
    summary_guidance: str

    def __str__(self) -> str:
        return (f"{self.line_count} lines, {self.branch_count} branches, "
                f"{self.call_count} calls, {self.loop_count} loops ({self.level})")


def analyze_complexity(code: str) -> ComplexityMetrics:
    if not code:
        return ComplexityMetrics(0, 0, 0, 0, "simple",
                                 "This is a simple function. Provide a concise summary (2-4 sentences).")

    lines = len(code.splitlines())
    branches = _count_occurrences(code, r"\bif\s*\(")
    branches += _count_occurrences(code, r"\bswitch\s*\(")
    branches += _count_occurrences(code, r"\bcase\s+")
    branches += _count_occurrences(code, r"\?.*:")  # ternary

    loops = _count_occurrences(code, r"\bwhile\s*\(")
    loops += _count_occurrences(code, r"\bfor\s*\(")
    loops += _count_occurrences(code, r"\bdo\s*\{")

    calls = _count_occurrences(code, r"\b[a-zA-Z_][a-zA-Z0-9_]*\s*\(")
    calls = max(0, calls - branches - loops)

    score = 0
    score += 2 if lines > 50 else (1 if lines > 20 else 0)
    score += 2 if branches > 10 else (1 if branches > 5 else 0)
    score += 2 if calls > 8 else (1 if calls > 4 else 0)
    score += 2 if loops > 3 else (1 if loops > 1 else 0)

    if score >= 6:
        level = "very_complex"
        guidance = ("This is a very complex function. Provide a detailed multi-paragraph summary "
                    "(3-5 paragraphs) covering all major code paths, data transformations, and behaviors.")
    elif score >= 4:
        level = "complex"
        guidance = ("This is a complex function. Provide a thorough summary (2-3 paragraphs) explaining "
                    "the main logic, key operations, and notable patterns.")
    elif score >= 2:
        level = "moderate"
        guidance = ("This is a moderately complex function. Provide a detailed summary (1-2 paragraphs) "
                    "explaining its purpose and key operations.")
    else:
        level = "simple"
        guidance = "This is a simple function. Provide a concise summary (2-4 sentences)."

    return ComplexityMetrics(lines, branches, calls, loops, level, guidance)


def function_summary_prompt(function_name: str, decompiled_code: str,
                            callers: List[str], callees: List[str]) -> str:
    """
    Generate a prompt for function summarization.

    .. deprecated::
        Use :class:`~services.function_summary_service.FunctionSummaryService` instead.
        This function provides a simplified prompt without RAG/MCP support.
        The FunctionSummaryService provides the unified prompt format used by both
        the Explain tab and Semantic Analysis, with full RAG and MCP support.

    Args:
        function_name: The name of the function
        decompiled_code: The decompiled code of the function
        callers: List of functions that call this function
        callees: List of functions called by this function

    Returns:
        A prompt string for the LLM
    """
    complexity = analyze_complexity(decompiled_code)

    prompt = ["Analyze this decompiled function and provide a structured summary.\n\n"]
    prompt.append(f"## Function: {function_name}\n\n")
    prompt.append(f"**Complexity:** {complexity}\n")

    if callers:
        prompt.append(f"**Called by:** {', '.join(callers)}\n")
    if callees:
        prompt.append(f"**Calls:** {', '.join(callees)}\n")
    prompt.append("\n")

    truncate_limit = 4000 if complexity.level == "very_complex" else 3000 if complexity.level == "complex" else 2000
    prompt.append(f"```c\n{_truncate_code(decompiled_code, truncate_limit)}\n```\n\n")

    # Output format instructions
    prompt.append("## Output Format (REQUIRED - follow this structure exactly):\n\n")
    prompt.append("**Summary:** [1-3 sentences describing what this function does]\n\n")

    # Complexity-based section guidance
    if complexity.level == "simple":
        prompt.append("For this simple function, provide ONLY the Summary and Category sections.\n\n")
    else:
        prompt.append("[Include the following sections ONLY if applicable to this function:]\n\n")

        if complexity.level in ("very_complex", "complex"):
            prompt.append("**Details:** [Detailed explanation of the function's logic including:\n")
            prompt.append("- Main code paths and control flow\n")
            prompt.append("- Key data transformations and algorithms\n")
            prompt.append("- Important state changes and side effects\n")
            prompt.append("- Error handling patterns\n")
            prompt.append("Use multiple paragraphs as needed for complex functions.]\n\n")
        else:
            prompt.append("**Details:** [Brief description of control flow and key operations. ")
            prompt.append("Skip this section for trivial utility functions.]\n\n")

        prompt.append("**File IO:** [ONLY if this function performs file operations: ")
        prompt.append("list operations like fopen, fread, fwrite, fclose, CreateFile, ReadFile, etc. ")
        prompt.append("Otherwise OMIT this section entirely.]\n\n")

        prompt.append("**Network IO:** [ONLY if this function performs network operations: ")
        prompt.append("list operations like socket, connect, send, recv, WSAStartup, getaddrinfo, etc. ")
        prompt.append("Otherwise OMIT this section entirely.]\n\n")

        prompt.append("**Security:** [ONLY if security-relevant observations exist: ")
        prompt.append("buffer handling concerns, input validation issues, crypto usage, ")
        prompt.append("privilege operations, error handling gaps. Otherwise OMIT this section.]\n\n")

    prompt.append("**Category:** [REQUIRED - One of: initialization, data_processing, io_operations, ")
    prompt.append("network, crypto, authentication, error_handling, utility, unknown]\n")

    return "".join(prompt)


def batch_function_summary_prompt(nodes: List[dict]) -> str:
    """Generate a batch prompt for summarizing multiple functions.
    Uses simplified format - Summary and Category only."""
    prompt = ["Summarize each of these functions. Scale summary length based on complexity:\n"
              "- Simple functions: 1-2 sentences\n"
              "- Moderate functions: 2-4 sentences\n"
              "- Complex functions: 1-2 paragraphs\n"
              "- Very complex functions: 2-3 paragraphs\n\n"
              "For each function, provide:\n"
              "**Summary:** [Description]\n"
              "**Category:** [One of: initialization, data_processing, io_operations, "
              "network, crypto, authentication, error_handling, utility, unknown]\n\n"
              "Format your response as a numbered list matching the input.\n\n"]

    for idx, node in enumerate(nodes, 1):
        name = node.get("name") or "unknown"
        code = node.get("raw_code") or ""
        complexity = analyze_complexity(code)
        truncate_limit = 2000 if complexity.level == "very_complex" else 1500 if complexity.level == "complex" else 1000
        prompt.append(f"{idx}. **{name}** [{complexity.level}]\n```c\n"
                      f"{_truncate_code(code, truncate_limit)}\n```\n\n")

    prompt.append("Summaries:\n")
    return "".join(prompt)


def function_brief_summary_prompt(function_name: str, decompiled_code: str) -> str:
    """Generate a complexity-scaled summary prompt for brief processing.
    Uses simplified format - Summary and Category only."""
    complexity = analyze_complexity(decompiled_code)

    prompt = [f"Summarize this decompiled function.\n\n"]
    prompt.append(f"Function: {function_name}\n")
    prompt.append(f"Complexity: {complexity}\n\n")

    truncate_limit = 4000 if complexity.level == "very_complex" else \
                     3000 if complexity.level == "complex" else \
                     2000 if complexity.level == "moderate" else 1500
    prompt.append(f"```c\n{_truncate_code(decompiled_code, truncate_limit)}\n```\n\n")

    prompt.append("## Output Format (REQUIRED):\n\n")
    prompt.append("**Summary:** [")
    if complexity.level == "simple":
        prompt.append("1-2 sentences")
    elif complexity.level == "moderate":
        prompt.append("2-4 sentences")
    else:
        prompt.append("1-2 paragraphs covering key functionality")
    prompt.append(" describing what this function does]\n\n")

    prompt.append("**Category:** [One of: initialization, data_processing, io_operations, ")
    prompt.append("network, crypto, authentication, error_handling, utility, unknown]\n\n")

    prompt.append("Do NOT include other sections (Details, File IO, Network IO, Security) in this brief format.")

    return "".join(prompt)


def _count_occurrences(text: str, pattern: str) -> int:
    return len(re.findall(pattern, text))


def _truncate_code(code: str, max_length: int) -> str:
    if not code:
        return ""
    if len(code) <= max_length:
        return code
    cutoff = code.rfind("\n", 0, max_length)
    if cutoff < max_length // 2:
        cutoff = max_length
    return code[:cutoff] + "\n// ... (truncated)"


# ========================================
# Response Parsing Helpers
# ========================================

def extract_summary(response: str) -> str:
    """Extract the Summary section from a function summary response."""
    return _extract_section(response, "Summary:")


def extract_details(response: str) -> str:
    """Extract the Details section from a function summary response."""
    return _extract_section(response, "Details:")


def extract_file_io(response: str) -> str:
    """Extract the File IO section from a function summary response."""
    return _extract_section(response, "File IO:")


def extract_network_io(response: str) -> str:
    """Extract the Network IO section from a function summary response."""
    return _extract_section(response, "Network IO:")


def extract_security(response: str) -> str:
    """Extract the Security section from a function summary response."""
    return _extract_section(response, "Security:")


def extract_category(response: str) -> str:
    """Extract the Category section from a function summary response."""
    return _extract_section(response, "Category:")


def _extract_section(response: str, header: str) -> str:
    """Extract a section from the response by header."""
    if not response:
        return ""

    # Try with ** markdown formatting first
    start = response.find(f"**{header}")
    if start != -1:
        # Find closing **
        close = response.find("**", start + 2)
        if close != -1:
            start = close + 2
    else:
        # Fall back to plain header
        start = response.find(header)
        if start != -1:
            start += len(header)

    if start == -1:
        return ""

    # Find the end of this section (next section header or end of text)
    end = len(response)

    # Look for next section (with ** prefix)
    next_section = response.find("\n**", start)
    if next_section != -1 and next_section < end:
        end = next_section

    # Also check for double newline as section separator
    double_newline = response.find("\n\n", start)
    if double_newline != -1 and double_newline < end:
        after_newline = response[double_newline + 2:].strip()
        if after_newline.startswith("**") or re.match(r"^[A-Z][a-z]+:", after_newline):
            end = double_newline

    result = response[start:end].strip()
    # Remove leading colon if present
    if result.startswith(":"):
        result = result[1:].strip()

    return result
