#!/usr/bin/env python3

"""
ReAct Agent Prompts

Prompt templates for planning, investigation, reflection, and synthesis.
Based on GhidrAssist's proven ReAct implementation.
"""


class ReActPrompts:
    """Prompt templates for ReAct agent"""

    @staticmethod
    def get_system_prompt() -> str:
        """System prompt for ReAct agent"""
        return """You are an expert reverse engineering assistant conducting an autonomous investigation.

You have access to MCP tools for binary analysis. Use these tools to systematically investigate the user's question.

Guidelines:
- Be thorough but efficient - don't make redundant tool calls
- Focus on the most relevant information for the investigation
- Track your progress against the investigation plan
- Summarize findings clearly after each tool use
- Know when you have enough information to provide a comprehensive answer"""

    @staticmethod
    def get_planning_prompt(objective: str, context_preview: str = "") -> str:
        """Generate planning prompt for initial todo list creation"""
        context_section = f"""**Available Context**:
{context_preview}""" if context_preview else """**Available Context**:
[Binary analysis context available via tools]"""

        return f"""## Investigation Planning

**User's Question**: {objective}

{context_section}

Before we start investigating, let's plan the investigation steps.

**Task**: Based on the user's question, propose a list of 3-5 investigation
steps to answer this question thoroughly.

Format your response as a markdown checklist:
- [ ] First investigation step
- [ ] Second investigation step
- [ ] Third investigation step

Focus on specific, actionable steps that use the available MCP tools.
Consider what information you need to gather to provide a comprehensive answer.

Keep steps concrete and achievable in 1-2 tool calls each."""

    @staticmethod
    def get_investigation_prompt(objective: str, todos_formatted: str,
                                  findings_formatted: str, iteration: int,
                                  remaining_iterations: int) -> str:
        """Generate investigation prompt for each iteration"""
        warning = ""
        if remaining_iterations <= 3:
            warning = f"\n\n**Warning:** Only {remaining_iterations} iterations remaining. Consider synthesizing your answer soon if you have enough information."

        return f"""## Investigation Iteration {iteration}

**Your Goal**: {objective}

**Investigation Progress**:
{todos_formatted}

**What You've Discovered**:
{findings_formatted}
{warning}

**Current Task**: Focus on the task marked with [->] in the progress list above.

**Instructions**:
1. Think about what information you still need for the current task
2. Call the appropriate MCP tool(s) to gather that information
3. After receiving results, briefly summarize what you learned

If you believe the current task is complete based on previous findings, you may proceed without additional tool calls."""

    @staticmethod
    def get_reflection_prompt(objective: str, todos_formatted: str,
                              findings_formatted: str) -> str:
        """Generate self-reflection prompt with adaptive planning"""
        return f"""## Self-Reflection & Plan Adaptation

**Original Question**: {objective}

**Current Investigation Plan**:
{todos_formatted}

**Findings Accumulated**:
{findings_formatted}

**Reflection Tasks**:
1. **Progress Assessment**: Review what you've learned and how it relates to the objective
2. **Plan Adaptation**: Based on new findings, should the investigation plan change?
3. **Readiness Check**: Can you now answer the user's question comprehensively?

**Required Response Format** (use plain text, keep label and content on same line):

**Assessment:** [Your assessment here on same line]

**Plan Updates:**
- ADD: [task] (or "None")
- REMOVE: [task] (or "None")

**Decision:** READY or CONTINUE

**Reason:** [Your reason here on same line - do NOT put a newline after "Reason:"]

**Guidelines**:
- Keep each label and its content on the SAME LINE (e.g., "**Reason:** Because..." not "**Reason:**\\nBecause...")
- **ADD** new tasks if findings reveal unexpected complexity or new investigation paths
- **REMOVE** pending tasks that are no longer relevant based on what you've learned
- Say **CONTINUE** if there are pending tasks that would provide valuable information
- Say **READY** only if ALL planned tasks are complete OR remaining tasks would not meaningfully improve the answer
- Completing investigation tasks thoroughly leads to better answers
- Do NOT use code blocks, backticks, or extra newlines after labels"""

    @staticmethod
    def get_synthesis_prompt(objective: str, todos_formatted: str,
                             findings_detailed: str) -> str:
        """Generate final synthesis prompt"""
        return f"""## Time to Synthesize

**Goal**: {objective}

**Completed Investigation**:
{todos_formatted}

**Investigation Summary**:
{findings_detailed}

You've completed your investigation. Based on all the information you've gathered, provide a comprehensive answer to the user's question.

**Instructions**:
Synthesize your findings into a clear, actionable response that:
1. Directly addresses the user's question
2. References specific evidence from your investigation
3. Highlights the most important discoveries
4. Provides recommendations or next steps if applicable

Format your response with clear headings and structure for readability.
Be concise but thorough - include all relevant findings."""

    @staticmethod
    def get_tool_guidance_prompt(available_tools: list) -> str:
        """Generate guidance about available tools"""
        if not available_tools:
            return ""

        tool_names = [t.get('function', {}).get('name', 'unknown') for t in available_tools]
        return f"""
**Available Tools**: {', '.join(tool_names)}

Choose the most appropriate tool for your current investigation step."""
