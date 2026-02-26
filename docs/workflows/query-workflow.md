# Workflow: Querying with the Query Tab

## Overview

The Query tab provides an interactive chat for asking questions about the binary. This workflow covers basic queries, context macros, MCP tool integration, and the ReAct autonomous agent.

## When to Use the Query Tab

- You have specific questions about a function or code pattern
- You need to compare multiple functions or trace data flows
- You want the LLM to investigate something across the binary using tools
- You're looking for vulnerabilities, backdoors, or specific behavior
- You need to understand how a function relates to the broader binary

## Basic Query Workflow

### Step 1: Navigate to a Function

Navigate to the function of interest in IDA. The **Current Offset** display updates to show the address.

You can also right-click in the Disassembly or Pseudocode view and select **Ask About Selection** (`Ctrl+Shift+Q`) to open the Query tab with `#func` pre-filled.

### Step 2: Compose Your Query

Type your question in the input area. Use context macros to include code from IDA:

| Macro | Inserts |
|-------|---------|
| `#func` | Current function's pseudocode or disassembly |
| `#addr` | Address under the cursor (e.g., `0x401234`) |
| `#line` | Current disassembly line |
| `#range(0x401000, 0x401100)` | Disassembly for an address range |

**Example queries:**

```
What does this function do? #func

Is there a use-after-free at #addr?

What calling convention does this use? #line

Compare these two code blocks:
Block 1: #range(0x401000, 0x401050)
Block 2: #range(0x402000, 0x402050)
```

### Step 3: Submit and Review

Press **Enter** (or click **Submit**) to send the query. The response streams into the display area. Use **Ctrl+Enter** to insert a newline without submitting.

### Step 4: Follow Up

Continue the conversation in the same chat session. The LLM retains context from previous messages, so you can ask follow-up questions without repeating context:

```
What about the error handling path?
Could this be exploited if the input is user-controlled?
```

### Step 5: Manage Conversations

- **New** — Start a fresh conversation
- **Delete** — Remove selected conversations
- Double-click a chat's description to rename it
- Click any previous chat in the history table to reload it

## MCP Tool Integration Workflow

Enable the **MCP** checkbox to let the LLM invoke tools during response generation.

### When to Use MCP

- Questions that require inspecting multiple functions
- Tracing data flows across the call graph
- Looking up cross-references or function signatures
- Any question where the LLM would benefit from gathering more information

### How It Works

1. Check the **MCP** checkbox
2. Submit your query
3. The LLM analyzes your question and decides which tools to call
4. Tool calls and results appear inline in the conversation
5. The LLM incorporates tool results into its final answer

**Available built-in tools** (via IDAssist's MCP server on port 8765):

| Tool | What It Does |
|------|-------------|
| `ida_get_function_name` | Look up a function's name by address |
| `ida_get_disassembly` | Get disassembly at an address |
| `ida_get_pseudocode` | Get Hex-Rays decompilation |
| `ida_get_xrefs` | Get cross-references to/from an address |
| `ida_set_function_name` | Rename a function |
| `ida_add_comment` | Add a comment at an address |

External MCP servers configured in Settings provide additional tools.

## ReAct Agent Workflow

The ReAct (Reasoning + Acting) agent performs autonomous multi-round investigations.

### When to Use ReAct

- Complex questions requiring exploration of multiple functions
- Vulnerability hunting across the binary
- Understanding data flow between distant functions
- Questions where you don't know which functions are relevant

### Enabling ReAct

1. Check the **ReAct Agent** checkbox (this also requires MCP)
2. Submit your query
3. The agent begins its investigation cycle

### Investigation Process

The agent follows a structured cycle:

1. **Plan** — Reads your question and plans what to investigate
2. **Investigate** — Calls tools to inspect functions, read code, trace xrefs
3. **Reflect** — Evaluates what it found and decides if more investigation is needed
4. **Repeat** — If more information is needed, the agent loops back to step 2
5. **Synthesize** — Produces a comprehensive answer incorporating all findings

Progress is visible in the chat as the agent works. Each tool call and intermediate reasoning step appears in the conversation.

### Stopping the Agent

Click **Stop** at any time to halt the investigation. The agent will produce a summary of what it found so far.

## Extended Thinking

Configure reasoning depth in the Settings tab:

| Level | Token Budget | Best For |
|-------|-------------|----------|
| None | Disabled | Quick, straightforward questions |
| Low | ~2K tokens | Simple analysis tasks |
| Medium | ~10K tokens | Moderate complexity, multi-step reasoning |
| High | ~25K tokens | Deep analysis, complex vulnerability assessment |

Higher thinking budgets produce more thorough responses but take longer. Extended thinking is supported by Anthropic Claude and OpenAI o1 models.

## Tips for Effective Queries

- **Be specific**: "What buffer overflow vulnerabilities exist in this function?" is better than "Is this secure?"
- **Use context macros**: Always include `#func` when asking about a specific function so the LLM can see the code
- **Build on previous answers**: The LLM remembers the conversation history, so reference earlier responses
- **Combine RAG + MCP**: Enable both for the most informed responses — RAG provides document context while MCP provides live binary inspection
- **Use ReAct for exploration**: When you don't know what to look for, let the agent explore
- **Save important chats**: Rename conversations with descriptive titles for easy retrieval later

## Related Documentation

- [Query Tab Reference](../tabs/query-tab.md) — Full UI element reference
- [Explain Workflow](explain-workflow.md) — Systematic function analysis
- [Semantic Graph Workflow](semantic-graph-workflow.md) — Build a knowledge graph
- [RAG Tab](../tabs/rag-tab.md) — Upload reference documents
- [Settings Tab](../tabs/settings-tab.md) — Configure providers, reasoning effort, MCP servers
