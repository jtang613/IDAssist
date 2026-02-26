# Workflow: Analyzing Functions with the Explain Tab

## Overview

The Explain workflow walks you through generating, reviewing, and saving function explanations. Use it to systematically document a binary's functions and identify security-relevant behavior.

## When to Use the Explain Tab

- You need to understand what an unfamiliar function does
- You want to assess a function's security risk
- You're building documentation for a binary
- You want to identify dangerous API usage (network, file I/O, crypto)
- You need a quick summary before diving into detailed analysis

## Step-by-Step Workflow

### Step 1: Select a Function

Navigate to a function in IDA's Disassembly or Pseudocode view. The **Current Offset** in the Explain tab updates automatically to show the function address.

You can also use the context menu shortcut: right-click in the Disassembly or Pseudocode view and select **Explain Function** (`Ctrl+Shift+E`). This opens IDAssist, switches to the Explain tab, and immediately starts the explanation.

### Step 2: Generate an Explanation

Click **Explain Function**. IDAssist extracts the function's pseudocode (via Hex-Rays) or disassembly and sends it to the active LLM provider. The explanation streams into the display area in real time.

If you only need to understand a specific line, click **Explain Line** instead. This produces a focused explanation of the instruction at the cursor, displayed in a separate panel below the main explanation.

### Step 3: Review Security Analysis

After the explanation finishes, review the Security Analysis panel:

| Field | What to Look For |
|-------|-----------------|
| **Risk Level** | HIGH or CRITICAL indicates immediate attention needed. |
| **Activity Profile** | Tells you what category of work the function does (NETWORK, FILE_IO, CRYPTO, MEMORY). |
| **Security Flags** | Specific vulnerability patterns detected (BUFFER_OVERFLOW_RISK, COMMAND_INJECTION_RISK, etc.). |
| **Network APIs** | Functions like `socket`, `connect`, `send`, `recv` — indicates network communication. |
| **File I/O APIs** | Functions like `open`, `read`, `write`, `unlink` — indicates file system access. |

### Step 4: Edit and Save

If you want to refine the explanation:
1. Click **Edit** to switch to the raw text editor
2. Modify the explanation text
3. Click **Save** to store your changes

The explanation is saved to the analysis database, keyed by binary SHA-256 + function address. It will reload automatically the next time you navigate to this function.

### Step 5: Provide Feedback

Use the thumbs-up / thumbs-down links at the bottom of the explanation to rate quality. This feedback is stored in the RLHF database for future reference.

### Step 6: Clear and Move On

Click **Clear** to remove the current explanation from the display (the saved version remains in the database). Navigate to the next function and repeat.

## Enhancing Explanations with RAG

Enable the **RAG** checkbox before generating an explanation to include relevant document context:

1. Upload reference documents in the [RAG Tab](../tabs/rag-tab.md) (API docs, protocol specs, etc.)
2. Check the **RAG** checkbox on the Explain tab
3. Click **Explain Function**
4. IDAssist searches the RAG index for relevant snippets and includes them in the LLM prompt
5. The explanation incorporates knowledge from your documents

This is especially useful when analyzing code that implements specific protocols, uses proprietary APIs, or follows documented standards.

## Enhancing Explanations with MCP

Enable the **MCP** checkbox to let the LLM call tools during explanation generation:

1. Ensure MCP providers are configured in [Settings](../tabs/settings-tab.md) (or use the built-in server)
2. Check the **MCP** checkbox on the Explain tab
3. Click **Explain Function**
4. The LLM can call tools to inspect related functions, check cross-references, or look up additional context
5. Tool results are incorporated into the explanation

## Explain Line Usage

The **Explain Line** feature is useful for:
- Understanding complex assembly instructions
- Clarifying what a specific decompiler output line does
- Getting a quick explanation without analyzing the entire function

The line explanation appears in a collapsible panel below the main explanation. Click the **x** button to dismiss it.

## Building a Documentation Set

For systematic binary documentation:

1. Start with entry points (main, DllMain, exported functions)
2. Explain each function, saving the results
3. Use the security analysis to prioritize which functions to investigate deeper
4. Navigate to callees of interesting functions and explain those
5. Build up a complete picture by working outward from entry points

Explanations persist in the analysis database, so you can close IDA and resume later. Previously explained functions load instantly without re-querying the LLM.

## Tips

- **Start with Hex-Rays**: Pseudocode produces better explanations than raw disassembly. Ensure Hex-Rays is available for your processor type.
- **Use Extended Thinking**: For complex functions, increase the reasoning effort in Settings to get deeper analysis.
- **Combine with Query**: After getting an explanation, switch to the Query tab to ask follow-up questions about specific aspects.
- **Check Security Flags**: Even if the overall risk is LOW, individual security flags can reveal subtle issues.

## Related Documentation

- [Explain Tab Reference](../tabs/explain-tab.md) — Full UI element reference
- [Query Workflow](query-workflow.md) — Ask follow-up questions about functions
- [RAG Tab](../tabs/rag-tab.md) — Upload reference documents
- [Settings Tab](../tabs/settings-tab.md) — Configure providers and reasoning effort
