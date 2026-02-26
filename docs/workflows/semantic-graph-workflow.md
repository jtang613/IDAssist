# Workflow: Building a Knowledge Graph with the Semantic Graph Tab

## Overview

The Semantic Graph workflow builds a searchable knowledge graph of the binary's functions, call relationships, security characteristics, and community structure. Once built, the graph enables semantic search, visual exploration, and automated security analysis.

## When to Use the Semantic Graph Tab

- You're starting analysis of a new binary and want a high-level overview
- You need to find functions related to a specific behavior (network, crypto, file I/O)
- You want to visualize the call graph around a function of interest
- You're hunting for vulnerabilities across the entire binary
- You want to identify functional modules and their relationships
- You're preparing to share analysis data via SymGraph

## Step-by-Step Workflow

### Step 1: Open the Semantic Graph Tab

Click the **Semantic Graph** tab in IDAssist. The bottom status bar shows the current graph statistics. If this is a new binary, the graph will be empty.

### Step 2: ReIndex the Binary

Click **ReIndex Binary** to extract the binary's structure:

- All functions are indexed via `idautils.Functions()`
- Call relationships are extracted from cross-references
- Data flow edges are identified
- The progress bar shows indexing progress

This step does not require an LLM — it uses IDA's built-in analysis data. The graph status bar updates to show the number of nodes and edges.

### Step 3: Run Semantic Analysis

Click **Semantic Analysis** to generate LLM summaries for each function:

- Each function's pseudocode or disassembly is sent to the LLM
- The LLM generates a natural-language summary
- Summaries are stored in the analysis database
- The progress bar shows how many functions have been analyzed

This step uses your active LLM provider and can take a while for large binaries. Options:
- **RAG** checkbox: Include document context in the analysis prompts
- **MCP** checkbox: Allow the LLM to use tools during analysis
- **Force re-analysis**: Regenerate summaries for functions that already have one

### Step 4: Run Security Analysis

In the **Manual Analysis** panel, click **Security Analysis** to detect vulnerability patterns:

- Scans for dangerous API usage (buffer operations, format strings, etc.)
- Identifies security-relevant flags on each function
- Detects potential vulnerability patterns
- Results are stored as security flags on graph nodes

### Step 5: Run Network Flow Analysis

Click **Network Flow** to trace network operations across the binary:

- Identifies functions that send or receive network data
- Traces data flow from input to output
- Creates `network_send` and `network_recv` edges in the graph
- Helps understand the binary's network communication patterns

### Step 6: Run Community Detection

Click **Community Detection** to group related functions into logical modules:

- Uses graph algorithms to identify clusters of related functions
- Groups functions that call each other frequently
- Helps identify functional boundaries (e.g., "crypto module", "network handler", "parser")
- Module information is stored in the graph and visible in search results

## Exploring the Graph

### List View

The default view showing details for the selected function:

1. Navigate to a function in IDA (or type a name/address in the **Current** field and click **Go**)
2. **Callers** and **Callees** lists show the function's relationships — double-click any entry to navigate
3. **Edges** table shows all edges with type filtering — useful for finding vulnerability or taint flow edges
4. **Security Flags** section shows and lets you toggle flags on the current function
5. **LLM Summary** displays the semantic analysis result — click **Edit** to modify

### Visual Graph

Switch to the Visual Graph sub-tab for an interactive diagram:

1. The center node (teal) is the currently selected function
2. Adjust **N-Hops** (1–5) to expand the visible neighborhood
3. Toggle edge types: **CALLS** (blue), **VULN** (red), **NETWORK** (gray)
4. Use zoom controls or scroll to zoom in/out, click **Fit** to fit the graph to the view
5. Double-click any node to navigate to that function in IDA
6. Click a node to see its summary in the panel below

Node colors indicate status:
- **Teal** (`#2ea8b3`) — Currently selected function
- **Dark gray** (`#3a3f44`) — Normal function
- **Dark red** (`#7a2b2b`) — Function with security vulnerability flags

### Search

The Search sub-tab provides seven query types:

| Query Type | Example Use |
|-----------|-------------|
| **Semantic Search** | "functions that parse network packets" |
| **Get Analysis** | Retrieve stored analysis for a specific address |
| **Similar Functions** | Find functions similar to the current one |
| **Call Context** | Explore the call chain around a function |
| **Security Analysis** | "find all functions with buffer overflow risk" |
| **Module Summary** | Summarize a detected community/module |
| **Activity Analysis** | "which functions perform file I/O" |

Click a result row to see full details, then click **Go To** to navigate to that function.

## Using the Graph in Queries

The semantic graph enhances other IDAssist features:

- **MCP Integration**: When MCP is enabled on the Query or Explain tabs, the LLM can query the graph for function summaries, relationships, and security data
- **RAG + Graph**: Combine document context with graph knowledge for the most comprehensive analysis
- **ReAct Agent**: The autonomous agent can traverse the graph to investigate relationships across the binary

## Sharing via SymGraph

Once your graph is built, push it to the SymGraph platform for team collaboration:

1. Switch to the **SymGraph** tab
2. Check **Symbols** and **Graph** under "Data to Push"
3. Click **Push to SymGraph**
4. Team members can pull your analysis, including function summaries, security flags, and graph structure

## Tips

- **Start with ReIndex**: Always ReIndex before running other analyses — it provides the structural foundation
- **Semantic Analysis takes time**: For large binaries (1000+ functions), consider running it overnight or on a subset
- **Use Force re-analysis sparingly**: Only re-analyze when you've changed the LLM provider or want better summaries
- **Security flags are cumulative**: Running security analysis multiple times won't duplicate flags
- **Refresh Names after renaming**: If you rename functions (via Actions tab or manually), click **Refresh Names** to update graph labels
- **Graphviz improves layout**: Install Graphviz (`dot` command) for better visual graph layouts. Without it, IDAssist falls back to a BFS-based layout.

## Related Documentation

- [Semantic Graph Tab Reference](../tabs/semantic-graph-tab.md) — Full UI element reference
- [Explain Workflow](explain-workflow.md) — Analyze individual functions in depth
- [Query Workflow](query-workflow.md) — Ask questions that leverage the graph via MCP
- [RAG Tab](../tabs/rag-tab.md) — Upload documents to enhance semantic analysis
