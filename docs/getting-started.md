# Getting Started with IDAssist

This guide walks you through installing IDAssist, configuring an LLM provider, and running your first function analysis.

## Prerequisites

- **IDA Pro 9.0+** with Python 3 support
- **Hex-Rays Decompiler** (recommended — enables pseudocode features)
- **Python 3.11+** (bundled with IDA Pro 9.x)
- **pip** for installing Python dependencies

## Installation

### Step 1: Install Python Dependencies

```bash
pip install -r requirements.txt
```

The key dependencies are:
- `openai` — OpenAI API client
- `anthropic` — Anthropic API client
- `markdown` — Markdown rendering
- `httpx` — Async HTTP client
- `mcp==1.23.3` — Model Context Protocol
- `whoosh` — Full-text search indexing
- `aiohttp` — Async HTTP server (for built-in MCP server)
- `anyio>=4.6` — Async I/O utilities

### Step 2: Install the Plugin

**Option A: Copy files** (simplest)

Copy `idassist_plugin.py` and the `src/` directory to your IDA plugins folder:

```bash
cp idassist_plugin.py ~/.idapro/plugins/
cp -r src ~/.idapro/plugins/
```

**Option B: Symlink** (recommended for development)

Create file-level symlinks so you can edit the source in place:

```bash
ln -s /path/to/IDAssist/idassist_plugin.py ~/.idapro/plugins/idassist_plugin.py
ln -s /path/to/IDAssist/src ~/.idapro/plugins/src
```

> **Note:** Use file-level symlinks, not directory symlinks. IDA discovers plugins by scanning `~/.idapro/plugins/` for `.py` files containing a `PLUGIN_ENTRY()` function.

### Step 3: Verify Installation

1. Launch IDA Pro and open any binary
2. Check the Output window for: `IDAssist: Plugin initialized`
3. The IDAssist panel should appear as a dockable tab

If the panel doesn't appear automatically, press **Ctrl+Shift+A** or go to **Edit > Plugins > IDAssist**.

## Open IDAssist

- **Hotkey:** `Ctrl+Shift+A`
- **Menu:** Edit > Plugins > IDAssist
- IDAssist opens as a dockable panel that persists across IDA sessions

## Configuring an LLM Provider

Navigate to the **Settings** tab to configure your LLM provider. IDAssist needs at least one configured provider before it can analyze functions.

### Option 1: Ollama (Local, Free)

Best for getting started quickly with no API keys.

1. Install Ollama from [ollama.com](https://ollama.com)
2. Pull a model: `ollama pull qwen2.5-coder:32b`
3. In IDAssist Settings, click **Add** under LLM Providers:
   - **Name:** `Ollama`
   - **Type:** `ollama`
   - **Model:** `qwen2.5-coder:32b`
   - **URL:** `http://localhost:11434`
   - **API Key:** (leave blank)
4. Click **Save**, then set as **Active Provider**

### Option 2: OpenAI

1. Get an API key from [platform.openai.com](https://platform.openai.com)
2. In IDAssist Settings, click **Add**:
   - **Name:** `OpenAI`
   - **Type:** `openai_platform`
   - **Model:** `gpt-4o`
   - **URL:** `https://api.openai.com/v1`
   - **API Key:** your key
3. Click **Save**, then set as **Active Provider**

### Option 3: Anthropic

1. Get an API key from [console.anthropic.com](https://console.anthropic.com)
2. In IDAssist Settings, click **Add**:
   - **Name:** `Claude`
   - **Type:** `anthropic_platform`
   - **Model:** `claude-sonnet-4-6`
   - **URL:** `https://api.anthropic.com`
   - **API Key:** your key
3. Click **Save**, then set as **Active Provider**

### Option 4: LiteLLM Proxy

Use LiteLLM to route through multiple providers with a single endpoint.

1. Set up a LiteLLM proxy server
2. In IDAssist Settings, click **Add**:
   - **Name:** `LiteLLM`
   - **Type:** `litellm`
   - **Model:** your model name
   - **URL:** your proxy URL
   - **API Key:** your proxy key (if required)
3. Click **Save**, then set as **Active Provider**

### Setting the Active Provider

After adding a provider, select it from the **Active Provider** dropdown in the Settings tab. Only one provider is active at a time. You can switch providers at any time — the active provider is used for all Explain, Query, and Actions operations.

Click **Test** next to any provider to verify the connection is working.

## Your First Analysis

### Step 1: Navigate to a Function

In IDA's Disassembly or Pseudocode view, navigate to any function you want to analyze. The current function address is displayed at the top of IDAssist tabs.

### Step 2: Generate an Explanation

Click the **Explain** tab, then click **Explain Function**. IDAssist will:
- Extract the function's pseudocode (if Hex-Rays is available) or disassembly
- Send it to your active LLM provider
- Stream the explanation into the display area
- Automatically generate a security analysis panel

### Step 3: Review Security Analysis

Below the explanation, the Security Analysis panel shows:
- **Risk Level** — Overall risk assessment
- **Activity Profile** — What the function does (network, file I/O, crypto, etc.)
- **Security Flags** — Specific vulnerability indicators
- **Network APIs / File I/O APIs** — Detected security-relevant API calls

### Step 4: Ask Follow-up Questions

Switch to the **Query** tab and ask questions about the function. Use context macros to include code:

- `#func` — Inserts the current function's pseudocode or disassembly
- `#addr` — Inserts the address under the cursor
- `#line` — Inserts the current disassembly line
- `#range(0x401000, 0x401100)` — Inserts disassembly for an address range

Example query:
```
What vulnerabilities exist in this function? #func
```

## Next Steps

- [Explain Workflow](workflows/explain-workflow.md) — Build a documentation set for the binary
- [Query Workflow](workflows/query-workflow.md) — Advanced querying with MCP tools and ReAct agent
- [Semantic Graph Workflow](workflows/semantic-graph-workflow.md) — Build a knowledge graph of the binary
- [Actions Tab](tabs/actions-tab.md) — AI-powered rename and retype suggestions
- [RAG Tab](tabs/rag-tab.md) — Upload reference documents for context
- [Settings Tab](tabs/settings-tab.md) — Full provider and configuration reference

## Troubleshooting

### Plugin Not Loading

- Verify `idassist_plugin.py` is in `~/.idapro/plugins/` (or your platform's IDA plugins directory)
- Check the IDA Output window for error messages
- Ensure all dependencies from `requirements.txt` are installed in IDA's Python environment
- Confirm IDA Pro 9.0+ with Python 3 support

### No Response from LLM

- Go to Settings and click **Test** on your active provider
- Check the URL, API key, and model name
- For Ollama, verify the server is running: `curl http://localhost:11434/api/tags`
- Check the IDA Output window for error details

### Hex-Rays Not Available

- IDAssist works without Hex-Rays but falls back to disassembly instead of pseudocode
- Some features (variable renaming, struct creation) require Hex-Rays
- Ensure Hex-Rays is licensed and loaded for your processor type

### Connection Issues

- For self-signed TLS certificates, enable **Disable TLS** in the provider settings
- For corporate proxies, consider using a LiteLLM proxy as an intermediary
- Check that your firewall allows outbound connections to the LLM provider
