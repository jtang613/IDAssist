#!/usr/bin/env python3

"""
Claude Code Provider - Implementation for Claude Code CLI
Uses the `claude` CLI tool to make LLM requests, bypassing API authentication.
"""

import asyncio
import json
import os
import shutil
import subprocess
import tempfile
import time
from typing import List, Dict, Any, AsyncGenerator, Optional, Callable

from .base_provider import (
    BaseLLMProvider, APIProviderError, AuthenticationError,
    RateLimitError, NetworkError
)
from ..models.llm_models import (
    ChatRequest, ChatResponse, EmbeddingRequest, EmbeddingResponse,
    ChatMessage, MessageRole, ToolCall, ToolResult, Usage, ProviderCapabilities
)
from ..models.provider_types import ProviderType

from src.ida_compat import log


class AnthropicClaudeCliProvider(BaseLLMProvider):
    """
    Claude Code CLI provider implementation.

    Uses the `claude` command-line tool to make LLM requests.
    This bypasses API authentication by using Claude Code's existing auth.

    Note: This provider does NOT support true streaming - it simulates streaming
    by chunking the complete response after the CLI returns.
    """

    def __init__(self, config: Dict[str, Any]):
        """Initialize Claude Code provider"""
        super().__init__(config)

        # Claude CLI path (default: 'claude' - assumes it's in PATH)
        self.claude_path = config.get('claude_path', 'claude')

        # Timeout for CLI execution (default: 5 minutes)
        self.timeout = config.get('timeout', 300)

        # Model to use (sonnet, opus, haiku)
        if not self.model:
            self.model = 'sonnet'

        # Chunk size for simulated streaming (characters per chunk)
        self.stream_chunk_size = config.get('stream_chunk_size', 50)

        # Delay between chunks for simulated streaming (seconds)
        self.stream_chunk_delay = config.get('stream_chunk_delay', 0.01)

        # MCP config file path (created on demand)
        self._mcp_config_path = None

        # Whether to use MCP servers (enabled by default if available)
        self.use_mcp = config.get('use_mcp', True)

        log.log_info(f"Claude Code provider initialized with model: {self.model}, CLI: {self.claude_path}")

    def _get_mcp_config(self) -> Optional[str]:
        """
        Get or create MCP config file for Claude CLI.

        Returns path to temporary MCP config file, or None if no MCP servers configured.
        """
        try:
            # Import settings service to get MCP providers
            from ..settings_service import settings_service

            mcp_providers = settings_service.get_mcp_providers()
            if not mcp_providers:
                log.log_debug("No MCP providers configured")
                return None

            # Filter to enabled SSE/HTTP providers only
            enabled_providers = [p for p in mcp_providers if p.get('enabled', True)]
            if not enabled_providers:
                log.log_debug("No enabled MCP providers")
                return None

            # Build Claude CLI MCP config format
            mcp_servers = {}
            for provider in enabled_providers:
                name = provider.get('name', 'unknown')
                url = provider.get('url', '')
                transport = provider.get('transport', 'sse')

                if not url:
                    continue

                # Claude CLI expects 'type' field for SSE/HTTP transports
                if transport in ('sse', 'streamablehttp'):
                    mcp_servers[name] = {
                        "type": "sse" if transport == "sse" else "http",
                        "url": url
                    }
                    log.log_debug(f"Added MCP server to config: {name} -> {url}")

            if not mcp_servers:
                log.log_debug("No compatible MCP servers for Claude CLI")
                return None

            # Create temp config file
            config_data = {"mcpServers": mcp_servers}

            # Create or reuse temp file
            if self._mcp_config_path and os.path.exists(self._mcp_config_path):
                # Update existing file
                with open(self._mcp_config_path, 'w') as f:
                    json.dump(config_data, f)
            else:
                # Create new temp file (won't be auto-deleted)
                fd, self._mcp_config_path = tempfile.mkstemp(suffix='.json', prefix='binassist_mcp_')
                with os.fdopen(fd, 'w') as f:
                    json.dump(config_data, f)

            log.log_info(f"Created MCP config with {len(mcp_servers)} servers: {self._mcp_config_path}")
            return self._mcp_config_path

        except Exception as e:
            log.log_warn(f"Failed to create MCP config: {e}")
            return None

    def cleanup(self):
        """Clean up temporary files."""
        if self._mcp_config_path and os.path.exists(self._mcp_config_path):
            try:
                os.unlink(self._mcp_config_path)
                self._mcp_config_path = None
            except Exception as e:
                log.log_debug(f"Failed to clean up MCP config: {e}")

    def _find_claude_cli(self) -> Optional[str]:
        """Find the claude CLI executable (cross-platform)"""
        import platform

        # First try the configured path
        if self.claude_path and shutil.which(self.claude_path):
            return self.claude_path

        # shutil.which() handles platform-specific executable extensions (.exe, .cmd on Windows)
        # Try the simple name first - this works on all platforms if claude is in PATH
        if shutil.which('claude'):
            return shutil.which('claude')

        # Platform-specific common locations
        system = platform.system()

        if system == 'Windows':
            # Windows npm global paths
            appdata = os.environ.get('APPDATA', '')
            localappdata = os.environ.get('LOCALAPPDATA', '')
            common_paths = [
                os.path.join(appdata, 'npm', 'claude.cmd'),
                os.path.join(appdata, 'npm', 'claude'),
                os.path.join(localappdata, 'npm', 'claude.cmd'),
                os.path.join(localappdata, 'npm', 'claude'),
                # Scoop install location
                os.path.join(os.environ.get('USERPROFILE', ''), 'scoop', 'shims', 'claude.cmd'),
            ]
        elif system == 'Darwin':
            # macOS paths
            common_paths = [
                '/usr/local/bin/claude',
                '/opt/homebrew/bin/claude',  # Apple Silicon Homebrew
                os.path.expanduser('~/.npm-global/bin/claude'),
                os.path.expanduser('~/Library/npm/bin/claude'),
            ]
        else:
            # Linux paths
            common_paths = [
                '/usr/local/bin/claude',
                '/usr/bin/claude',
                os.path.expanduser('~/.local/bin/claude'),
                os.path.expanduser('~/.npm-global/bin/claude'),
                '/snap/bin/claude',  # Snap install
            ]

        for path in common_paths:
            if path and os.path.isfile(path):
                return path
            # Also try shutil.which in case of symlinks or PATH issues
            if path and shutil.which(path):
                return shutil.which(path)

        return None

    def _format_messages_for_cli(self, messages: List[ChatMessage]) -> str:
        """
        Format chat messages into a single prompt string for the CLI.

        The claude CLI expects a single prompt string, so we need to
        format multi-turn conversations appropriately.
        """
        formatted_parts = []

        for message in messages:
            role = message.role.value if isinstance(message.role, MessageRole) else message.role
            content = message.content or ""

            if role == "system":
                formatted_parts.append(f"System: {content}")
            elif role == "user":
                formatted_parts.append(f"User: {content}")
            elif role == "assistant":
                formatted_parts.append(f"Assistant: {content}")
            elif role == "tool":
                formatted_parts.append(f"Tool Result: {content}")

        return "\n\n".join(formatted_parts)

    async def _run_claude_cli(self, prompt: str, tools: Optional[List[Dict[str, Any]]] = None) -> str:
        """
        Execute the claude CLI and return the response.

        Args:
            prompt: The prompt to send to Claude
            tools: Optional list of tool definitions

        Returns:
            The CLI output (Claude's response)
        """
        cli_path = self._find_claude_cli()
        if not cli_path:
            raise APIProviderError(
                "Claude CLI not found. Please install it with: npm install -g @anthropic-ai/claude-code"
            )

        # Validate prompt is not empty
        if not prompt or not prompt.strip():
            raise APIProviderError("Cannot send empty prompt to Claude CLI")

        # Build command - use stdin for prompt to avoid shell escaping issues
        cmd = [cli_path, '--print', '--model', self.model]

        # Add MCP config if available and enabled
        # Only use MCP if:
        # 1. use_mcp is True (provider setting)
        # 2. tools parameter was provided (indicates MCP checkbox is enabled in UI)
        if self.use_mcp and tools is not None:
            mcp_config_path = self._get_mcp_config()
            if mcp_config_path:
                cmd.extend(['--mcp-config', mcp_config_path])
                # Auto-approve MCP tool calls (required for non-interactive mode)
                cmd.append('--dangerously-skip-permissions')
                log.log_debug(f"Using MCP config: {mcp_config_path}")
        elif tools is None:
            log.log_debug("MCP disabled (no tools requested)")

        # Note: We don't need --allowedTools when using MCP, as the CLI handles tool discovery
        # The tools parameter from BinAssist is ignored - Claude CLI discovers tools from MCP servers

        # Note: prompt will be passed via stdin, not as argument
        log.log_debug(f"Executing Claude CLI: {' '.join(cmd)} (prompt length: {len(prompt)})")

        try:
            # Run the CLI asynchronously with stdin for prompt input
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            try:
                # Pass prompt via stdin to avoid shell escaping issues with special characters
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(input=prompt.encode('utf-8')),
                    timeout=self.timeout
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                raise APIProviderError(f"Claude CLI timed out after {self.timeout} seconds")

            if process.returncode != 0:
                error_msg = stderr.decode('utf-8', errors='replace').strip()
                if not error_msg:
                    error_msg = f"CLI exited with code {process.returncode}"

                # Check for common error patterns
                if "rate limit" in error_msg.lower():
                    raise RateLimitError(f"Claude rate limit: {error_msg}")
                elif "auth" in error_msg.lower() or "login" in error_msg.lower():
                    raise AuthenticationError(f"Claude authentication failed: {error_msg}")

                raise APIProviderError(f"Claude CLI error: {error_msg}")

            response = stdout.decode('utf-8', errors='replace').strip()
            log.log_debug(f"Claude CLI response length: {len(response)}")

            return response

        except FileNotFoundError:
            raise APIProviderError(f"Claude CLI not found at: {cli_path}")
        except PermissionError:
            raise APIProviderError(f"Permission denied executing Claude CLI: {cli_path}")

    async def chat_completion(self, request: ChatRequest,
                            native_message_callback: Optional[Callable[[Dict[str, Any], ProviderType], None]] = None) -> ChatResponse:
        """Generate non-streaming chat completion via Claude CLI"""
        log.log_info(f"Claude Code chat completion with {len(request.messages)} messages")

        # Format messages for CLI
        prompt = self._format_messages_for_cli(request.messages)

        # Execute CLI
        response_text = await self._run_claude_cli(prompt, request.tools)

        # Parse response for tool calls if tools were provided
        tool_calls = []
        if request.tools:
            tool_calls = self._extract_tool_calls(response_text)

        # Create usage estimate (CLI doesn't provide actual token counts)
        usage = Usage(
            prompt_tokens=len(prompt) // 4,  # Rough estimate
            completion_tokens=len(response_text) // 4,
            total_tokens=(len(prompt) + len(response_text)) // 4
        )

        # Call native message callback
        if native_message_callback:
            native_message = {
                "role": "assistant",
                "content": response_text,
                "tool_calls": [
                    {"id": tc.id, "name": tc.name, "arguments": tc.arguments}
                    for tc in tool_calls
                ] if tool_calls else [],
                "model": self.model,
                "provider": "anthropic_cli"
            }
            native_message_callback(native_message, self.get_provider_type())

        return ChatResponse(
            content=response_text,
            model=self.model,
            usage=usage,
            tool_calls=tool_calls,
            finish_reason="tool_calls" if tool_calls else "stop"
        )

    async def chat_completion_stream(self, request: ChatRequest,
                                   native_message_callback: Optional[Callable[[Dict[str, Any], ProviderType], None]] = None) -> AsyncGenerator[ChatResponse, None]:
        """
        Generate simulated streaming chat completion.

        Note: Claude CLI doesn't support true streaming, so we:
        1. Get the complete response from CLI
        2. Yield it in chunks to simulate streaming
        """
        log.log_info(f"Claude Code simulated streaming with {len(request.messages)} messages")

        # Get complete response first
        prompt = self._format_messages_for_cli(request.messages)
        response_text = await self._run_claude_cli(prompt, request.tools)

        # Parse tool calls if applicable
        tool_calls = []
        if request.tools:
            tool_calls = self._extract_tool_calls(response_text)

        # Simulate streaming by chunking the response
        content_length = len(response_text)
        chunks_sent = 0

        for i in range(0, content_length, self.stream_chunk_size):
            chunk = response_text[i:i + self.stream_chunk_size]
            chunks_sent += 1

            yield ChatResponse(
                content=chunk,
                model=self.model,
                usage=Usage(prompt_tokens=0, completion_tokens=0, total_tokens=0),
                tool_calls=[],
                finish_reason="",
                is_streaming=True
            )

            # Small delay between chunks for visual effect
            if self.stream_chunk_delay > 0:
                await asyncio.sleep(self.stream_chunk_delay)

        # Call native message callback with complete response
        if native_message_callback:
            native_message = {
                "role": "assistant",
                "content": response_text,
                "tool_calls": [
                    {"id": tc.id, "name": tc.name, "arguments": tc.arguments}
                    for tc in tool_calls
                ] if tool_calls else [],
                "model": self.model,
                "provider": "anthropic_cli",
                "streaming": True
            }
            native_message_callback(native_message, self.get_provider_type())

        # Final message with usage and finish reason
        usage = Usage(
            prompt_tokens=len(prompt) // 4,
            completion_tokens=len(response_text) // 4,
            total_tokens=(len(prompt) + len(response_text)) // 4
        )

        yield ChatResponse(
            content="",
            model=self.model,
            usage=usage,
            tool_calls=tool_calls,
            finish_reason="tool_calls" if tool_calls else "stop",
            is_streaming=False
        )

    def _extract_tool_calls(self, response_text: str) -> List[ToolCall]:
        """
        Extract tool calls from CLI response.

        The Claude CLI may output tool calls in various formats.
        This method attempts to parse them.
        """
        tool_calls = []

        # Try to find JSON tool call blocks in the response
        # Claude might output: {"tool_calls": [...]} or similar
        try:
            # First, try to parse the entire response as JSON
            data = json.loads(response_text)
            if isinstance(data, dict) and 'tool_calls' in data:
                for tc in data['tool_calls']:
                    tool_calls.append(ToolCall(
                        id=tc.get('id', f"call_{int(time.time() * 1000)}"),
                        name=tc.get('name', tc.get('function', {}).get('name', 'unknown')),
                        arguments=tc.get('arguments', tc.get('function', {}).get('arguments', {}))
                    ))
        except json.JSONDecodeError:
            pass

        # Try to find embedded JSON blocks that look like tool calls
        if not tool_calls:
            import re
            # Look for patterns like: <tool_call>{"name": "...", "arguments": {...}}</tool_call>
            tool_call_pattern = r'<tool_call>\s*({.*?})\s*</tool_call>'
            matches = re.findall(tool_call_pattern, response_text, re.DOTALL)

            for match in matches:
                try:
                    tc_data = json.loads(match)
                    tool_calls.append(ToolCall(
                        id=tc_data.get('id', f"call_{int(time.time() * 1000)}"),
                        name=tc_data.get('name', 'unknown'),
                        arguments=tc_data.get('arguments', {})
                    ))
                except json.JSONDecodeError:
                    continue

        return tool_calls

    async def generate_embeddings(self, request: EmbeddingRequest) -> EmbeddingResponse:
        """
        Generate embeddings - NOT SUPPORTED by Claude CLI.
        """
        raise NotImplementedError(
            "Claude Code CLI does not support embeddings. "
            "Use OpenAI or Ollama provider for embedding generation."
        )

    def get_capabilities(self) -> ProviderCapabilities:
        """Get provider capabilities"""
        return ProviderCapabilities(
            supports_chat=True,
            supports_streaming=False,  # Only simulated streaming
            supports_tools=True,
            supports_embeddings=False,
            supports_vision=False,  # CLI may support but not implemented
            max_tokens=self.max_tokens,
            models=[self.model] if self.model else ["sonnet", "opus", "haiku"]
        )

    def get_provider_type(self) -> ProviderType:
        """Get the provider type"""
        return ProviderType.ANTHROPIC_CLI

    def validate_config(self):
        """Validate provider configuration - relaxed for CLI-based provider"""
        if not self.name:
            raise ValueError("Provider name is required")
        if not self.model:
            self.model = 'sonnet'  # Default model
        # URL and API key are not required for CLI-based provider

    async def test_connection(self) -> bool:
        """Test connection by checking if claude CLI is available and working"""
        try:
            cli_path = self._find_claude_cli()
            if not cli_path:
                log.log_error("Claude CLI not found")
                return False

            # Try to get version
            process = await asyncio.create_subprocess_exec(
                cli_path, '--version',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=10
            )

            if process.returncode == 0:
                version = stdout.decode('utf-8', errors='replace').strip()
                log.log_info(f"Claude CLI version: {version}")
                return True
            else:
                error = stderr.decode('utf-8', errors='replace').strip()
                log.log_error(f"Claude CLI check failed: {error}")
                return False

        except asyncio.TimeoutError:
            log.log_error("Claude CLI version check timed out")
            return False
        except Exception as e:
            log.log_error(f"Claude CLI test failed: {e}")
            return False


# Factory for Claude Code provider
from .provider_factory import ProviderFactory
from ..models.provider_types import ProviderType

class AnthropicClaudeCliProviderFactory(ProviderFactory):
    """Factory for creating Anthropic Claude CLI provider instances"""

    def create_provider(self, config: Dict[str, Any]) -> AnthropicClaudeCliProvider:
        """Create Anthropic Claude CLI provider instance"""
        return AnthropicClaudeCliProvider(config)

    def supports_provider_type(self, provider_type: ProviderType) -> bool:
        """Check if this factory supports the provider type"""
        return provider_type == ProviderType.ANTHROPIC_CLI
