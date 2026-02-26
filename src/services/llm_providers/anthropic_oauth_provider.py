#!/usr/bin/env python3

"""
Anthropic Experimental Provider - OAuth authentication for Claude Pro/Max subscriptions

This provider uses OAuth PKCE authentication to access the Anthropic API using
Claude Pro/Max subscriptions, replicating the authentication flow used by
Claude Code and OpenCode.

Key Features:
- OAuth PKCE authentication (no API key required)
- Automatic token refresh
- Two-step warmup sequence (required by API)
- Claude Code-style request formatting
- Tool name prefixing (mcp_)

Requirements:
- User must have Claude Pro or Claude Max subscription
- Browser access for OAuth authorization flow
- aiohttp package for async HTTP requests

Based on the opencode-anthropic-auth package implementation.
"""

import asyncio
import base64
import hashlib
import json
import re
import math
import secrets
import time
import webbrowser
from collections import Counter
from typing import List, Dict, Any, AsyncGenerator, Optional, Callable

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    aiohttp = None
    AIOHTTP_AVAILABLE = False

from .base_provider import (
    BaseLLMProvider, APIProviderError, AuthenticationError,
    RateLimitError, NetworkError
)
from ..models.llm_models import (
    ChatRequest, ChatResponse, EmbeddingRequest, EmbeddingResponse,
    ChatMessage, MessageRole, ToolCall, ToolResult, Usage, ProviderCapabilities
)
from ..models.provider_types import ProviderType
from ..models.reasoning_models import ReasoningConfig

from src.ida_compat import log


# ============================================================================
# OAuth Configuration - From opencode-anthropic-auth package
# ============================================================================

# Official Anthropic OAuth Client ID (from Claude Code/OpenCode)
OAUTH_CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"

# OAuth endpoints
OAUTH_AUTH_URL = "https://claude.ai/oauth/authorize"
OAUTH_TOKEN_URL = "https://console.anthropic.com/v1/oauth/token"
OAUTH_REDIRECT_URI = "https://console.anthropic.com/oauth/code/callback"
OAUTH_SCOPES = "user:profile user:inference user:sessions:claude_code"

# Anthropic API
ANTHROPIC_API_URL = "https://api.anthropic.com"

# Required system prompt prefix for Claude Code OAuth requests
CLAUDE_CODE_SYSTEM_PREFIX = "You are a Claude agent, built on Anthropic's Claude Agent SDK."

# Tool name prefix required by OAuth API
TOOL_PREFIX = "mcp_"

# Minimal stub tools - required for OAuth API requests
MINIMAL_STUB_TOOLS = [
    {
        "name": "Task",
        "description": "Launch a task to perform work",
        "input_schema": {
            "type": "object",
            "properties": {
                "prompt": {"type": "string", "description": "The task prompt"}
            },
            "required": ["prompt"]
        }
    },
    {
        "name": "Bash",
        "description": "Execute bash commands",
        "input_schema": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "The command to run"}
            },
            "required": ["command"]
        }
    },
    {
        "name": "Read",
        "description": "Read file contents",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "File path to read"}
            },
            "required": ["path"]
        }
    }
]


class AnthropicOAuthProvider(BaseLLMProvider):
    """
    Anthropic Experimental Provider with OAuth authentication.

    Uses OAuth PKCE flow to authenticate with Claude Pro/Max subscriptions,
    bypassing the need for API keys. This replicates the authentication
    mechanism used by Claude Code and OpenCode.

    Key differences from standard AnthropicPlatformApiProvider:
    - Uses OAuth tokens instead of API keys
    - Requires two-step warmup sequence before first request
    - Must include Claude Code system prompt prefix in all requests
    - Must include tools array in all requests (uses stub tools if none provided)
    - Tool names must be prefixed with 'mcp_'
    - Uses special headers and beta flags
    """

    # Provider name for credential storage
    PROVIDER_NAME = "anthropic_oauth"

    def __init__(self, config: Dict[str, Any]):
        """Initialize Anthropic Experimental provider"""
        super().__init__(config)

        # Validate aiohttp is available
        if not AIOHTTP_AVAILABLE:
            raise ImportError("aiohttp package required for Anthropic Experimental provider. Install with: pip install aiohttp")

        # Session management
        self._session = None  # Type: Optional[aiohttp.ClientSession]

        # OAuth state
        self._warmed_up = False
        self._credentials = None  # Cached credentials
        self._pending_pkce_verifier = None  # Store verifier between auth steps
        self._pending_auth_code = None  # Store auth code from dialog for async completion

        # Parse OAuth credentials from api_key field (JSON format)
        # The api_key is set by ProviderDialog.on_authenticate_clicked()
        api_key = config.get('api_key', '')
        if api_key:
            try:
                from .oauth_utils import parse_credentials_json
                self._credentials = parse_credentials_json(api_key)
                if self._credentials:
                    log.log_info("Loaded OAuth credentials from api_key field")
            except Exception as e:
                log.log_warn(f"Failed to parse OAuth credentials from api_key: {e}")

        log.log_info(f"Anthropic Experimental provider initialized with model: {self.model}")

    # =========================================================================
    # Session Management
    # =========================================================================

    async def _get_session(self):
        """Get or create aiohttp session. Returns aiohttp.ClientSession."""
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=120)
            self._session = aiohttp.ClientSession(timeout=timeout)
        return self._session

    async def close(self):
        """Close the HTTP session"""
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None

    # =========================================================================
    # OAuth PKCE Authentication
    # =========================================================================

    def _generate_pkce(self) -> tuple[str, str]:
        """
        Generate PKCE code verifier and challenge.
        Returns: (verifier, challenge)
        """
        # Generate random verifier (43 characters)
        verifier = secrets.token_urlsafe(32)

        # Generate SHA-256 challenge
        challenge_bytes = hashlib.sha256(verifier.encode()).digest()
        challenge = base64.urlsafe_b64encode(challenge_bytes).rstrip(b"=").decode()

        return verifier, challenge

    def _generate_state(self) -> str:
        """Generate a random state parameter for CSRF protection"""
        return secrets.token_urlsafe(32)

    def _build_authorize_url(self, pkce_challenge: str, state: str) -> str:
        """Build the OAuth authorization URL"""
        from urllib.parse import urlencode

        params = {
            "code": "true",  # Request authorization code display
            "client_id": OAUTH_CLIENT_ID,
            "response_type": "code",
            "redirect_uri": OAUTH_REDIRECT_URI,
            "scope": OAUTH_SCOPES,
            "code_challenge": pkce_challenge,
            "code_challenge_method": "S256",
            "state": state,
        }

        return f"{OAUTH_AUTH_URL}?{urlencode(params)}"

    async def _exchange_code_for_tokens(self, code: str, verifier: str, state: str) -> Dict[str, Any]:
        """Exchange authorization code for OAuth tokens"""
        session = await self._get_session()

        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": OAUTH_REDIRECT_URI,
            "client_id": OAUTH_CLIENT_ID,
            "code_verifier": verifier,
            "state": state,
        }

        async with session.post(
            OAUTH_TOKEN_URL,
            json=data,
            headers={"Content-Type": "application/json"},
        ) as response:
            if not response.ok:
                text = await response.text()
                raise AuthenticationError(f"Token exchange failed: {response.status} - {text}")
            return await response.json()

    async def _refresh_access_token(self, refresh_token: str) -> Dict[str, Any]:
        """Refresh the access token using refresh token"""
        session = await self._get_session()

        data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": OAUTH_CLIENT_ID,
        }

        async with session.post(
            OAUTH_TOKEN_URL,
            json=data,
            headers={"Content-Type": "application/json"},
        ) as response:
            if not response.ok:
                text = await response.text()
                raise AuthenticationError(f"Token refresh failed: {response.status} - {text}")
            return await response.json()

    def start_authentication(self) -> str:
        """
        Start OAuth authentication by opening browser.

        Returns the authorization URL that was opened.
        The user should then call complete_authentication() with the code.
        """
        # Generate PKCE codes and state, store for later
        verifier, challenge = self._generate_pkce()
        state = self._generate_state()
        self._pending_pkce_verifier = verifier
        self._pending_oauth_state = state

        # Build authorization URL and open browser
        auth_url = self._build_authorize_url(challenge, state)
        log.log_info(f"Opening browser for OAuth authorization...")
        webbrowser.open(auth_url)

        return auth_url

    async def complete_authentication(self, auth_code: str, returned_state: str = None) -> bool:
        """
        Complete OAuth authentication with the authorization code.

        NOTE: This method is now deprecated. Authentication should be done via
        ProviderDialog.on_authenticate_clicked() which stores the credentials
        in the api_key field. This method is kept for backward compatibility.

        Args:
            auth_code: Authorization code from the OAuth callback
            returned_state: State parameter from callback (optional, uses stored state if not provided)

        Returns:
            True if authentication successful
        """
        if not self._pending_pkce_verifier:
            raise AuthenticationError(
                "No pending authentication. Call start_authentication() first."
            )

        try:
            verifier = self._pending_pkce_verifier
            state = returned_state or getattr(self, '_pending_oauth_state', '')
            self._pending_pkce_verifier = None  # Clear pending state
            self._pending_oauth_state = None

            # Exchange code for tokens
            tokens = await self._exchange_code_for_tokens(auth_code, verifier, state)

            if tokens.get("error"):
                raise AuthenticationError(
                    f"Token exchange failed: {tokens.get('error_description', tokens['error'])}"
                )

            # Calculate expiry time
            expires_at = time.time() + tokens.get("expires_in", 3600)

            # Cache credentials (not persisted - use ProviderDialog for persistent storage)
            self._credentials = {
                "access_token": tokens["access_token"],
                "refresh_token": tokens["refresh_token"],
                "expires_at": expires_at
            }

            # Reset warmup state for new credentials
            self._warmed_up = False

            log.log_info("OAuth authentication successful!")
            return True

        except Exception as e:
            log.log_error(f"OAuth authentication failed: {e}")
            raise

    def is_authenticated(self) -> bool:
        """Check if valid OAuth credentials exist"""
        credentials = self._get_credentials()
        return credentials is not None and bool(credentials.get("access_token"))

    def _get_credentials(self) -> Optional[Dict[str, Any]]:
        """
        Get cached OAuth credentials.

        Credentials are loaded from api_key field (JSON) during __init__.
        """
        if self._credentials:
            token = self._credentials.get('access_token', '')
            log.log_debug(f"Using cached credentials (token length: {len(token)})")
            return self._credentials

        return None

    async def _ensure_valid_token(self) -> str:
        """Ensure we have a valid access token, refreshing if needed"""
        credentials = self._get_credentials()

        if credentials is None:
            raise AuthenticationError(
                "Not authenticated. Please authenticate with your Claude Pro/Max subscription first."
            )

        # Check if token is expired (with 5 minute buffer)
        if time.time() >= credentials.get("expires_at", 0) - 300:
            log.log_info("Access token expired, refreshing...")

            try:
                tokens = await self._refresh_access_token(credentials["refresh_token"])

                # Update cached credentials
                expires_at = time.time() + tokens.get("expires_in", 3600)

                self._credentials = {
                    "access_token": tokens["access_token"],
                    "refresh_token": tokens.get("refresh_token", credentials["refresh_token"]),
                    "expires_at": expires_at
                }

                log.log_info("Access token refreshed successfully")

            except Exception as e:
                log.log_error(f"Token refresh failed: {e}")
                # Clear invalid credentials - user will need to re-authenticate via Settings UI
                self._credentials = None
                raise AuthenticationError(
                    "Session expired. Please re-authenticate via Settings > Edit Provider > Authenticate."
                )

        return self._credentials["access_token"]

    async def logout(self) -> None:
        """Clear cached OAuth credentials"""
        self._credentials = None
        self._warmed_up = False
        log.log_info("OAuth credentials cleared")

    # =========================================================================
    # Warmup Sequence
    # =========================================================================

    async def _perform_warmup(self) -> bool:
        """
        Perform the two-step warmup sequence required for OAuth API calls.

        The Claude Code API requires a warmup before allowing claude-code-20250219
        beta requests:
        1. Simple quota check with haiku model (no claude-code beta)
        2. Token counting request with tools (includes claude-code beta)

        Returns:
            True if warmup successful
        """
        if self._warmed_up:
            return True

        log.log_info("Performing OAuth warmup sequence...")

        try:
            # Step 1: Quota check (no claude-code-20250219)
            log.log_debug("Warmup step 1/2: quota check...")
            await self._warmup_quota_check()

            # Step 2: Token counting with tools (includes claude-code-20250219)
            log.log_debug("Warmup step 2/2: token count with tools...")
            await self._warmup_token_count()

            self._warmed_up = True
            log.log_info("OAuth warmup completed successfully")
            return True

        except Exception as e:
            log.log_error(f"OAuth warmup failed: {e}")
            return False

    async def _warmup_quota_check(self) -> None:
        """Step 1: Simple quota check request (no claude-code beta)"""
        session = await self._get_session()
        access_token = await self._ensure_valid_token()

        # Debug: Log token details
        log.log_info(f"[WARMUP DEBUG] Token length: {len(access_token)}")
        log.log_info(f"[WARMUP DEBUG] Token prefix: {access_token[:30]}...")
        log.log_info(f"[WARMUP DEBUG] Token suffix: ...{access_token[-20:]}")

        headers = {
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
            "accept": "application/json",
            "authorization": f"Bearer {access_token}",
            "anthropic-beta": "oauth-2025-04-20,interleaved-thinking-2025-05-14",
            "anthropic-dangerous-direct-browser-access": "true",
            "user-agent": "claude-cli/2.1.6 (external, sdk-cli)",
            "x-app": "cli",
        }

        # Add stainless headers for compatibility
        headers.update(self._get_stainless_headers())

        data = {
            "model": "claude-haiku-4-5-20251001",
            "max_tokens": 1,
            "messages": [{"role": "user", "content": "quota"}],
            "metadata": {"user_id": self._generate_user_id()}
        }

        url = f"{ANTHROPIC_API_URL}/v1/messages?beta=true"

        # Debug: Log full request details
        log.log_info(f"[WARMUP DEBUG] URL: {url}")
        log.log_info(f"[WARMUP DEBUG] Headers (excluding token): {[(k,v) for k,v in headers.items() if k != 'authorization']}")
        log.log_info(f"[WARMUP DEBUG] Auth header: Bearer {access_token[:30]}...")
        log.log_info(f"[WARMUP DEBUG] Data: {data}")

        async with session.post(url, json=data, headers=headers) as response:
            if not response.ok:
                text = await response.text()
                log.log_error(f"[WARMUP DEBUG] Response status: {response.status}")
                log.log_error(f"[WARMUP DEBUG] Response text: {text}")
                raise APIProviderError(f"Warmup quota check failed: {response.status} - {text}")
            else:
                log.log_info(f"[WARMUP DEBUG] Warmup step 1 succeeded!")

    async def _warmup_token_count(self) -> None:
        """Step 2: Token counting request with tools (includes claude-code beta)"""
        session = await self._get_session()
        access_token = await self._ensure_valid_token()

        headers = {
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
            "accept": "application/json",
            "authorization": f"Bearer {access_token}",
            "anthropic-beta": "claude-code-20250219,oauth-2025-04-20,interleaved-thinking-2025-05-14,token-counting-2024-11-01",
            "anthropic-dangerous-direct-browser-access": "true",
            "user-agent": "claude-cli/2.1.6 (external, sdk-cli)",
            "x-app": "cli",
        }

        headers.update(self._get_stainless_headers())

        # IMPORTANT: Tools in token count request do NOT use mcp_ prefix
        # This matches the working anthropic_oauth_client.py behavior
        tools = [
            {
                "name": "Task",
                "description": "Launch a task",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "prompt": {"type": "string"}
                    },
                    "required": ["prompt"]
                }
            }
        ]

        data = {
            "model": "claude-opus-4-5-20251101",
            "messages": [{"role": "user", "content": "foo"}],
            "tools": tools,
        }

        url = f"{ANTHROPIC_API_URL}/v1/messages/count_tokens?beta=true"

        log.log_debug(f"[WARMUP DEBUG] Token count URL: {url}")
        log.log_debug(f"[WARMUP DEBUG] Token count tools: {[t.get('name') for t in tools]}")

        async with session.post(url, json=data, headers=headers) as response:
            if not response.ok:
                text = await response.text()
                log.log_error(f"[WARMUP DEBUG] Token count failed: {response.status} - {text}")
                raise APIProviderError(f"Warmup token count failed: {response.status} - {text}")
            log.log_debug("[WARMUP DEBUG] Token count succeeded!")

    # =========================================================================
    # Request Helpers
    # =========================================================================

    def _get_stainless_headers(self) -> Dict[str, str]:
        """Get Stainless SDK headers for API compatibility"""
        return {
            "x-stainless-arch": "x64",
            "x-stainless-lang": "js",
            "x-stainless-os": "Linux",
            "x-stainless-package-version": "0.70.0",
            "x-stainless-retry-count": "0",
            "x-stainless-runtime": "node",
            "x-stainless-runtime-version": "v22.20.0",
            "x-stainless-timeout": "600",
        }

    def _generate_user_id(self) -> str:
        """Generate a user ID in Claude Code format"""
        user_hash = hashlib.sha256(b"binassist_experimental").hexdigest()
        return f"user_{user_hash}_account_00000000-0000-0000-0000-000000000000_session_00000000-0000-0000-0000-000000000000"

    def _add_tool_prefix(self, tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Add mcp_ prefix to tool names for OAuth API compatibility"""
        if not tools:
            return tools

        prefixed_tools = []
        for tool in tools:
            tool_copy = tool.copy()
            name = tool_copy.get("name", "")
            if not name.startswith(TOOL_PREFIX):
                tool_copy["name"] = f"{TOOL_PREFIX}{name}"
            prefixed_tools.append(tool_copy)

        return prefixed_tools

    def _remove_tool_prefix(self, text: str) -> str:
        """Remove mcp_ prefix from tool names in response"""
        return re.sub(r'"name"\s*:\s*"mcp_([^"]+)"', r'"name": "\1"', text)

    def _prepare_system_prompt(self, original_system: Optional[str]) -> str:
        """Prepare system prompt with required Claude Code prefix"""
        # TEMPORARY TEST: Only use Claude Code prefix, ignore BinAssist system prompt
        # to test if the system prompt content is causing the OAuth rejection
        log.log_info(f"[SYSTEM PROMPT DEBUG] Ignoring original system prompt for test")
        return CLAUDE_CODE_SYSTEM_PREFIX
        # Original code:
        # if original_system:
        #     return f"{CLAUDE_CODE_SYSTEM_PREFIX}\n\n{original_system}"
        # return CLAUDE_CODE_SYSTEM_PREFIX

    def _prepare_tools(self, request_tools: Optional[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        """Prepare tools array - use provided tools or stub tools"""
        if request_tools:
            # Convert OpenAI format to Anthropic format and add prefix
            anthropic_tools = self._convert_tools_to_anthropic(request_tools)
            return self._add_tool_prefix(anthropic_tools)
        else:
            # Use minimal stub tools
            return self._add_tool_prefix(MINIMAL_STUB_TOOLS)

    def _convert_tools_to_anthropic(self, tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Convert OpenAI tool format to Anthropic tool format"""
        anthropic_tools = []

        for tool in tools:
            if tool.get("type") == "function":
                function = tool.get("function", {})
                anthropic_tool = {
                    "name": function.get("name", ""),
                    "description": function.get("description", ""),
                    "input_schema": function.get("parameters", {})
                }
                anthropic_tools.append(anthropic_tool)
            elif "name" in tool and "input_schema" in tool:
                # Already in Anthropic format
                anthropic_tools.append(tool)

        return anthropic_tools

    async def _get_oauth_headers(self) -> Dict[str, str]:
        """Get OAuth-specific headers for API requests"""
        access_token = await self._ensure_valid_token()

        headers = {
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
            "accept": "application/json",
            "authorization": f"Bearer {access_token}",
            "anthropic-beta": "claude-code-20250219,oauth-2025-04-20,interleaved-thinking-2025-05-14",
            "anthropic-dangerous-direct-browser-access": "true",
            "user-agent": "claude-cli/2.1.6 (external, sdk-cli)",
            "x-app": "cli",
        }

        headers.update(self._get_stainless_headers())

        return headers

    # =========================================================================
    # Chat Completion
    # =========================================================================

    async def chat_completion(self, request: ChatRequest,
                            native_message_callback: Optional[Callable[[Dict, ProviderType], None]] = None) -> ChatResponse:
        """Generate non-streaming chat completion with OAuth and rate limit retry"""
        # Authentication must be done via Settings UI before using this provider
        if not self.is_authenticated():
            raise AuthenticationError(
                "Not authenticated. Please go to Settings > Edit Provider > Authenticate "
                "to sign in with your Claude Pro/Max subscription."
            )

        return await self._with_rate_limit_retry(self._chat_completion_impl, request, native_message_callback)

    async def _chat_completion_impl(self, request: ChatRequest,
                            native_message_callback: Optional[Callable[[Dict[str, Any], ProviderType], None]] = None) -> ChatResponse:
        """Internal implementation of chat completion"""

        # Ensure authenticated
        if not self.is_authenticated():
            raise AuthenticationError(
                "Not authenticated. Please authenticate with your Claude Pro/Max subscription."
            )

        # Ensure warmup is done
        if not self._warmed_up:
            if not await self._perform_warmup():
                raise APIProviderError("OAuth warmup failed. Please try again.")

        try:
            session = await self._get_session()
            headers = await self._get_oauth_headers()

            # Prepare messages in Anthropic format
            anthropic_messages = self._prepare_messages(request.messages)

            # Prepare system prompt (with Claude Code prefix)
            original_system = self._extract_system_message(request.messages)
            system_prompt = self._prepare_system_prompt(original_system)

            # Prepare tools (use request tools or stub tools)
            tools = self._prepare_tools(request.tools)

            # Build payload
            payload = {
                "model": request.model or self.model,
                "messages": anthropic_messages,
                "max_tokens": min(request.max_tokens, self.max_tokens),
                "stream": False,
                "system": system_prompt,
                "tools": tools,
                "metadata": {"user_id": self._generate_user_id()}
            }

            # Handle temperature/top_p (Anthropic doesn't allow both)
            reasoning_effort = self.config.get('reasoning_effort', 'none')
            thinking_enabled = reasoning_effort and reasoning_effort != 'none'

            if thinking_enabled:
                payload["temperature"] = 1
            elif request.temperature is not None:
                payload["temperature"] = request.temperature
            elif request.top_p is not None:
                payload["top_p"] = request.top_p

            if request.stop:
                payload["stop_sequences"] = request.stop if isinstance(request.stop, list) else [request.stop]

            # Add extended thinking if configured
            if thinking_enabled:
                reasoning_config = ReasoningConfig.from_string(reasoning_effort)
                reasoning_config.max_tokens = min(request.max_tokens, self.max_tokens)
                budget = reasoning_config.get_anthropic_budget()
                if budget and budget > 0:
                    payload["thinking"] = {
                        "type": "enabled",
                        "budget_tokens": budget
                    }

            url = f"{ANTHROPIC_API_URL}/v1/messages?beta=true"

            # Debug: Log non-streaming request details (same as streaming)
            log.log_info(f"[NON-STREAM DEBUG] URL: {url}")
            log.log_info(f"[NON-STREAM DEBUG] Headers beta: {headers.get('anthropic-beta')}")
            log.log_info(f"[NON-STREAM DEBUG] Model: {payload.get('model')}")
            log.log_info(f"[NON-STREAM DEBUG] Num messages: {len(payload.get('messages', []))}")
            log.log_info(f"[NON-STREAM DEBUG] Has system: {bool(payload.get('system'))}")
            log.log_info(f"[NON-STREAM DEBUG] System prefix: {payload.get('system', '')[:80]}...")
            log.log_info(f"[NON-STREAM DEBUG] Num tools: {len(payload.get('tools', []))}")
            log.log_info(f"[NON-STREAM DEBUG] Tool names: {[t.get('name') for t in payload.get('tools', [])]}")
            log.log_info(f"[NON-STREAM DEBUG] Has metadata: {bool(payload.get('metadata'))}")

            async with session.post(url, json=payload, headers=headers) as response:
                if not response.ok:
                    text = await response.text()
                    await self._handle_error_response(response.status, text)

                response_data = await response.json()

            # Extract content, tool calls, and build native content blocks
            content = ""
            tool_calls = []
            native_content_blocks = []

            for content_block in response_data.get("content", []):
                block_type = content_block.get("type")

                if block_type == "text":
                    content += content_block.get("text", "")
                    native_content_blocks.append({"type": "text", "text": content_block.get("text", "")})

                elif block_type == "thinking":
                    native_content_blocks.append({
                        "type": "thinking",
                        "thinking": content_block.get("thinking", ""),
                        "signature": content_block.get("signature")
                    })

                elif block_type == "tool_use":
                    # Remove mcp_ prefix from tool name
                    tool_name = content_block.get("name", "")
                    if tool_name.startswith(TOOL_PREFIX):
                        tool_name = tool_name[len(TOOL_PREFIX):]

                    tool_call = ToolCall(
                        id=content_block.get("id", ""),
                        name=tool_name,
                        arguments=content_block.get("input", {})
                    )
                    tool_calls.append(tool_call)
                    native_content_blocks.append({
                        "type": "tool_use",
                        "id": content_block.get("id", ""),
                        "name": tool_name,
                        "input": content_block.get("input", {})
                    })

            # Call native message callback
            if native_message_callback:
                native_message = {
                    "role": "assistant",
                    "content": response_data.get("content", []),
                    "model": response_data.get("model", ""),
                    "id": response_data.get("id", ""),
                    "stop_reason": response_data.get("stop_reason", ""),
                    "usage": response_data.get("usage", {})
                }
                native_message_callback(native_message, self.get_provider_type())

            # Create usage info
            usage_data = response_data.get("usage", {})
            usage = Usage(
                prompt_tokens=usage_data.get("input_tokens", 0),
                completion_tokens=usage_data.get("output_tokens", 0),
                total_tokens=usage_data.get("input_tokens", 0) + usage_data.get("output_tokens", 0)
            )

            return ChatResponse(
                content=content,
                model=response_data.get("model", self.model),
                usage=usage,
                tool_calls=tool_calls if tool_calls else None,
                finish_reason=self._map_stop_reason(response_data.get("stop_reason", "")),
                response_id=response_data.get("id", ""),
                native_content=native_content_blocks if native_content_blocks else None
            )

        except AuthenticationError:
            raise
        except RateLimitError:
            raise
        except Exception as e:
            raise APIProviderError(f"Chat completion failed: {e}")

    async def _handle_error_response(self, status: int, text: str) -> None:
        """Handle API error responses"""
        log.log_error(f"[API ERROR DEBUG] Status: {status}")
        log.log_error(f"[API ERROR DEBUG] Response: {text[:500]}")

        error_lower = text.lower()

        if status == 401:
            # Token might be invalid - clear and require re-auth
            await self.logout()
            raise AuthenticationError("OAuth token invalid. Please re-authenticate.")
        elif status == 429 or "rate limit" in error_lower:
            raise RateLimitError(f"Rate limit exceeded: {text}")
        elif "credential is only authorized for use with claude code" in error_lower:
            # Warmup might have failed - retry warmup
            log.log_error(f"[API ERROR DEBUG] Claude Code credential error - warmed_up was: {self._warmed_up}")
            self._warmed_up = False
            raise APIProviderError(
                "OAuth request rejected. This usually means warmup failed. "
                "Please try again or re-authenticate."
            )
        elif status == 400:
            raise APIProviderError(f"Bad request: {text}")
        elif status == 403:
            raise AuthenticationError(f"Permission denied: {text}")
        else:
            raise APIProviderError(f"API error ({status}): {text}")

    # =========================================================================
    # Streaming Chat Completion
    # =========================================================================

    async def chat_completion_stream(self, request: ChatRequest,
                                   native_message_callback: Optional[Callable[[Dict, ProviderType], None]] = None) -> AsyncGenerator[ChatResponse, None]:
        """Generate streaming chat completion with OAuth and rate limit retry"""
        # Authentication must be done via Settings UI before using this provider
        if not self.is_authenticated():
            raise AuthenticationError(
                "Not authenticated. Please go to Settings > Edit Provider > Authenticate "
                "to sign in with your Claude Pro/Max subscription."
            )

        async for response in self._with_rate_limit_retry_stream(self._chat_completion_stream_impl, request, native_message_callback):
            yield response

    async def _chat_completion_stream_impl(self, request: ChatRequest,
                                   native_message_callback: Optional[Callable[[Dict[str, Any], ProviderType], None]] = None) -> AsyncGenerator[ChatResponse, None]:
        """Internal implementation of streaming chat completion"""

        # Ensure authenticated
        if not self.is_authenticated():
            raise AuthenticationError(
                "Not authenticated. Please authenticate with your Claude Pro/Max subscription."
            )

        # Ensure warmup is done
        if not self._warmed_up:
            if not await self._perform_warmup():
                raise APIProviderError("OAuth warmup failed. Please try again.")

        try:
            session = await self._get_session()
            headers = await self._get_oauth_headers()
            headers["accept"] = "text/event-stream"

            # Prepare messages in Anthropic format
            anthropic_messages = self._prepare_messages(request.messages)

            # Prepare system prompt (with Claude Code prefix)
            original_system = self._extract_system_message(request.messages)
            system_prompt = self._prepare_system_prompt(original_system)

            # Prepare tools (use request tools or stub tools)
            tools = self._prepare_tools(request.tools)

            # Build payload - NOTE: Do NOT include metadata for streaming
            # The working anthropic_oauth_client.py does not add metadata to streaming requests
            payload = {
                "model": request.model or self.model,
                "messages": anthropic_messages,
                "max_tokens": min(request.max_tokens, self.max_tokens),
                "stream": True,
                "system": system_prompt,
                "tools": tools
            }

            # Handle temperature/top_p
            reasoning_effort = self.config.get('reasoning_effort', 'none')
            thinking_enabled = reasoning_effort and reasoning_effort != 'none'

            if thinking_enabled:
                payload["temperature"] = 1
            elif request.temperature is not None:
                payload["temperature"] = request.temperature
            elif request.top_p is not None:
                payload["top_p"] = request.top_p

            if request.stop:
                payload["stop_sequences"] = request.stop if isinstance(request.stop, list) else [request.stop]

            # Add extended thinking if configured
            if thinking_enabled:
                reasoning_config = ReasoningConfig.from_string(reasoning_effort)
                reasoning_config.max_tokens = min(request.max_tokens, self.max_tokens)
                budget = reasoning_config.get_anthropic_budget()
                if budget and budget > 0:
                    payload["thinking"] = {
                        "type": "enabled",
                        "budget_tokens": budget
                    }

            url = f"{ANTHROPIC_API_URL}/v1/messages?beta=true"

            # Debug: Log streaming request details
            log.log_info(f"[STREAM DEBUG] URL: {url}")
            log.log_info(f"[STREAM DEBUG] Headers beta: {headers.get('anthropic-beta')}")
            log.log_info(f"[STREAM DEBUG] Model: {payload.get('model')}")
            log.log_info(f"[STREAM DEBUG] Num messages: {len(payload.get('messages', []))}")
            log.log_info(f"[STREAM DEBUG] Has system: {bool(payload.get('system'))}")
            log.log_info(f"[STREAM DEBUG] Num tools: {len(payload.get('tools', []))}")
            log.log_info(f"[STREAM DEBUG] Tool names: {[t.get('name') for t in payload.get('tools', [])]}")

            accumulated_content = ""
            tool_calls = []
            thinking_blocks = []
            building_tool_calls: Dict[str, Dict[str, Any]] = {}
            building_thinking: Dict[int, Dict[str, Any]] = {}

            async with session.post(url, json=payload, headers=headers) as response:
                if not response.ok:
                    text = await response.text()
                    await self._handle_error_response(response.status, text)

                async for line in response.content:
                    line = line.decode('utf-8').strip()

                    if not line.startswith("data: "):
                        continue

                    data_str = line[6:]
                    if data_str == "[DONE]":
                        break

                    try:
                        event = json.loads(data_str)
                    except json.JSONDecodeError:
                        continue

                    event_type = event.get("type", "")

                    if event_type == "content_block_delta":
                        delta = event.get("delta", {})

                        if delta.get("type") == "text_delta":
                            text_delta = delta.get("text", "")
                            if text_delta:
                                accumulated_content += text_delta
                                yield ChatResponse(
                                    content=text_delta,
                                    model=request.model or self.model,
                                    usage=Usage(0, 0, 0),
                                    is_streaming=True,
                                    finish_reason="incomplete"
                                )

                        elif delta.get("type") == "thinking_delta":
                            thinking_delta = delta.get("thinking", "")
                            if thinking_delta and "index" in event:
                                idx = event["index"]
                                if idx not in building_thinking:
                                    building_thinking[idx] = {"thinking": "", "signature": None}
                                building_thinking[idx]["thinking"] += thinking_delta

                        elif delta.get("type") == "input_json_delta":
                            partial_json = delta.get("partial_json", "")
                            if "index" in event:
                                for tid, td in building_tool_calls.items():
                                    if td.get("index") == event["index"]:
                                        td["input_json"] = td.get("input_json", "") + partial_json
                                        break

                    elif event_type == "content_block_start":
                        content_block = event.get("content_block", {})
                        block_type = content_block.get("type")

                        if block_type == "thinking":
                            idx = event.get("index", 0)
                            building_thinking[idx] = {
                                "thinking": content_block.get("thinking", ""),
                                "signature": content_block.get("signature")
                            }

                        elif block_type == "tool_use":
                            building_tool_calls[content_block.get("id", "")] = {
                                "id": content_block.get("id", ""),
                                "name": content_block.get("name", ""),
                                "input": content_block.get("input", {}),
                                "input_json": "",
                                "index": event.get("index")
                            }

                    elif event_type == "content_block_stop":
                        idx = event.get("index")

                        # Check if thinking block completed
                        if idx in building_thinking:
                            content_block = event.get("content_block", {})
                            if content_block.get("signature"):
                                building_thinking[idx]["signature"] = content_block["signature"]

                        # Check if tool call completed
                        for tid, td in list(building_tool_calls.items()):
                            if td.get("index") == idx:
                                final_input = td["input"]
                                if td.get("input_json"):
                                    try:
                                        final_input = json.loads(td["input_json"])
                                    except json.JSONDecodeError:
                                        pass

                                # Remove mcp_ prefix
                                tool_name = td["name"]
                                if tool_name.startswith(TOOL_PREFIX):
                                    tool_name = tool_name[len(TOOL_PREFIX):]

                                tool_calls.append(ToolCall(
                                    id=td["id"],
                                    name=tool_name,
                                    arguments=final_input
                                ))
                                del building_tool_calls[tid]
                                break

                    elif event_type == "message_stop":
                        # Extract thinking blocks
                        for idx in sorted(building_thinking.keys()):
                            thinking_blocks.append(building_thinking[idx])

            # Call native message callback
            if native_message_callback and (accumulated_content or tool_calls or thinking_blocks):
                content_blocks = []
                for tb in thinking_blocks:
                    content_blocks.append({
                        "type": "thinking",
                        "thinking": tb["thinking"],
                        "signature": tb.get("signature")
                    })
                if accumulated_content:
                    content_blocks.append({"type": "text", "text": accumulated_content})
                for tc in tool_calls:
                    content_blocks.append({
                        "type": "tool_use",
                        "id": tc.id,
                        "name": tc.name,
                        "input": tc.arguments
                    })

                native_message = {
                    "role": "assistant",
                    "content": content_blocks,
                    "model": request.model or self.model,
                    "streaming": True
                }
                native_message_callback(native_message, self.get_provider_type())

            # Final response
            if accumulated_content or tool_calls or thinking_blocks:
                final_content_blocks = []
                for tb in thinking_blocks:
                    final_content_blocks.append({
                        "type": "thinking",
                        "thinking": tb["thinking"],
                        "signature": tb.get("signature")
                    })
                if accumulated_content:
                    final_content_blocks.append({"type": "text", "text": accumulated_content})
                for tc in tool_calls:
                    final_content_blocks.append({
                        "type": "tool_use",
                        "id": tc.id,
                        "name": tc.name,
                        "input": tc.arguments
                    })

                yield ChatResponse(
                    content="",
                    model=request.model or self.model,
                    usage=Usage(0, 0, 0),
                    tool_calls=tool_calls if tool_calls else None,
                    is_streaming=False,
                    finish_reason="tool_calls" if tool_calls else "stop",
                    native_content=final_content_blocks if final_content_blocks else None
                )

        except AuthenticationError:
            raise
        except RateLimitError:
            raise
        except Exception as e:
            raise APIProviderError(f"Streaming chat completion failed: {e}")

    # =========================================================================
    # Message Formatting (adapted from AnthropicPlatformApiProvider)
    # =========================================================================

    def _prepare_messages(self, messages: List[ChatMessage]) -> List[Dict[str, Any]]:
        """Convert messages to Anthropic format"""
        anthropic_messages = []

        for message in messages:
            # Skip system messages - handled separately
            if message.role == MessageRole.SYSTEM:
                continue

            # Use native_content if available
            if message.native_content is not None:
                anthropic_msg = {
                    "role": "user" if message.role == MessageRole.USER else "assistant",
                    "content": message.native_content
                }
            else:
                anthropic_msg = {
                    "role": "user" if message.role == MessageRole.USER else "assistant",
                    "content": message.content
                }

                # Handle tool calls for assistant messages
                if message.tool_calls:
                    content = []
                    if message.content:
                        content.append({"type": "text", "text": message.content})

                    for tool_call in message.tool_calls:
                        # Add mcp_ prefix
                        tool_name = tool_call.name
                        if not tool_name.startswith(TOOL_PREFIX):
                            tool_name = f"{TOOL_PREFIX}{tool_name}"

                        content.append({
                            "type": "tool_use",
                            "id": tool_call.id,
                            "name": tool_name,
                            "input": tool_call.arguments
                        })

                    anthropic_msg["content"] = content

            # Handle tool responses
            if message.role == MessageRole.TOOL:
                anthropic_msg = {
                    "role": "user",
                    "content": [{
                        "type": "tool_result",
                        "tool_use_id": message.tool_call_id,
                        "content": message.content
                    }]
                }

            anthropic_messages.append(anthropic_msg)

        return anthropic_messages

    def _extract_system_message(self, messages: List[ChatMessage]) -> Optional[str]:
        """Extract system message content"""
        for message in messages:
            if message.role == MessageRole.SYSTEM:
                return message.content
        return None

    def _map_stop_reason(self, stop_reason: str) -> str:
        """Map Anthropic stop reasons to OpenAI format"""
        mapping = {
            "end_turn": "stop",
            "max_tokens": "length",
            "stop_sequence": "stop",
            "tool_use": "tool_calls"
        }
        return mapping.get(stop_reason, stop_reason)

    def format_tool_results_for_continuation(self, tool_calls: List[ToolCall], tool_results: List[str]) -> List[Dict[str, Any]]:
        """Format tool results for Anthropic conversation continuation"""
        messages = []

        if tool_calls and tool_results:
            content_blocks = []

            for tool_call, result in zip(tool_calls, tool_results):
                content_blocks.append({
                    "type": "tool_result",
                    "tool_use_id": tool_call.id,
                    "content": result
                })

            messages.append({
                "role": "user",
                "content": content_blocks
            })

        return messages

    # =========================================================================
    # Embeddings (TF-IDF fallback like AnthropicPlatformApiProvider)
    # =========================================================================

    async def generate_embeddings(self, request: EmbeddingRequest) -> EmbeddingResponse:
        """Generate embeddings using TF-IDF (OAuth API doesn't provide embeddings)"""
        try:
            embeddings = await asyncio.to_thread(self._generate_tfidf_embeddings, request.texts)

            total_tokens = sum(len(text.split()) for text in request.texts)
            usage = Usage(
                prompt_tokens=total_tokens,
                completion_tokens=0,
                total_tokens=total_tokens
            )

            return EmbeddingResponse(
                embeddings=embeddings,
                model=request.model,
                usage=usage,
                dimensions=len(embeddings[0]) if embeddings else 0
            )

        except Exception as e:
            raise APIProviderError(f"Error generating TF-IDF embeddings: {e}")

    def get_embeddings(self, texts: List[str]) -> List[List[float]]:
        """Synchronous wrapper for embeddings generation"""
        try:
            return self._generate_tfidf_embeddings(texts)
        except Exception as e:
            raise APIProviderError(f"Error generating TF-IDF embeddings: {e}")

    def _generate_tfidf_embeddings(self, texts: List[str]) -> List[List[float]]:
        """Generate TF-IDF embeddings as fallback"""
        if not hasattr(self, '_global_vocabulary'):
            self._global_vocabulary = {}
            self._global_tokenized_texts = []

        tokenized_texts = [self._tokenize(text) for text in texts]

        if len(texts) > 10 or not self._global_vocabulary:
            vocabulary = self._build_vocabulary(tokenized_texts)
            self._global_vocabulary = vocabulary
            self._global_tokenized_texts = tokenized_texts
        else:
            vocabulary = self._global_vocabulary

        embeddings = []
        for tokens in tokenized_texts:
            tfidf_vector = self._calculate_tfidf(tokens, self._global_tokenized_texts, vocabulary)
            embeddings.append(tfidf_vector)

        return embeddings

    def _tokenize(self, text: str) -> List[str]:
        """Simple tokenization for TF-IDF"""
        tokens = re.findall(r'\b\w+\b', text.lower())
        return tokens

    def _build_vocabulary(self, tokenized_texts: List[List[str]]) -> Dict[str, int]:
        """Build vocabulary from all texts"""
        word_counts = Counter()
        for tokens in tokenized_texts:
            word_counts.update(set(tokens))

        vocab_size = min(1000, len(word_counts))
        vocabulary = {}
        for i, (word, _) in enumerate(word_counts.most_common(vocab_size)):
            vocabulary[word] = i

        return vocabulary

    def _calculate_tfidf(self, tokens: List[str], all_tokenized_texts: List[List[str]],
                        vocabulary: Dict[str, int]) -> List[float]:
        """Calculate TF-IDF vector for a document"""
        vector = [0.0] * len(vocabulary)

        token_counts = Counter(tokens)
        total_tokens = len(tokens)

        for word, tf_count in token_counts.items():
            if word in vocabulary:
                tf = tf_count / total_tokens if total_tokens > 0 else 0
                df = sum(1 for doc_tokens in all_tokenized_texts if word in doc_tokens)
                idf = math.log(len(all_tokenized_texts) / df) if df > 0 else 0
                tfidf = tf * idf
                vector[vocabulary[word]] = tfidf

        # L2 normalization
        norm = math.sqrt(sum(x * x for x in vector))
        if norm > 0:
            vector = [x / norm for x in vector]

        return vector

    # =========================================================================
    # Provider Interface Methods
    # =========================================================================

    async def test_connection(self) -> bool:
        """Test OAuth token validity"""
        try:
            # Authentication must be done via Settings UI before testing
            if not self.is_authenticated():
                log.log_warn("Not authenticated - connection test failed")
                return False

            # Try to ensure valid token (may refresh if expired)
            await self._ensure_valid_token()

            # Try warmup if not done
            if not self._warmed_up:
                return await self._perform_warmup()

            return True

        except Exception as e:
            log.log_error(f"Connection test failed: {e}")
            return False

    def get_capabilities(self) -> ProviderCapabilities:
        """Get provider capabilities"""
        return ProviderCapabilities(
            supports_chat=True,
            supports_streaming=True,
            supports_tools=True,
            supports_embeddings=True,  # Via TF-IDF fallback
            supports_vision=False,
            max_tokens=self.max_tokens,
            models=[
                "claude-sonnet-4-20250514",
                "claude-haiku-4-5-20251001",
                "claude-opus-4-5-20251101"
            ]
        )

    def get_provider_type(self) -> ProviderType:
        """Get the provider type"""
        return ProviderType.ANTHROPIC_OAUTH

    def validate_config(self) -> bool:
        """Validate provider configuration - relaxed for OAuth provider"""
        if not self.name:
            raise ValueError("Provider name is required")
        if not self.model:
            raise ValueError("Model is required")
        # URL and API key are not required for OAuth provider
        return True

    async def count_tokens(self, request: ChatRequest) -> int:
        """
        Count tokens using Anthropic's token counting API.

        Note: Requires valid OAuth token and completed warmup.
        """
        try:
            if not self.is_authenticated():
                return await super().count_tokens(request)

            if not self._warmed_up:
                if not await self._perform_warmup():
                    return await super().count_tokens(request)

            session = await self._get_session()
            headers = await self._get_oauth_headers()
            headers["anthropic-beta"] = "claude-code-20250219,oauth-2025-04-20,interleaved-thinking-2025-05-14,token-counting-2024-11-01"

            anthropic_messages = self._prepare_messages(request.messages)
            original_system = self._extract_system_message(request.messages)
            system_prompt = self._prepare_system_prompt(original_system)
            tools = self._prepare_tools(request.tools)

            payload = {
                "model": request.model or self.model,
                "messages": anthropic_messages,
                "system": system_prompt,
                "tools": tools,
            }

            url = f"{ANTHROPIC_API_URL}/v1/messages/count_tokens?beta=true"

            async with session.post(url, json=payload, headers=headers) as response:
                if not response.ok:
                    log.log_warn(f"Token counting failed, using estimation")
                    return await super().count_tokens(request)

                data = await response.json()
                token_count = data.get("input_tokens", 0)
                log.log_debug(f"Anthropic Experimental token count: {token_count}")
                return token_count

        except Exception as e:
            log.log_warn(f"Token counting failed: {e}, using estimation")
            return await super().count_tokens(request)


# ============================================================================
# Provider Factory
# ============================================================================

from .provider_factory import ProviderFactory

class AnthropicOAuthProviderFactory(ProviderFactory):
    """Factory for creating Anthropic OAuth provider instances"""

    def create_provider(self, config: Dict[str, Any]) -> AnthropicOAuthProvider:
        """Create Anthropic OAuth provider instance"""
        return AnthropicOAuthProvider(config)

    def supports_provider_type(self, provider_type: ProviderType) -> bool:
        """Check if this factory supports the provider type"""
        return provider_type == ProviderType.ANTHROPIC_OAUTH
