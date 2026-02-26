#!/usr/bin/env python3

"""
LiteLLM Provider - Implementation for LiteLLM proxy API
Handles AWS Bedrock and other providers via LiteLLM proxy
"""

import asyncio
import json
from typing import List, Dict, Any, Optional, Callable, AsyncGenerator

try:
    import openai
except ImportError:
    raise ImportError("openai package not available. Install with: pip install openai")

from .openai_platform_api_provider import OpenAIPlatformApiProvider
from .base_provider import APIProviderError, AuthenticationError, RateLimitError, NetworkError
from ..models.llm_models import (
    ChatMessage, ChatRequest, ChatResponse, ToolCall, Usage, MessageRole
)
from ..models.provider_types import ProviderType
from ..models.reasoning_models import ReasoningConfig

from src.ida_compat import log


class LiteLLMProvider(OpenAIPlatformApiProvider):
    """
    LiteLLM provider for proxy access to AWS Bedrock and other models.

    Handles LiteLLM-specific quirks:
    1. Bedrock requires tools=[] even for no-tool calls
    2. Different thinking block message format for Bedrock Anthropic models
    3. Model-family-specific parameter handling

    Extends OpenAIPlatformApiProvider since LiteLLM uses OpenAI-compatible API.
    """

    def __init__(self, config: Dict[str, Any]):
        """Initialize LiteLLM provider"""
        # Initialize attributes BEFORE parent init (parent may access them)
        # We need model from config to detect family/bedrock
        self.model = config.get('model', '')
        self.model_family = self._detect_model_family()
        self.is_bedrock = self._is_bedrock_model()

        # Don't require API key for LiteLLM (depends on proxy config)
        # Override the OpenAI validation temporarily
        original_api_key = config.get('api_key', '')
        if not original_api_key:
            config['api_key'] = 'dummy-key-for-litellm'

        # Call parent init (will also set self.model from config)
        super().__init__(config)

        # Restore original api_key
        if not original_api_key:
            self.api_key = ''

        # Override timeout settings for LiteLLM/Bedrock
        # Bedrock can be significantly slower than direct API calls
        # Only recreate client if TLS is disabled (requires custom httpx client)
        timeout = 300.0
        log.log_info(f"LiteLLM: Using extended timeout of {timeout}s for reliability")

        if self.disable_tls:
            try:
                import httpx
                import ssl
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
                http_client = httpx.Client(verify=False, timeout=timeout)
                self._client.close()  # Close old client
                from openai import OpenAI
                self._client = OpenAI(
                    api_key=self.api_key or 'dummy',
                    base_url=self.url if self.url else None,
                    timeout=timeout,
                    max_retries=0,
                    http_client=http_client
                )
            except Exception as e:
                log.log_warn(f"Failed to update LiteLLM client for TLS bypass: {e}")
        else:
            # Don't recreate client - use the one from parent with default settings
            # This preserves better streaming behavior from the SDK defaults
            # Just update the timeout on the existing client
            try:
                self._client.timeout = timeout
            except Exception as e:
                log.log_debug(f"Could not update client timeout: {e}")

        # Use longer retry delays for LiteLLM/Bedrock (5s base instead of 2s)
        self.rate_limit_min_delay = 5.0
        self.rate_limit_max_delay = 15.0

        log.log_info(f"LiteLLM provider initialized for model: {self.model}")
        log.log_info(f"  Model family: {self.model_family}")
        log.log_info(f"  Is Bedrock: {self.is_bedrock}")
        log.log_info(f"  Retry delays: {self.rate_limit_min_delay}s - {self.rate_limit_max_delay}s")

    def _detect_model_family(self) -> str:
        """
        Detect underlying model family from model name.

        Examples:
        - bedrock/anthropic.claude-3-5-sonnet-20241022-v2:0 -> anthropic
        - bedrock-anthropic.claude-3-5-sonnet-20241022-v2:0 -> anthropic
        - bedrock-claude-sonnet-4-5 -> anthropic
        - bedrock/amazon.nova-pro-v1:0 -> amazon
        - bedrock/meta.llama3-70b-instruct-v1:0 -> meta
        - bedrock/gpt-oss-120b -> openai
        - claude-3-5-sonnet -> anthropic (non-Bedrock)
        - gpt-4o -> openai (non-Bedrock)

        Note: LiteLLM may use 'bedrock/' or 'bedrock-' prefix depending on configuration.
        """
        model_lower = self.model.lower()

        # Bedrock models: bedrock/<provider>.<model-name> or bedrock-<model-name>
        if self._is_bedrock_model():
            if 'anthropic' in model_lower or 'claude' in model_lower:
                return 'anthropic'
            elif 'amazon' in model_lower or 'nova' in model_lower:
                return 'amazon'
            elif 'meta' in model_lower or 'llama' in model_lower:
                return 'meta'
            elif 'cohere' in model_lower:
                return 'cohere'
            elif 'ai21' in model_lower:
                return 'ai21'
            elif 'gpt' in model_lower or 'openai' in model_lower:
                return 'openai'

        # Non-Bedrock LiteLLM models
        if 'claude' in model_lower or 'anthropic' in model_lower:
            return 'anthropic'
        elif 'gpt' in model_lower or 'openai' in model_lower:
            return 'openai'
        elif 'gemini' in model_lower or 'google' in model_lower:
            return 'google'
        elif 'llama' in model_lower or 'meta' in model_lower:
            return 'meta'

        return 'unknown'

    def _is_bedrock_model(self) -> bool:
        """
        Check if this is a Bedrock model.

        Supports both 'bedrock/' and 'bedrock-' prefixes for LiteLLM compatibility.
        """
        model_lower = self.model.lower()
        return model_lower.startswith('bedrock/') or model_lower.startswith('bedrock-')

    def _prepare_completion_kwargs(self, request: ChatRequest) -> Dict[str, Any]:
        """
        Prepare completion kwargs with LiteLLM/Bedrock quirks handled.

        Quirks:
        1. Bedrock requires tools=[] even when not using tools
        2. Bedrock Anthropic has different reasoning parameter handling
        """
        # Start with base kwargs from OpenAI provider logic
        openai_messages = self._prepare_messages(request.messages)

        completion_kwargs = {
            "model": self.model,
            "messages": openai_messages,
            "stream": request.stream
        }

        # Handle token limits
        if self._is_reasoning_model():
            completion_kwargs["max_completion_tokens"] = min(
                request.max_tokens or self.max_tokens, self.max_tokens
            )
        else:
            completion_kwargs["max_tokens"] = min(
                request.max_tokens or self.max_tokens, self.max_tokens
            )

            # Handle temperature
            reasoning_effort_str = self.config.get('reasoning_effort', 'none')
            thinking_enabled = reasoning_effort_str and reasoning_effort_str != 'none'

            if thinking_enabled:
                completion_kwargs["temperature"] = 1
                log.log_debug("LiteLLM: Thinking/reasoning enabled, forcing temperature=1")
            elif request.temperature is not None:
                completion_kwargs["temperature"] = request.temperature

        # Handle tools parameter
        # Get tools from request (may be None, [], or a list of tools)
        request_tools = getattr(request, 'tools', None)

        if request_tools:
            # Tools provided by orchestrator (either for actual use or for Bedrock compatibility)
            completion_kwargs["tools"] = request_tools
            log.log_debug(f"LiteLLM: Using {len(request_tools)} tools from request")
        # Note: Don't add empty tools array - it can interfere with streaming on some backends
        # The Bedrock compatibility quirk was causing streaming issues

        # Handle reasoning effort based on model family
        reasoning_effort_str = self.config.get('reasoning_effort', 'none')
        if reasoning_effort_str and reasoning_effort_str != 'none':
            if self.model_family == 'openai':
                # OpenAI models (including gpt-oss) support reasoning_effort parameter
                from ..models.reasoning_models import ReasoningConfig
                reasoning_config = ReasoningConfig.from_string(reasoning_effort_str)
                effort = reasoning_config.get_openai_reasoning_effort()
                if effort:
                    completion_kwargs["reasoning_effort"] = effort
                    log.log_info(f"LiteLLM: Using reasoning_effort={effort} for OpenAI model {self.model}")
            elif self.model_family == 'anthropic':
                # Anthropic models via LiteLLM need thinking params passed through extra_body
                # so they get forwarded to Bedrock/Anthropic backend
                from ..models.reasoning_models import ReasoningConfig
                reasoning_config = ReasoningConfig.from_string(reasoning_effort_str)
                budget_tokens = reasoning_config.get_anthropic_budget()
                if budget_tokens:
                    # Use extra_body to pass Anthropic-native parameters through the proxy
                    completion_kwargs["extra_body"] = completion_kwargs.get("extra_body", {})
                    completion_kwargs["extra_body"]["thinking"] = {
                        "type": "enabled",
                        "budget_tokens": budget_tokens
                    }
                    log.log_info(f"LiteLLM: Using thinking.budget_tokens={budget_tokens} for Anthropic model {self.model}")
            else:
                # Other model families - skip reasoning_effort
                log.log_debug(f"LiteLLM: Skipping reasoning_effort param for {self.model_family} model family")

        return completion_kwargs

    def _prepare_messages(self, messages: List[ChatMessage]) -> List[Dict[str, Any]]:
        """
        Convert BinAssist ChatMessage objects to LiteLLM format.

        LiteLLM expects OpenAI format and handles translation to backend formats
        (Anthropic, Bedrock, etc.) internally. We must use OpenAI format here.

        For Anthropic models with extended thinking, we must include thinking_blocks
        in assistant messages to satisfy Anthropic's requirement that assistant messages
        start with thinking blocks when thinking is enabled.
        """
        # Use OpenAI format - LiteLLM handles translation to Anthropic/Bedrock
        result = super()._prepare_messages(messages)

        # Check if thinking is enabled for Anthropic models
        reasoning_effort_str = self.config.get('reasoning_effort', 'none')
        thinking_enabled = (
            reasoning_effort_str and
            reasoning_effort_str != 'none' and
            self.model_family == 'anthropic'
        )

        # Enhance messages with thinking_blocks if present in native_content
        for i, msg in enumerate(messages):
            if msg.role == MessageRole.ASSISTANT and hasattr(msg, 'native_content') and msg.native_content:
                native = msg.native_content

                # Check for thinking_blocks in native_content
                if isinstance(native, dict):
                    thinking_blocks = native.get('thinking_blocks')
                    reasoning_content = native.get('reasoning_content')

                    if thinking_blocks:
                        result[i]['thinking_blocks'] = thinking_blocks
                        log.log_debug(f"LiteLLM: Added {len(thinking_blocks)} thinking_blocks to message {i}")

                    if reasoning_content:
                        result[i]['reasoning_content'] = reasoning_content
                        log.log_debug(f"LiteLLM: Added reasoning_content ({len(reasoning_content)} chars) to message {i}")

        # Debug: Log the messages being sent to LiteLLM
        log.log_info(f"LITELLM _prepare_messages DEBUG - {len(messages)} ChatMessages -> {len(result)} API messages:")
        for i, msg in enumerate(result):
            role = msg.get('role', 'unknown')
            content_preview = str(msg.get('content', ''))[:100]
            has_tool_calls = 'tool_calls' in msg
            has_tool_call_id = 'tool_call_id' in msg
            has_thinking = 'thinking_blocks' in msg or 'reasoning_content' in msg
            log.log_info(f"  [{i}] role={role}, has_tool_calls={has_tool_calls}, has_tool_call_id={has_tool_call_id}, has_thinking={has_thinking}, content={content_preview}...")
            if has_tool_calls:
                for tc in msg['tool_calls']:
                    log.log_info(f"       tool_call: id={tc.get('id', 'N/A')}, name={tc.get('function', {}).get('name', 'N/A')}")
            if has_tool_call_id:
                log.log_info(f"       tool_call_id={msg.get('tool_call_id')}, name={msg.get('name', 'N/A')}")
            if has_thinking:
                log.log_info(f"       thinking_blocks={len(msg.get('thinking_blocks', []))}, reasoning_content={len(msg.get('reasoning_content', '')) if msg.get('reasoning_content') else 0} chars")

        # Fix empty content in assistant messages with tool calls
        # Bedrock rejects content blocks with empty text (OpenAI format `content: ""`
        # becomes Bedrock format `content: [{"type": "text", "text": ""}]` which fails)
        for msg in result:
            if msg.get("role") == "assistant" and msg.get("tool_calls"):
                content = msg.get("content")
                if content is None or (isinstance(content, str) and not content.strip()):
                    msg["content"] = " "  # Minimal non-empty content
                    log.log_debug(f"LiteLLM: Fixed empty content in assistant message with tool calls")

        return result

    def get_provider_type(self) -> ProviderType:
        """Return LITELLM provider type"""
        return ProviderType.LITELLM

    def _is_reasoning_model(self) -> bool:
        """
        Check if the current model is a reasoning model.

        Extends parent to handle Bedrock model naming.
        """
        # Check if Bedrock model wraps a reasoning model
        if self.is_bedrock:
            model_lower = self.model.lower()
            # Bedrock doesn't currently support o* models, but future-proof
            if any(x in model_lower for x in ['o1', 'o2', 'o3', 'o4', 'gpt-5']):
                return True

        # Fall back to parent logic
        return super()._is_reasoning_model()

    async def _chat_completion_impl(self, request: ChatRequest,
                                    native_message_callback: Optional[Callable[[Dict[str, Any], ProviderType], None]] = None) -> ChatResponse:
        """Internal implementation of chat completion with LiteLLM/Bedrock quirks"""
        try:
            # Use our quirk-aware completion kwargs builder
            completion_kwargs = self._prepare_completion_kwargs(request)
            completion_kwargs["stream"] = False

            # Make API call
            response = self._client.chat.completions.create(**completion_kwargs)

            if not response.choices:
                raise APIProviderError("No choices in LiteLLM response")

            message = response.choices[0].message
            content = message.content or ""

            # Extract tool calls if present
            tool_calls = []
            if message.tool_calls:
                for tc in message.tool_calls:
                    try:
                        arguments = json.loads(tc.function.arguments) if tc.function.arguments else {}
                    except json.JSONDecodeError:
                        log.log_warn(f"Failed to parse tool call arguments: {tc.function.arguments}")
                        arguments = {}

                    tool_call = ToolCall(
                        id=tc.id,
                        name=tc.function.name,
                        arguments=arguments
                    )
                    tool_calls.append(tool_call)

            # Call native message callback with actual response
            if native_message_callback:
                choice = response.choices[0]
                native_message = {
                    "role": "assistant",
                    "content": choice.message.content,
                    "model": response.model,
                    "id": response.id,
                    "object": response.object,
                    "created": response.created,
                    "finish_reason": choice.finish_reason
                }

                if choice.message.tool_calls:
                    native_message["tool_calls"] = [
                        {
                            "id": tc.id,
                            "type": tc.type,
                            "function": {
                                "name": tc.function.name,
                                "arguments": tc.function.arguments
                            }
                        }
                        for tc in choice.message.tool_calls
                    ]

                # Capture thinking blocks from LiteLLM response (Anthropic models)
                # LiteLLM returns these fields for Anthropic extended thinking
                if hasattr(choice.message, 'reasoning_content') and choice.message.reasoning_content:
                    native_message["reasoning_content"] = choice.message.reasoning_content
                    log.log_info(f"LiteLLM: Captured reasoning_content ({len(choice.message.reasoning_content)} chars)")

                if hasattr(choice.message, 'thinking_blocks') and choice.message.thinking_blocks:
                    native_message["thinking_blocks"] = choice.message.thinking_blocks
                    log.log_info(f"LiteLLM: Captured {len(choice.message.thinking_blocks)} thinking_blocks")

                if response.usage:
                    native_message["usage"] = {
                        "prompt_tokens": response.usage.prompt_tokens,
                        "completion_tokens": response.usage.completion_tokens,
                        "total_tokens": response.usage.total_tokens
                    }

                native_message_callback(native_message, self.get_provider_type())

            # Calculate usage
            usage = None
            if response.usage:
                usage = Usage(
                    prompt_tokens=response.usage.prompt_tokens,
                    completion_tokens=response.usage.completion_tokens,
                    total_tokens=response.usage.total_tokens
                )

            # Build native_content with thinking blocks for ReAct to capture
            # (same data that goes to native_message_callback, but embedded in ChatResponse)
            native_content_for_response = {}
            choice = response.choices[0]
            if hasattr(choice.message, 'reasoning_content') and choice.message.reasoning_content:
                native_content_for_response["reasoning_content"] = choice.message.reasoning_content
            if hasattr(choice.message, 'thinking_blocks') and choice.message.thinking_blocks:
                native_content_for_response["thinking_blocks"] = choice.message.thinking_blocks

            return ChatResponse(
                content=content,
                model=self.model,
                usage=usage,
                tool_calls=tool_calls,
                finish_reason=response.choices[0].finish_reason or "stop",
                native_content=native_content_for_response if native_content_for_response else None
            )

        except openai.AuthenticationError as e:
            log.log_error(f"Authentication error: {e}")
            raise AuthenticationError(f"LiteLLM authentication failed: {e}")
        except openai.RateLimitError as e:
            log.log_error(f"Rate limit error: {e}")
            raise RateLimitError(f"LiteLLM rate limit exceeded: {e}")
        except openai.APITimeoutError as e:
            # Timeouts are common with Bedrock due to slow inference and throttling
            log.log_warn(f"LiteLLM request timeout (may be Bedrock throttling): {e}")
            raise NetworkError(f"LiteLLM request timed out: {e}")
        except openai.APIConnectionError as e:
            log.log_error(f"Connection error: {e}")
            # Check if this might be throttling
            error_str = str(e).lower()
            if any(keyword in error_str for keyword in ['throttl', 'too many requests', '429', 'rate limit']):
                log.log_warn("Detected potential throttling - will retry with backoff")
                raise RateLimitError(f"LiteLLM throttled: {e}")
            raise NetworkError(f"LiteLLM connection failed: {e}")
        except openai.BadRequestError as e:
            # Enhanced error handling for Bedrock-specific errors
            error_message = str(e)
            if "doesn't support tool use in streaming mode" in error_message:
                log.log_error(
                    f"Bedrock streaming+tools error: {e}. "
                    "This should be handled automatically for Meta models. Please report this issue."
                )
            elif "doesn't support tool calling without" in error_message:
                log.log_error(
                    f"Bedrock tool calling error: {e}. "
                    "This should be handled automatically. Please report this issue."
                )
            elif "Expected `thinking` or `redacted_thinking`" in error_message:
                log.log_error(
                    f"Bedrock thinking format error: {e}. "
                    "Try disabling reasoning_effort in settings."
                )
            elif any(keyword in error_message.lower() for keyword in ['throttl', 'too many requests']):
                log.log_warn("Detected throttling in error message - will retry with backoff")
                raise RateLimitError(f"LiteLLM throttled: {e}")
            raise APIProviderError(f"LiteLLM API error: {e}")
        except openai.APIError as e:
            log.log_error(f"LiteLLM API error: {e}")
            raise APIProviderError(f"LiteLLM API error: {e}")
        except Exception as e:
            log.log_error(f"Chat completion failed: {e}")
            raise APIProviderError(f"Unexpected error during chat completion: {e}")

    async def _chat_completion_stream_impl(self, request: ChatRequest,
                                          native_message_callback: Optional[Callable[[Dict[str, Any], ProviderType], None]] = None) -> AsyncGenerator[ChatResponse, None]:
        """Internal implementation of streaming chat completion with LiteLLM/Bedrock quirks"""
        try:
            # LITELLM/BEDROCK QUIRK #3: Meta models don't support tool use in streaming mode
            # Fall back to non-streaming if Meta model + tools
            # Note: Applies to all Meta models since they're typically routed through Bedrock
            request_tools = getattr(request, 'tools', None)

            # Check if thinking is enabled
            reasoning_effort_str = self.config.get('reasoning_effort', 'none')
            thinking_enabled = reasoning_effort_str and reasoning_effort_str != 'none'

            # LITELLM/ANTHROPIC QUIRK: Streaming with thinking + tools doesn't provide signatures
            # Anthropic requires signatures on thinking blocks for tool calling continuation
            # Fall back to non-streaming for Anthropic models with thinking + tools
            needs_nonstreaming_for_thinking = (
                self.model_family == 'anthropic' and
                thinking_enabled and
                request_tools and len(request_tools) > 0
            )

            needs_nonstreaming_fallback = (
                (self.model_family == 'meta' and request_tools and len(request_tools) > 0) or
                needs_nonstreaming_for_thinking
            )

            if needs_nonstreaming_fallback:
                if needs_nonstreaming_for_thinking:
                    log.log_info(
                        f"LiteLLM: Using non-streaming mode for Anthropic model '{self.model}' with thinking+tools "
                        f"(streaming doesn't provide thinking block signatures required for tool continuation)"
                    )
                else:
                    log.log_info(
                        f"LiteLLM: Using non-streaming mode for Meta model '{self.model}' with tools "
                        f"(streaming+tools not supported on Bedrock)"
                    )
                # Call non-streaming API with native_message_callback to capture thinking_blocks
                non_streaming_response = await self.chat_completion(request, native_message_callback)

                # Yield the full content at once (no fake chunking)
                if non_streaming_response.content:
                    yield ChatResponse(
                        content=non_streaming_response.content,
                        model=self.model,
                        usage=Usage(prompt_tokens=0, completion_tokens=0, total_tokens=0),
                        tool_calls=[],
                        finish_reason="",
                        is_streaming=True
                    )

                # Yield the final response with tool calls, usage, and native_content
                yield ChatResponse(
                    content="",
                    model=non_streaming_response.model,
                    usage=non_streaming_response.usage,
                    tool_calls=non_streaming_response.tool_calls,
                    finish_reason=non_streaming_response.finish_reason,
                    is_streaming=False,  # Mark as final
                    native_content=non_streaming_response.native_content  # Pass through from non-streaming
                )
                return

            # Use our quirk-aware completion kwargs builder
            completion_kwargs = self._prepare_completion_kwargs(request)
            completion_kwargs["stream"] = True
            # Add stream_options for better streaming control (if supported by backend)
            completion_kwargs["stream_options"] = {"include_usage": True}

            # Make streaming API call
            stream = self._client.chat.completions.create(**completion_kwargs)

            accumulated_content = ""
            accumulated_reasoning = ""  # Track reasoning content for thinking-enabled models
            building_tool_calls = {}  # tool_index -> partial tool data
            thinking_blocks = []  # Store complete thinking blocks when received

            try:
                finished = False
                for chunk in stream:
                    if not chunk.choices or finished:
                        continue

                    choice = chunk.choices[0]
                    delta = choice.delta

                    # Handle reasoning content delta (LiteLLM Anthropic thinking)
                    if hasattr(delta, 'reasoning_content') and delta.reasoning_content:
                        accumulated_reasoning += delta.reasoning_content

                    # Handle content delta - yield immediately for responsive streaming
                    if delta.content is not None and delta.content:
                        accumulated_content += delta.content
                        yield ChatResponse(
                            content=delta.content,
                            model=self.model,
                            usage=Usage(prompt_tokens=0, completion_tokens=0, total_tokens=0),
                            tool_calls=[],
                            finish_reason="",
                            is_streaming=True
                        )
                        # Yield control to event loop for responsive UI updates
                        await asyncio.sleep(0)

                    # Handle tool call deltas - accumulate across chunks
                    if delta.tool_calls:
                        for tc_delta in delta.tool_calls:
                            tool_index = tc_delta.index if hasattr(tc_delta, 'index') else 0

                            # Initialize tool call if not seen before
                            if tool_index not in building_tool_calls:
                                building_tool_calls[tool_index] = {
                                    'id': tc_delta.id or f"tool_call_{tool_index}",
                                    'name': '',
                                    'arguments': ''
                                }

                            # Update tool call data from delta
                            if tc_delta.id:
                                building_tool_calls[tool_index]['id'] = tc_delta.id

                            if tc_delta.function:
                                if tc_delta.function.name:
                                    building_tool_calls[tool_index]['name'] = tc_delta.function.name

                                if tc_delta.function.arguments:
                                    building_tool_calls[tool_index]['arguments'] += tc_delta.function.arguments

                    # Handle finish reason
                    if choice.finish_reason and not finished:
                        # Convert accumulated tool calls to ToolCall objects
                        final_tool_calls = []
                        for tool_index, tool_data in building_tool_calls.items():
                            if tool_data['name']:  # Only include tools with names
                                try:
                                    arguments = json.loads(tool_data['arguments']) if tool_data['arguments'] else {}
                                except json.JSONDecodeError:
                                    log.log_warn(f"Failed to parse tool call arguments: {tool_data['arguments']}")
                                    arguments = {}

                                tool_call = ToolCall(
                                    id=tool_data['id'],
                                    name=tool_data['name'],
                                    arguments=arguments
                                )
                                final_tool_calls.append(tool_call)

                        # Call native message callback with complete streaming response
                        if native_message_callback:
                            native_message = {
                                "role": "assistant",
                                "content": accumulated_content,
                                "model": self.model,
                                "finish_reason": choice.finish_reason,
                                "streaming": True  # Mark as reconstructed from streaming
                            }

                            # Add tool calls if present
                            if final_tool_calls:
                                native_message["tool_calls"] = [
                                    {
                                        "id": tc.id,
                                        "type": "function",
                                        "function": {
                                            "name": tc.name,
                                            "arguments": json.dumps(tc.arguments) if isinstance(tc.arguments, dict) else tc.arguments
                                        }
                                    }
                                    for tc in final_tool_calls
                                ]

                            # Add thinking/reasoning content if present (Anthropic models)
                            if accumulated_reasoning:
                                native_message["reasoning_content"] = accumulated_reasoning
                                log.log_info(f"LiteLLM streaming: Captured reasoning_content ({len(accumulated_reasoning)} chars)")
                                # Create thinking_blocks structure for Anthropic compatibility
                                thinking_blocks.append({
                                    "type": "thinking",
                                    "thinking": accumulated_reasoning,
                                    "signature": None  # Signature not available in streaming
                                })

                            if thinking_blocks:
                                native_message["thinking_blocks"] = thinking_blocks
                                log.log_info(f"LiteLLM streaming: Captured {len(thinking_blocks)} thinking_blocks")

                            native_message_callback(native_message, self.get_provider_type())

                        # Build native_content with thinking blocks for ReAct to capture
                        native_content_for_response = {}
                        if accumulated_reasoning:
                            native_content_for_response["reasoning_content"] = accumulated_reasoning
                        if thinking_blocks:
                            native_content_for_response["thinking_blocks"] = thinking_blocks

                        # Emit final response with tool calls AND native_content
                        final_response = ChatResponse(
                            content="",  # Empty content since all sent as deltas
                            model=self.model,
                            usage=Usage(prompt_tokens=0, completion_tokens=0, total_tokens=0),
                            tool_calls=final_tool_calls,
                            finish_reason=choice.finish_reason,
                            is_streaming=False,  # Mark as final response
                            native_content=native_content_for_response if native_content_for_response else None
                        )
                        yield final_response
                        finished = True

            except StopIteration:
                pass

        except openai.AuthenticationError as e:
            log.log_error(f"Authentication error: {e}")
            raise AuthenticationError(f"LiteLLM authentication failed: {e}")
        except openai.RateLimitError as e:
            log.log_error(f"Rate limit error: {e}")
            raise RateLimitError(f"LiteLLM rate limit exceeded: {e}")
        except openai.APITimeoutError as e:
            # Timeouts are common with Bedrock due to slow inference and throttling
            log.log_warn(f"LiteLLM streaming timeout (may be Bedrock throttling): {e}")
            raise NetworkError(f"LiteLLM streaming timed out: {e}")
        except openai.APIConnectionError as e:
            log.log_error(f"Connection error: {e}")
            # Check if this might be throttling
            error_str = str(e).lower()
            if any(keyword in error_str for keyword in ['throttl', 'too many requests', '429', 'rate limit']):
                log.log_warn("Detected potential throttling - will retry with backoff")
                raise RateLimitError(f"LiteLLM throttled: {e}")
            raise NetworkError(f"LiteLLM connection failed: {e}")
        except openai.BadRequestError as e:
            # Enhanced error handling for Bedrock-specific errors
            error_message = str(e)
            if "doesn't support tool use in streaming mode" in error_message:
                log.log_error(
                    f"Bedrock streaming+tools error: {e}. "
                    "This should be handled automatically for Meta models. Please report this issue."
                )
            elif "doesn't support tool calling without" in error_message:
                log.log_error(
                    f"Bedrock tool calling error: {e}. "
                    "This should be handled automatically. Please report this issue."
                )
            elif "Expected `thinking` or `redacted_thinking`" in error_message:
                log.log_error(
                    f"Bedrock thinking format error: {e}. "
                    "Try disabling reasoning_effort in settings."
                )
            elif any(keyword in error_message.lower() for keyword in ['throttl', 'too many requests']):
                log.log_warn("Detected throttling in error message - will retry with backoff")
                raise RateLimitError(f"LiteLLM throttled: {e}")
            raise APIProviderError(f"LiteLLM API error: {e}")
        except openai.APIError as e:
            log.log_error(f"LiteLLM API error: {e}")
            raise APIProviderError(f"LiteLLM API error: {e}")
        except Exception as e:
            log.log_error(f"Streaming completion failed: {e}")
            raise APIProviderError(f"Unexpected error during streaming completion: {e}")
