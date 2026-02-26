#!/usr/bin/env python3

"""
Ollama Provider - Implementation for Ollama API
Adapted from reference implementation for BinAssist architecture
"""

import asyncio
import json
import time
from typing import List, Dict, Any, AsyncGenerator, Optional, Callable

try:
    import httpx
except ImportError:
    raise ImportError("httpx package not available. Install with: pip install httpx")

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


class OllamaProvider(BaseLLMProvider):
    """
    Ollama API provider implementation.

    Supports chat completions, streaming, and tool calling with Ollama's native API.
    Ollama typically runs locally and doesn't require API keys.
    """

    def __init__(self, config: Dict[str, Any]):
        """Initialize Ollama provider"""
        super().__init__(config)

        # Validate configuration
        self.validate_config()

        # Set default URL if not provided (Ollama's default)
        if not self.url or self.url in ['http://localhost:11434', 'http://localhost:11434/', '']:
            self.url = "http://localhost:11434"

        # Remove any trailing /v1 since Ollama uses native API
        self.url = self.url.rstrip('/v1').rstrip('/')

        # Warn if TLS verification is disabled
        if self.disable_tls:
            import ssl
            log.log_warn(f"TLS verification disabled for Ollama provider '{self.name}'")
            # Suppress SSL warnings when verification is disabled
            import warnings
            warnings.filterwarnings('ignore', message='Unverified HTTPS request')

        log.log_info(f"Ollama provider initialized with URL: {self.url}, model: {self.model}")

    async def chat_completion(self, request: ChatRequest,
                            native_message_callback: Optional[Callable[[Dict[str, Any], ProviderType], None]] = None) -> ChatResponse:
        """Generate non-streaming chat completion with rate limit retry"""
        log.log_info(f"Ollama chat completion for {self.model} with {len(request.messages)} messages")
        return await self._with_rate_limit_retry(self._chat_completion_impl, request, native_message_callback)

    async def _chat_completion_impl(self, request: ChatRequest,
                            native_message_callback: Optional[Callable[[Dict[str, Any], ProviderType], None]] = None) -> ChatResponse:
        """Internal implementation of chat completion"""
        try:
            # Convert messages to Ollama format
            ollama_messages = self._prepare_messages(request.messages)

            # Prepare payload
            payload = {
                "model": self.model,
                "messages": ollama_messages,
                "stream": False
            }

            # Add parameters if specified
            if request.temperature is not None:
                payload["options"] = payload.get("options", {})
                payload["options"]["temperature"] = request.temperature

            if request.max_tokens:
                payload["options"] = payload.get("options", {})
                payload["options"]["num_predict"] = request.max_tokens

            # Add reasoning if configured (think parameter at TOP LEVEL, not in options)
            reasoning_effort_str = self.config.get('reasoning_effort', 'none')
            if reasoning_effort_str and reasoning_effort_str != 'none':
                # For gpt-oss: use string value ("low", "medium", "high")
                # For other models: use boolean (true)
                if "gpt-oss" in self.model.lower():
                    payload["think"] = reasoning_effort_str
                    log.log_debug(f"Ollama gpt-oss thinking set to: {reasoning_effort_str}")
                else:
                    payload["think"] = True
                    log.log_debug(f"Ollama thinking enabled (boolean) for model: {self.model}")

            # Add tools if present (transform to Ollama-compatible format)
            if request.tools:
                transformed_tools = self._transform_tools_for_ollama(request.tools)
                payload["tools"] = transformed_tools
                payload["format"] = "json"  # Request JSON format for better tool calling

            # Make API call
            url = f"{self.url}/api/chat"
            async with httpx.AsyncClient(timeout=30.0, verify=not self.disable_tls) as client:
                response = await client.post(url, json=payload)

                if response.status_code != 200:
                    error_msg = f"HTTP {response.status_code}"
                    try:
                        error_data = response.json()
                        if 'error' in error_data:
                            error_msg = error_data['error']
                    except:
                        error_msg = response.text or error_msg

                    # Check for rate limit errors (HTTP 429)
                    if response.status_code == 429:
                        raise RateLimitError(f"Ollama rate limit exceeded: {error_msg}")

                    raise APIProviderError(f"Ollama API error: {error_msg}")

                data = response.json()

                # Extract content and tool calls
                content = ""
                tool_calls = []

                if 'message' in data:
                    message = data['message']
                    content = message.get('content', '')

                    # Check for native tool calls
                    if 'tool_calls' in message:
                        for tc in message['tool_calls']:
                            if isinstance(tc, dict) and 'function' in tc:
                                function_data = tc['function']
                                arguments = function_data.get('arguments', {})
                                if isinstance(arguments, str):
                                    try:
                                        arguments = json.loads(arguments)
                                    except json.JSONDecodeError:
                                        arguments = {}

                                tool_call = ToolCall(
                                    id=tc.get('id', f"call_{int(time.time() * 1000)}"),
                                    name=function_data.get('name', 'unknown'),
                                    arguments=arguments
                                )
                                tool_calls.append(tool_call)

                    # Try to extract tool calls from content if no native tool calls
                    elif content and request.tools:
                        extracted_calls = self._extract_tool_calls_from_content(content)
                        for tc_dict in extracted_calls:
                            if 'function' in tc_dict:
                                function_data = tc_dict['function']
                                arguments = function_data.get('arguments', {})
                                if isinstance(arguments, str):
                                    try:
                                        arguments = json.loads(arguments)
                                    except json.JSONDecodeError:
                                        arguments = {}

                                tool_call = ToolCall(
                                    id=tc_dict.get('id', f"call_{int(time.time() * 1000)}"),
                                    name=function_data.get('name', 'unknown'),
                                    arguments=arguments
                                )
                                tool_calls.append(tool_call)

                # Call native message callback with actual API response
                if native_message_callback:
                    # Store the complete Ollama response in native format
                    native_message = {
                        "role": "assistant",
                        "content": content,
                        "tool_calls": [
                            {
                                "id": tc.id,
                                "name": tc.name,
                                "arguments": tc.arguments
                            } for tc in tool_calls
                        ] if tool_calls else [],
                        "model": self.model,
                        "done": data.get('done', True),
                        "eval_count": data.get('eval_count', 0),
                        "prompt_eval_count": data.get('prompt_eval_count', 0)
                    }
                    native_message_callback(native_message, self.get_provider_type())

                # Create usage info (estimated)
                usage = Usage(
                    prompt_tokens=data.get('prompt_eval_count', 0),
                    completion_tokens=data.get('eval_count', 0),
                    total_tokens=data.get('prompt_eval_count', 0) + data.get('eval_count', 0)
                )

                return ChatResponse(
                    content=content,
                    model=self.model,
                    usage=usage,
                    tool_calls=tool_calls,
                    finish_reason="stop" if data.get('done', True) else "incomplete"
                )

        except httpx.RequestError as e:
            log.log_error(f"Network error: {e}")
            raise NetworkError(f"Ollama connection failed: {e}")
        except Exception as e:
            log.log_error(f"Chat completion failed: {e}")
            raise APIProviderError(f"Unexpected error during chat completion: {e}")

    async def chat_completion_stream(self, request: ChatRequest,
                                   native_message_callback: Optional[Callable[[Dict[str, Any], ProviderType], None]] = None) -> AsyncGenerator[ChatResponse, None]:
        """Generate streaming chat completion with rate limit retry"""
        log.log_info(f"Ollama streaming completion for {self.model} with {len(request.messages)} messages")
        async for response in self._with_rate_limit_retry_stream(self._chat_completion_stream_impl, request, native_message_callback):
            yield response

    async def _chat_completion_stream_impl(self, request: ChatRequest,
                                   native_message_callback: Optional[Callable[[Dict[str, Any], ProviderType], None]] = None) -> AsyncGenerator[ChatResponse, None]:
        """Internal implementation of streaming chat completion"""
        stream_response = None
        try:
            # Convert messages to Ollama format
            ollama_messages = self._prepare_messages(request.messages)

            # Prepare payload
            payload = {
                "model": self.model,
                "messages": ollama_messages,
                "stream": True
            }

            # Add parameters if specified
            if request.temperature is not None:
                payload["options"] = payload.get("options", {})
                payload["options"]["temperature"] = request.temperature

            if request.max_tokens:
                payload["options"] = payload.get("options", {})
                payload["options"]["num_predict"] = request.max_tokens

            # Add reasoning if configured (think parameter at TOP LEVEL, not in options - streaming)
            reasoning_effort_str = self.config.get('reasoning_effort', 'none')
            if reasoning_effort_str and reasoning_effort_str != 'none':
                # For gpt-oss: use string value ("low", "medium", "high")
                # For other models: use boolean (true)
                if "gpt-oss" in self.model.lower():
                    payload["think"] = reasoning_effort_str
                    log.log_debug(f"Ollama streaming gpt-oss thinking set to: {reasoning_effort_str}")
                else:
                    payload["think"] = True
                    log.log_debug(f"Ollama streaming thinking enabled (boolean) for model: {self.model}")

            # Add tools if present (transform to Ollama-compatible format)
            if request.tools:
                transformed_tools = self._transform_tools_for_ollama(request.tools)
                payload["tools"] = transformed_tools
                payload["format"] = "json"  # Request JSON format for better tool calling

            # Make streaming API call
            url = f"{self.url}/api/chat"

            accumulated_content = ""
            accumulated_tool_calls = []

            async with httpx.AsyncClient(timeout=60.0, verify=not self.disable_tls) as client:
                stream_response = client.stream("POST", url, json=payload)
                response = await stream_response.__aenter__()

                try:
                    if response.status_code != 200:
                        error_msg = f"HTTP {response.status_code}"
                        try:
                            error_data = await response.aread()
                            error_data = json.loads(error_data)
                            if 'error' in error_data:
                                error_msg = error_data['error']
                        except:
                            error_text = await response.aread()
                            error_msg = error_text.decode() if isinstance(error_text, bytes) else str(error_text)

                        # Check for rate limit errors (HTTP 429)
                        if response.status_code == 429:
                            raise RateLimitError(f"Ollama rate limit exceeded: {error_msg}")

                        raise APIProviderError(f"Ollama streaming API error: {error_msg}")

                    # Process streaming response
                    async for text_chunk in response.aiter_text():
                        if not text_chunk.strip():
                            continue

                        # Split by lines in case multiple JSON objects are in one chunk
                        for line in text_chunk.strip().split('\n'):
                            if not line.strip():
                                continue

                            try:
                                chunk = json.loads(line)

                                # Handle structured tool calls (like OpenAI and Anthropic)
                                if 'message' in chunk and 'tool_calls' in chunk['message']:
                                    for tc in chunk['message']['tool_calls']:
                                        if isinstance(tc, dict):
                                            # Handle different Ollama tool call formats
                                            tool_name = None
                                            arguments = {}
                                            tool_id = tc.get('id', f"call_{int(time.time() * 1000)}")

                                            if 'function' in tc:
                                                # OpenAI-style format
                                                function_data = tc['function']
                                                tool_name = function_data.get('name', 'unknown')
                                                arguments = function_data.get('arguments', {})
                                            elif 'name' in tc:
                                                # Direct format
                                                tool_name = tc.get('name', 'unknown')
                                                arguments = tc.get('arguments', tc.get('parameters', {}))
                                            else:
                                                log.log_warn(f"Ollama: Unknown tool call format: {tc}")
                                                continue

                                            # Parse arguments if they're a string
                                            if isinstance(arguments, str):
                                                try:
                                                    arguments = json.loads(arguments)
                                                except json.JSONDecodeError:
                                                    log.log_warn(f"Ollama: Failed to parse tool arguments: {arguments}")
                                                    arguments = {}

                                            tool_call = ToolCall(
                                                id=tool_id,
                                                name=tool_name,
                                                arguments=arguments if isinstance(arguments, dict) else {}
                                            )
                                            accumulated_tool_calls.append(tool_call)

                                # Handle regular content - yield immediately for responsive streaming
                                if 'message' in chunk and 'content' in chunk['message']:
                                    content_chunk = chunk['message']['content']
                                    if content_chunk:
                                        accumulated_content += content_chunk
                                        yield ChatResponse(
                                            content=content_chunk,
                                            model=self.model,
                                            usage=Usage(prompt_tokens=0, completion_tokens=0, total_tokens=0),
                                            tool_calls=[],
                                            finish_reason="",
                                            is_streaming=True
                                        )

                                # Check if streaming is done
                                if chunk.get('done', False):
                                    # Call native message callback with complete streaming response
                                    if native_message_callback and (accumulated_content or accumulated_tool_calls):
                                        native_message = {
                                            "role": "assistant",
                                            "content": accumulated_content,
                                            "tool_calls": [
                                                {
                                                    "id": tc.id,
                                                    "name": tc.name,
                                                    "arguments": tc.arguments
                                                } for tc in accumulated_tool_calls
                                            ] if accumulated_tool_calls else [],
                                            "model": self.model,
                                            "done": True,
                                            "streaming": True,
                                            "eval_count": chunk.get('eval_count', 0),
                                            "prompt_eval_count": chunk.get('prompt_eval_count', 0)
                                        }
                                        native_message_callback(native_message, self.get_provider_type())

                                    # Emit final response
                                    usage = Usage(
                                        prompt_tokens=chunk.get('prompt_eval_count', 0),
                                        completion_tokens=chunk.get('eval_count', 0),
                                        total_tokens=chunk.get('prompt_eval_count', 0) + chunk.get('eval_count', 0)
                                    )

                                    yield ChatResponse(
                                        content="",  # Empty content since all content already sent as deltas
                                        model=self.model,
                                        usage=usage,
                                        tool_calls=accumulated_tool_calls,
                                        finish_reason="tool_calls" if accumulated_tool_calls else "stop",
                                        is_streaming=False
                                    )
                                    # Exit the streaming loop cleanly - context manager will handle cleanup
                                    break

                            except json.JSONDecodeError as e:
                                log.log_warn(f"Failed to parse Ollama streaming chunk: {line} - {e}")
                                continue

                finally:
                    # Explicitly close the stream response using context manager protocol
                    if stream_response:
                        await stream_response.__aexit__(None, None, None)

        except httpx.RequestError as e:
            log.log_error(f"Network error: {e}")
            raise NetworkError(f"Ollama connection failed: {e}")
        except Exception as e:
            log.log_error(f"Streaming completion failed: {e}")
            raise APIProviderError(f"Unexpected error during streaming: {e}")
        finally:
            # Ensure stream response is properly closed
            if stream_response:
                try:
                    await stream_response.__aexit__(None, None, None)
                except Exception:
                    pass  # Ignore cleanup errors

    async def generate_embeddings(self, request: EmbeddingRequest) -> EmbeddingResponse:
        """Generate embeddings using Ollama's embedding API"""
        log.log_info(f"Ollama embeddings for {len(request.texts)} texts")

        try:
            embeddings = []

            # Ollama's embedding API typically requires individual requests per text
            for text in request.texts:
                payload = {
                    "model": self.model,
                    "prompt": text
                }

                url = f"{self.url}/api/embeddings"
                async with httpx.AsyncClient(timeout=30.0, verify=not self.disable_tls) as client:
                    response = await client.post(url, json=payload)

                    if response.status_code != 200:
                        error_msg = f"HTTP {response.status_code}"
                        try:
                            error_data = response.json()
                            if 'error' in error_data:
                                error_msg = error_data['error']
                        except:
                            error_msg = response.text or error_msg

                        raise APIProviderError(f"Ollama embedding API error: {error_msg}")

                    data = response.json()
                    if 'embedding' not in data:
                        raise APIProviderError(f"Invalid response from Ollama embedding API: {data}")

                    embeddings.append(data['embedding'])

            # Calculate usage (estimated)
            total_tokens = sum(len(text.split()) for text in request.texts)
            usage = Usage(
                prompt_tokens=total_tokens,
                completion_tokens=0,
                total_tokens=total_tokens
            )

            return EmbeddingResponse(
                embeddings=embeddings,
                usage=usage
            )

        except httpx.RequestError as e:
            log.log_error(f"Network error getting embeddings: {e}")
            raise NetworkError(f"Ollama connection failed: {e}")
        except Exception as e:
            log.log_error(f"Unexpected error getting embeddings: {e}")
            raise APIProviderError(f"Unexpected error getting embeddings: {e}")

    def get_capabilities(self) -> ProviderCapabilities:
        """Get provider capabilities"""
        return ProviderCapabilities(
            supports_chat=True,
            supports_streaming=True,
            supports_tools=True,  # Limited support, model-dependent
            supports_embeddings=True,
            supports_vision=False,  # Model-dependent, not implemented yet
            max_tokens=self.max_tokens,
            models=[self.model] if self.model else []
        )

    def get_provider_type(self) -> ProviderType:
        """Get the provider type for this provider"""
        return ProviderType.OLLAMA

    def validate_config(self):
        """Validate provider configuration"""
        super().validate_config()

        # Ollama-specific validation
        if not self.model:
            raise ValueError("Model is required for Ollama provider")

        # API key is not required for Ollama (typically runs locally)

    async def test_connection(self) -> bool:
        """Test connection to Ollama API"""
        try:
            # Simple test with minimal parameters
            test_request = ChatRequest(
                messages=[ChatMessage(role=MessageRole.USER, content="Hello")],
                max_tokens=10
            )

            response = await self.chat_completion(test_request)
            return bool(response.content)

        except Exception as e:
            log.log_error(f"Ollama connection test failed: {e}")
            return False

    def _prepare_messages(self, messages: List[ChatMessage]) -> List[Dict[str, Any]]:
        """Convert messages to Ollama format"""
        ollama_messages = []

        for message in messages:
            ollama_msg = {
                "role": message.role.value,  # Convert enum to string
                "content": message.content
            }

            # Handle tool calls for assistant messages
            if message.tool_calls:
                # Ollama might not support native tool calls in messages
                # For now, include them in a structured format
                tool_call_info = []
                for tool_call in message.tool_calls:
                    tool_call_info.append({
                        "id": tool_call.id,
                        "name": tool_call.name,
                        "arguments": tool_call.arguments
                    })

                if tool_call_info:
                    ollama_msg["tool_calls"] = tool_call_info

            # Handle tool responses
            if message.role == MessageRole.TOOL:
                ollama_msg = {
                    "role": "user",  # Ollama might handle tool responses as user messages
                    "content": f"Tool result: {message.content}",
                    "tool_call_id": message.tool_call_id
                }

            ollama_messages.append(ollama_msg)

        return ollama_messages

    def _transform_tools_for_ollama(self, tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Transform tool schemas from OpenAI/Pydantic format to Ollama-compatible format.

        Ollama's Go template expects simple JSON Schema without complex features like anyOf.
        This function simplifies the schema to be compatible with Ollama's expectations.
        """
        transformed_tools = []

        for tool in tools:
            transformed_tool = {
                "type": tool.get("type", "function"),
                "function": {
                    "name": tool["function"]["name"],
                    "description": tool["function"].get("description", ""),
                    "parameters": self._simplify_parameters(tool["function"].get("parameters", {}))
                }
            }
            transformed_tools.append(transformed_tool)

        return transformed_tools

    def _simplify_parameters(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Simplify parameter schema to be Ollama-compatible.

        Removes anyOf/oneOf constructs and uses simple type strings.
        """
        simplified = {
            "type": params.get("type", "object"),
            "properties": {},
            "required": params.get("required", [])
        }

        properties = params.get("properties", {})
        for prop_name, prop_schema in properties.items():
            simplified["properties"][prop_name] = self._simplify_property(prop_schema)

        return simplified

    def _simplify_property(self, prop: Dict[str, Any]) -> Dict[str, Any]:
        """
        Simplify a single property schema.

        Handles anyOf/oneOf by extracting the primary type (ignoring null).
        """
        simplified = {}

        # Handle anyOf/oneOf (common in Pydantic schemas for optional fields)
        if "anyOf" in prop or "oneOf" in prop:
            variants = prop.get("anyOf") or prop.get("oneOf")
            # Find the first non-null type
            for variant in variants:
                if isinstance(variant, dict) and variant.get("type") != "null":
                    simplified["type"] = variant.get("type")
                    break
            # If no non-null type found, default to string
            if "type" not in simplified:
                simplified["type"] = "string"
        elif "type" in prop:
            simplified["type"] = prop["type"]
        else:
            # Default to string if no type specified
            simplified["type"] = "string"

        # Copy over description and title if present
        if "description" in prop:
            simplified["description"] = prop["description"]
        if "title" in prop:
            simplified["title"] = prop["title"]

        # Copy over constraints (min, max, etc.)
        for key in ["minimum", "maximum", "minLength", "maxLength", "pattern", "enum", "default"]:
            if key in prop:
                simplified[key] = prop[key]

        return simplified

    def format_tool_results_for_continuation(self, tool_calls: List[ToolCall], tool_results: List[str]) -> List[Dict[str, Any]]:
        """
        Format tool execution results for Ollama conversation continuation.

        Based on Ollama API documentation, tool results should use the "tool" role
        with content containing the execution result.
        """
        messages = []

        for tool_call, result in zip(tool_calls, tool_results):
            messages.append({
                "role": "tool",
                "content": result
            })

        return messages



# Factory for Ollama provider
from ..llm_providers.provider_factory import ProviderFactory
from ..models.provider_types import ProviderType

class OllamaProviderFactory(ProviderFactory):
    """Factory for creating Ollama provider instances"""

    def create_provider(self, config: Dict[str, Any]) -> OllamaProvider:
        """Create Ollama provider instance"""
        return OllamaProvider(config)

    def supports_provider_type(self, provider_type: ProviderType) -> bool:
        """Check if this factory supports the provider type"""
        return provider_type == ProviderType.OLLAMA
