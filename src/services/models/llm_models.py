#!/usr/bin/env python3

"""
LLM Models - Data structures for LLM requests and responses
Normalized around OpenAI API format for consistency across providers
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Union
from enum import Enum


class MessageRole(Enum):
    """Message roles in chat conversations"""
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


@dataclass
class ToolCall:
    """Represents a function/tool call from the LLM"""
    id: str
    name: str
    arguments: Dict[str, Any]
    call_id: Optional[str] = None  # For provider compatibility

    def __post_init__(self):
        """Set call_id to id if not provided"""
        if self.call_id is None:
            self.call_id = self.id


@dataclass
class ToolResult:
    """Result from executing a tool call"""
    tool_call_id: str
    content: str
    error: Optional[str] = None
    execution_time: Optional[float] = None
    server_name: Optional[str] = None

    @property
    def success(self) -> bool:
        """Check if tool execution was successful"""
        return self.error is None


@dataclass
class ChatMessage:
    """Individual message in a chat conversation"""
    role: MessageRole
    content: str
    tool_calls: Optional[List[ToolCall]] = None
    tool_call_id: Optional[str] = None  # For tool response messages
    name: Optional[str] = None  # For function messages
    native_content: Optional[Any] = None  # Provider-specific structured content (e.g., Anthropic content blocks)

    def __post_init__(self):
        """Convert string roles to MessageRole enum"""
        if isinstance(self.role, str):
            self.role = MessageRole(self.role)


@dataclass
class ChatRequest:
    """Request for chat completion"""
    messages: List[ChatMessage]
    model: str
    max_tokens: int = 4096
    temperature: float = 0.7
    top_p: float = 1.0
    stream: bool = False
    tools: Optional[List[Dict[str, Any]]] = None
    tool_choice: Optional[Union[str, Dict[str, Any]]] = None
    stop: Optional[Union[str, List[str]]] = None
    presence_penalty: float = 0.0
    frequency_penalty: float = 0.0
    user: Optional[str] = None


@dataclass
class Usage:
    """Token usage information"""
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int


@dataclass
class ChatResponse:
    """Response from chat completion"""
    content: str
    model: str
    usage: Usage
    tool_calls: Optional[List[ToolCall]] = None
    finish_reason: str = "stop"
    is_streaming: bool = False
    response_id: Optional[str] = None
    created: Optional[int] = None
    native_content: Optional[Any] = None  # Provider-specific structured content (e.g., Anthropic content blocks)

    @property
    def has_tool_calls(self) -> bool:
        """Check if response contains tool calls"""
        return self.tool_calls is not None and len(self.tool_calls) > 0

    @property
    def stopped_for_tool_calls(self) -> bool:
        """Check if response stopped because of tool calls"""
        return self.finish_reason == "tool_calls" or (self.finish_reason == "stop" and self.has_tool_calls)


@dataclass
class EmbeddingRequest:
    """Request for text embeddings"""
    texts: List[str]
    model: str = "text-embedding-3-small"
    dimensions: Optional[int] = None
    user: Optional[str] = None


@dataclass
class EmbeddingResponse:
    """Response from embedding generation"""
    embeddings: List[List[float]]
    model: str
    usage: Usage
    dimensions: int


@dataclass
class ProviderCapabilities:
    """Capabilities supported by a provider"""
    supports_chat: bool = True
    supports_streaming: bool = True
    supports_tools: bool = False
    supports_embeddings: bool = False
    supports_vision: bool = False
    max_tokens: int = 4096
    models: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'supports_chat': self.supports_chat,
            'supports_streaming': self.supports_streaming,
            'supports_tools': self.supports_tools,
            'supports_embeddings': self.supports_embeddings,
            'supports_vision': self.supports_vision,
            'max_tokens': self.max_tokens,
            'models': self.models
        }