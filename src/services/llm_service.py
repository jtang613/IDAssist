#!/usr/bin/env python3

"""
LLM Service - Main orchestrator for LLM operations
Manages provider selection, request routing, and error handling
"""

import asyncio
from typing import List, Dict, Any, Optional, AsyncGenerator
from threading import Lock

from src.ida_compat import log

from .models.llm_models import (
    ChatRequest, ChatResponse, EmbeddingRequest, EmbeddingResponse,
    ProviderCapabilities, ChatMessage, MessageRole
)
from .llm_providers.base_provider import (
    BaseLLMProvider, LLMProviderError, APIProviderError,
    AuthenticationError, RateLimitError, NetworkError
)
from .llm_providers.provider_factory import get_provider_factory
from .settings_service import SettingsService
from .models.provider_types import ProviderType


class LLMService:
    """
    Main LLM service that orchestrates all LLM operations.

    Responsibilities:
    - Provider selection and management
    - Request routing to appropriate providers
    - Error handling and fallback logic
    - Integration with settings service
    """

    def __init__(self, settings_service: SettingsService):
        """Initialize LLM service with settings integration"""
        self.settings_service = settings_service
        self._providers: Dict[str, BaseLLMProvider] = {}
        self._provider_lock = Lock()
        self._active_provider_name: Optional[str] = None
        self._factory = get_provider_factory()

    async def get_active_provider(self) -> Optional[BaseLLMProvider]:
        """Get the currently active provider instance"""
        with self._provider_lock:
            # Get active provider from settings
            active_provider_config = self.settings_service.get_active_llm_provider()
            if not active_provider_config:
                return None

            provider_name = active_provider_config['name']

            # Check if we have a cached provider that's still valid
            if (provider_name in self._providers and
                self._active_provider_name == provider_name):
                return self._providers[provider_name]

            # Create new provider instance
            try:
                provider = await self._create_provider(active_provider_config)
                if provider:
                    self._providers[provider_name] = provider
                    self._active_provider_name = provider_name
                    return provider
            except Exception as e:
                log.log_error(f"[IDAssist] Failed to create provider {provider_name}: {e}")
                return None

        return None

    async def chat_completion(self, messages: List[ChatMessage],
                            model: Optional[str] = None,
                            max_tokens: int = 4096,
                            temperature: float = 0.7,
                            top_p: float = 1.0,
                            tools: Optional[List[Dict[str, Any]]] = None,
                            tool_choice: Optional[str] = None,
                            stop: Optional[List[str]] = None,
                            **kwargs) -> ChatResponse:
        """
        Generate chat completion using active provider

        Args:
            messages: Chat conversation history
            model: Model to use (overrides provider default)
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature
            top_p: Top-p sampling parameter
            tools: Available tools for function calling
            tool_choice: Tool selection preference
            stop: Stop sequences
            **kwargs: Additional provider-specific parameters

        Returns:
            Chat completion response

        Raises:
            LLMProviderError: If no provider available or request fails
        """
        provider = await self.get_active_provider()
        if not provider:
            raise LLMProviderError("No active LLM provider configured")

        # Create request object
        request = ChatRequest(
            messages=messages,
            model=model or provider.model,
            max_tokens=max_tokens,
            temperature=temperature,
            top_p=top_p,
            tools=tools,
            tool_choice=tool_choice,
            stop=stop,
            **kwargs
        )

        try:
            return await provider.chat_completion(request)
        except Exception as e:
            raise LLMProviderError(f"Chat completion failed: {e}") from e

    async def chat_completion_stream(self, messages: List[ChatMessage],
                                   model: Optional[str] = None,
                                   max_tokens: int = 4096,
                                   temperature: float = 0.7,
                                   top_p: float = 1.0,
                                   tools: Optional[List[Dict[str, Any]]] = None,
                                   tool_choice: Optional[str] = None,
                                   stop: Optional[List[str]] = None,
                                   **kwargs) -> AsyncGenerator[ChatResponse, None]:
        """
        Generate streaming chat completion using active provider

        Args:
            messages: Chat conversation history
            model: Model to use (overrides provider default)
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature
            top_p: Top-p sampling parameter
            tools: Available tools for function calling
            tool_choice: Tool selection preference
            stop: Stop sequences
            **kwargs: Additional provider-specific parameters

        Yields:
            Streaming chat completion responses

        Raises:
            LLMProviderError: If no provider available or request fails
        """
        provider = await self.get_active_provider()
        if not provider:
            raise LLMProviderError("No active LLM provider configured")

        # Create request object
        request = ChatRequest(
            messages=messages,
            model=model or provider.model,
            max_tokens=max_tokens,
            temperature=temperature,
            top_p=top_p,
            stream=True,
            tools=tools,
            tool_choice=tool_choice,
            stop=stop,
            **kwargs
        )

        try:
            async for response in provider.chat_completion_stream(request):
                yield response
        except Exception as e:
            raise LLMProviderError(f"Streaming chat completion failed: {e}") from e

    async def generate_embeddings(self, texts: List[str],
                                model: Optional[str] = None,
                                dimensions: Optional[int] = None,
                                **kwargs) -> EmbeddingResponse:
        """
        Generate embeddings using active provider

        Args:
            texts: Texts to embed
            model: Embedding model to use
            dimensions: Desired embedding dimensions
            **kwargs: Additional provider-specific parameters

        Returns:
            Embedding response with vectors

        Raises:
            LLMProviderError: If no provider available or request fails
        """
        provider = await self.get_active_provider()
        if not provider:
            raise LLMProviderError("No active LLM provider configured")

        # Check if provider supports embeddings
        capabilities = provider.get_capabilities()
        if not capabilities.supports_embeddings:
            raise LLMProviderError(f"Provider {provider.name} doesn't support embeddings")

        # Create request object
        request = EmbeddingRequest(
            texts=texts,
            model=model or "text-embedding-3-small",
            dimensions=dimensions,
            **kwargs
        )

        try:
            return await provider.generate_embeddings(request)
        except Exception as e:
            raise LLMProviderError(f"Embedding generation failed: {e}") from e

    async def test_provider_connection(self, provider_name: Optional[str] = None) -> bool:
        """
        Test connection to provider

        Args:
            provider_name: Name of provider to test (uses active if None)

        Returns:
            True if connection successful, False otherwise
        """
        if provider_name:
            # Test specific provider
            provider_config = self.settings_service.get_provider_by_name(provider_name)
            if not provider_config:
                return False

            try:
                provider = await self._create_provider(provider_config)
                if provider:
                    return await provider.test_connection()
            except Exception:
                return False
        else:
            # Test active provider
            provider = await self.get_active_provider()
            if not provider:
                return False

            try:
                return await provider.test_connection()
            except Exception:
                return False

        return False

    def get_provider_capabilities(self, provider_name: Optional[str] = None) -> Optional[ProviderCapabilities]:
        """
        Get capabilities of provider

        Args:
            provider_name: Name of provider (uses active if None)

        Returns:
            Provider capabilities or None if not available
        """
        try:
            if provider_name and provider_name in self._providers:
                return self._providers[provider_name].get_capabilities()
            elif self._active_provider_name and self._active_provider_name in self._providers:
                return self._providers[self._active_provider_name].get_capabilities()
        except Exception:
            pass

        return None

    def get_available_models(self, provider_name: Optional[str] = None) -> List[str]:
        """
        Get list of available models for provider

        Args:
            provider_name: Name of provider (uses active if None)

        Returns:
            List of available model names
        """
        capabilities = self.get_provider_capabilities(provider_name)
        return capabilities.models if capabilities else []

    def invalidate_provider_cache(self, provider_name: Optional[str] = None):
        """
        Invalidate cached provider instances

        Args:
            provider_name: Specific provider to invalidate (all if None)
        """
        with self._provider_lock:
            if provider_name:
                self._providers.pop(provider_name, None)
                if self._active_provider_name == provider_name:
                    self._active_provider_name = None
            else:
                self._providers.clear()
                self._active_provider_name = None

    async def _create_provider(self, provider_config: Dict[str, Any]) -> Optional[BaseLLMProvider]:
        """
        Create provider instance from configuration

        Args:
            provider_config: Provider configuration from settings

        Returns:
            Provider instance or None if creation fails
        """
        try:
            provider = self._factory.create_provider(provider_config)
            return provider

        except Exception as e:
            log.log_error(f"[IDAssist] Failed to create provider: {e}")
            return None

    def __str__(self) -> str:
        """String representation"""
        return f"LLMService(active_provider='{self._active_provider_name}')"

    def __repr__(self) -> str:
        """Detailed string representation"""
        return (f"LLMService("
                f"active_provider='{self._active_provider_name}', "
                f"cached_providers={list(self._providers.keys())})")
