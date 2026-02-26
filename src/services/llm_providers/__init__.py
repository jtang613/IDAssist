#!/usr/bin/env python3

from .base_provider import (
    BaseLLMProvider, LLMProviderError, APIProviderError,
    AuthenticationError, RateLimitError, NetworkError
)
from .provider_factory import get_provider_factory, LLMProviderFactory

# Import providers as they are implemented
try:
    from .anthropic_platform_api_provider import AnthropicPlatformApiProvider
except ImportError:
    AnthropicPlatformApiProvider = None

try:
    from .anthropic_oauth_provider import AnthropicOAuthProvider
except ImportError:
    AnthropicOAuthProvider = None

__all__ = [
    'BaseLLMProvider', 'LLMProviderError', 'APIProviderError',
    'AuthenticationError', 'RateLimitError', 'NetworkError',
    'get_provider_factory', 'LLMProviderFactory'
]

# Add available providers to __all__
if AnthropicPlatformApiProvider:
    __all__.append('AnthropicPlatformApiProvider')

if AnthropicOAuthProvider:
    __all__.append('AnthropicOAuthProvider')
