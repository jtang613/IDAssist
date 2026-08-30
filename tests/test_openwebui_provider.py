"""Tests for OpenWebUI provider URL and transport handling."""

import asyncio
import sys
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.services.llm_providers.openwebui_platform_api_provider import (
    OpenWebUIPlatformApiProvider,
    OpenWebUIPlatformApiProviderFactory,
)
from src.services.llm_providers.provider_factory import LLMProviderFactory
from src.services.models.provider_types import ProviderType


class TestOpenWebUIProvider(unittest.TestCase):
    """OpenWebUI provider behavior."""

    def _config(self, **overrides):
        config = {
            "name": "OpenWebUI",
            "model": "llama3.1:8b",
            "provider_type": "openwebui",
            "url": "http://localhost:3000",
        }
        config.update(overrides)
        return config

    def _create_provider(self, config):
        with (
            patch("src.services.llm_providers.openai_platform_api_provider.OpenAI") as openai_cls,
            patch("src.services.llm_providers.openai_platform_api_provider.httpx.Client") as client_cls,
        ):
            client_cls.return_value = Mock()
            provider = OpenWebUIPlatformApiProvider(config)
            return provider, openai_cls, client_cls

    def test_base_url_appends_api_path(self):
        """OpenWebUI root URLs are converted to the /api base."""
        _, openai_cls, _ = self._create_provider(self._config())

        self.assertEqual(
            openai_cls.call_args.kwargs["base_url"],
            "http://localhost:3000/api",
        )

    def test_base_url_does_not_double_append_api_path(self):
        """Configured URLs already ending in /api stay unchanged."""
        _, openai_cls, _ = self._create_provider(
            self._config(url="https://example.com/open-webui/api")
        )

        self.assertEqual(
            openai_cls.call_args.kwargs["base_url"],
            "https://example.com/open-webui/api",
        )

    def test_custom_api_base_path(self):
        """Self-hosted OpenWebUI deployments can configure a custom API base path."""
        _, openai_cls, _ = self._create_provider(
            self._config(
                url="https://example.com/open-webui",
                api_base_path="/owui-api",
            )
        )

        self.assertEqual(
            openai_cls.call_args.kwargs["base_url"],
            "https://example.com/open-webui/owui-api",
        )

    def test_bypass_proxy_does_not_disable_tls_verification(self):
        """Proxy bypass and TLS verification are independent settings."""
        _, _, client_cls = self._create_provider(
            self._config(bypass_proxy=True, disable_tls=False)
        )

        self.assertEqual(client_cls.call_args.kwargs["trust_env"], False)
        self.assertEqual(client_cls.call_args.kwargs["verify"], True)

    def test_disable_tls_is_explicit(self):
        """TLS verification is disabled only when disable_tls is set."""
        _, _, client_cls = self._create_provider(
            self._config(bypass_proxy=True, disable_tls=True)
        )

        self.assertEqual(client_cls.call_args.kwargs["trust_env"], False)
        self.assertEqual(client_cls.call_args.kwargs["verify"], False)

    def test_openwebui_models_are_not_all_reasoning_models(self):
        """OpenWebUI model names keep the shared reasoning-model detection."""
        provider, _, _ = self._create_provider(self._config(model="llama3.1:8b"))
        self.assertFalse(provider._is_reasoning_model())

        provider, _, _ = self._create_provider(self._config(model="gpt-5"))
        self.assertTrue(provider._is_reasoning_model())

    def test_empty_completion_still_proves_connectivity(self):
        """A valid empty local-model response is not a connection failure."""
        provider, _, _ = self._create_provider(self._config())
        provider.chat_completion = AsyncMock(return_value=Mock(content=""))

        self.assertTrue(asyncio.run(provider.test_connection()))

    def test_factory_registration(self):
        """The main factory registers OpenWebUI with its dedicated provider."""
        factory = LLMProviderFactory()

        self.assertTrue(factory.is_supported(ProviderType.OPENWEBUI))
        self.assertIsInstance(
            factory._factories[ProviderType.OPENWEBUI],
            OpenWebUIPlatformApiProviderFactory,
        )

        with (
            patch("src.services.llm_providers.openai_platform_api_provider.OpenAI"),
            patch("src.services.llm_providers.openai_platform_api_provider.httpx.Client"),
        ):
            provider = factory.create_provider(self._config())

        self.assertEqual(provider.get_provider_type(), ProviderType.OPENWEBUI)
        self.assertIsInstance(provider, OpenWebUIPlatformApiProvider)


if __name__ == "__main__":
    unittest.main()
