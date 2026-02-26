#!/usr/bin/env python3

"""
Service Registry - Dependency injection container for services
Manages service lifecycle and dependencies
"""

from typing import Dict, Any, Optional
from threading import Lock

from src.ida_compat import log

from .settings_service import SettingsService
from .llm_service import LLMService


class ServiceRegistry:
    """
    Service registry implementing dependency injection pattern.

    Manages service instances and their dependencies in a centralized way.
    Ensures proper initialization order and singleton behavior where needed.
    """

    def __init__(self):
        """Initialize empty service registry"""
        self._services: Dict[str, Any] = {}
        self._lock = Lock()
        self._initialized = False

    def initialize(self):
        """Initialize all services with proper dependency resolution"""
        with self._lock:
            if self._initialized:
                return

            try:
                # Initialize services in dependency order

                # 1. Settings service (no dependencies)
                settings_service = SettingsService()
                self._services['settings'] = settings_service

                # 2. LLM service (depends on settings)
                llm_service = LLMService(settings_service)
                self._services['llm'] = llm_service

                self._initialized = True

            except Exception as e:
                # Clean up on failure
                self._services.clear()
                raise RuntimeError(f"Failed to initialize services: {e}") from e

    def get_service(self, service_name: str) -> Optional[Any]:
        """
        Get service instance by name

        Args:
            service_name: Name of service to retrieve

        Returns:
            Service instance or None if not found
        """
        if not self._initialized:
            self.initialize()

        return self._services.get(service_name)

    def get_settings_service(self) -> SettingsService:
        """Get settings service instance"""
        service = self.get_service('settings')
        if not service:
            raise RuntimeError("Settings service not initialized")
        return service

    def get_llm_service(self) -> LLMService:
        """Get LLM service instance"""
        service = self.get_service('llm')
        if not service:
            raise RuntimeError("LLM service not initialized")
        return service

    def shutdown(self):
        """Shutdown all services and cleanup resources"""
        with self._lock:
            # Shutdown in reverse order
            for service_name in reversed(list(self._services.keys())):
                service = self._services[service_name]
                if hasattr(service, 'shutdown'):
                    try:
                        service.shutdown()
                    except Exception as e:
                        log.log_warn(f"[IDAssist] Error shutting down {service_name}: {e}")

            self._services.clear()
            self._initialized = False

    def reset(self):
        """Reset registry and reinitialize services"""
        self.shutdown()
        self.initialize()

    def is_initialized(self) -> bool:
        """Check if registry is initialized"""
        return self._initialized

    def get_service_status(self) -> Dict[str, bool]:
        """Get status of all services"""
        return {
            name: service is not None
            for name, service in self._services.items()
        }


# Global service registry instance
_service_registry: Optional[ServiceRegistry] = None
_registry_lock = Lock()

def get_service_registry() -> ServiceRegistry:
    """
    Get the global service registry instance

    Returns:
        Singleton service registry instance
    """
    global _service_registry

    with _registry_lock:
        if _service_registry is None:
            _service_registry = ServiceRegistry()

        return _service_registry

def reset_service_registry():
    """Reset the global service registry (mainly for testing)"""
    global _service_registry

    with _registry_lock:
        if _service_registry:
            _service_registry.shutdown()
        _service_registry = None
