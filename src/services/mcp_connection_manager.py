#!/usr/bin/env python3
"""
MCP Connection Manager

Provides a clean interface for managing MCP connections with lazy initialization,
connection pooling, and tool discovery caching. Integrates with the Query Controller
to provide tools when the MCP checkbox is enabled.
"""

import asyncio
import threading
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

from .mcp_client_service import MCPClientService
from .models.mcp_models import MCPTool

from src.ida_compat import log
from src.mcp_server.tools import get_internal_tools_for_llm


@dataclass
class ConnectionState:
    """Track connection state and cached tools"""
    connected: bool = False
    last_connection_attempt: float = 0.0
    tools: List[Dict[str, Any]] = None
    tools_cached_at: float = 0.0
    error_message: Optional[str] = None

    def __post_init__(self):
        if self.tools is None:
            self.tools = []


class MCPConnectionManager:
    """
    Manages MCP connections with lazy initialization and caching.

    Provides a clean interface for the Query Controller to:
    - Check if MCP tools are available
    - Get tool definitions for LLM requests
    - Ensure connections are established when needed
    """

    def __init__(self):
        self._mcp_service = MCPClientService()
        self._state = ConnectionState()
        self._lock = threading.RLock()
        self._tools_cache_ttl = 60.0  # 60 seconds
        self._connection_retry_delay = 5.0  # 5 seconds between retry attempts


    def is_available(self) -> bool:
        """
        Check if MCP connections are available.

        Returns:
            True if at least one MCP server is connected
        """
        with self._lock:
            return self._state.connected

    def get_available_tools_for_llm(self) -> List[Dict[str, Any]]:
        """
        Get MCP tools formatted for LLM consumption.

        Combines internal tools (graph_query, search_graph, etc.) with
        external tools from connected MCP servers.  When an external server
        provides a tool with the same name as an internal tool, the external
        version takes precedence (it is typically more featureful).

        Returns:
            List of tool definitions in OpenAI tool calling format.
        """
        with self._lock:
            # Check if we have cached tools that are still fresh
            current_time = time.time()
            cache_age = current_time - self._state.tools_cached_at

            if self._state.tools and cache_age < self._tools_cache_ttl:
                return self._state.tools.copy()

            # Collect external tools from connected MCP servers
            external_tools = []
            if self._state.connected:
                try:
                    raw_tools = self._mcp_service.get_available_tools()
                    external_tools = self._convert_tools_for_llm(raw_tools)
                except Exception as e:
                    log.log_error(f"Failed to get external MCP tools: {e}")
                    self._state.error_message = str(e)

            # Names already covered by external servers
            external_names = {
                t["function"]["name"]
                for t in external_tools
                if "function" in t and "name" in t["function"]
            }

            # Add internal tools that are NOT already provided externally
            internal_tools = get_internal_tools_for_llm(exclude_names=external_names)

            tools = external_tools + internal_tools
            self._state.tools = tools
            self._state.tools_cached_at = current_time
            log.log_info(
                f"Refreshed MCP tools cache: {len(external_tools)} external + "
                f"{len(internal_tools)} internal = {len(tools)} total"
            )
            return tools.copy()

    def ensure_connections(self) -> bool:
        """
        Ensure MCP connections are established.

        This method performs lazy initialization - connections are only
        established when actually needed (when MCP checkbox is enabled).

        Returns:
            True if connections are established successfully
        """
        with self._lock:
            current_time = time.time()

            # If already connected, return success
            if self._state.connected:
                return True

            # Check if we should retry connection (rate limiting)
            time_since_last_attempt = current_time - self._state.last_connection_attempt
            if time_since_last_attempt < self._connection_retry_delay:
                return False

            # Attempt to establish connections
            self._state.last_connection_attempt = current_time

            try:
                log.log_info("Initializing MCP connections...")

                # Load configuration and initialize connections
                if not self._mcp_service.load_configuration():
                    self._state.error_message = "Failed to load MCP configuration"
                    log.log_warn("No MCP configuration found")
                    return False

                # Initialize connections in background
                success = self._mcp_service.initialize_connections()

                if success:
                    self._state.connected = True
                    self._state.error_message = None
                    self._state.tools = []  # Reset cache
                    self._state.tools_cached_at = 0.0
                    log.log_info("MCP connections established successfully")
                    return True
                else:
                    self._state.error_message = "Failed to initialize MCP connections"
                    log.log_warn("MCP connection initialization failed")
                    return False

            except Exception as e:
                self._state.error_message = str(e)
                log.log_error(f"Exception during MCP connection: {e}")
                return False

    def get_connection_status(self) -> Dict[str, Any]:
        """
        Get detailed connection status for UI display.

        Returns:
            Dictionary with connection status information
        """
        with self._lock:
            status = {
                "connected": self._state.connected,
                "tools_count": len(self._state.tools),
                "last_attempt": self._state.last_connection_attempt,
                "cache_age": time.time() - self._state.tools_cached_at if self._state.tools_cached_at > 0 else 0,
                "error": self._state.error_message
            }

            if self._state.connected:
                # Get detailed server status
                server_statuses = self._mcp_service.get_all_connection_statuses()
                status["servers"] = server_statuses

            return status

    def _convert_tools_for_llm(self, mcp_tools: List) -> List[Dict[str, Any]]:
        """Convert MCP tools to OpenAI tool calling format"""
        llm_tools = []

        for tool in mcp_tools:
            try:
                # Base tool definition
                tool_def = {
                    "type": "function",
                    "function": {
                        "name": tool.name,
                        "description": tool.description or f"Tool from {tool.server_name}",
                    }
                }

                # Add schema if available
                if tool.schema and isinstance(tool.schema, dict):
                    # Convert MCP schema to OpenAI function calling schema
                    if "properties" in tool.schema:
                        tool_def["function"]["parameters"] = {
                            "type": "object",
                            "properties": tool.schema["properties"],
                            "required": tool.schema.get("required", [])
                        }
                    else:
                        # If no proper schema, create minimal one
                        tool_def["function"]["parameters"] = {
                            "type": "object",
                            "properties": {},
                            "required": []
                        }
                else:
                    # Default schema for tools without defined parameters
                    tool_def["function"]["parameters"] = {
                        "type": "object",
                        "properties": {},
                        "required": []
                    }

                llm_tools.append(tool_def)

            except Exception as e:
                log.log_error(f"Error converting tool {getattr(tool, 'name', 'unknown')} to LLM format: {e}")
                continue

        return llm_tools

    def disconnect(self):
        """
        Disconnect from all MCP servers and clean up resources.
        """
        with self._lock:
            if self._state.connected:
                try:
                    log.log_info("Disconnecting from MCP servers...")
                    self._mcp_service.shutdown()
                    self._state.connected = False
                    self._state.tools = []
                    self._state.tools_cached_at = 0.0
                    self._state.error_message = None
                    log.log_info("MCP connections closed")
                except Exception as e:
                    log.log_error(f"Error during MCP disconnect: {e}")

    def force_reconnect(self):
        """
        Force a reconnection attempt, bypassing retry delays.
        """
        with self._lock:
            log.log_info("Forcing MCP reconnection...")
            self._state.connected = False
            self._state.last_connection_attempt = 0.0
            self._state.tools = []
            self._state.tools_cached_at = 0.0
            self._state.error_message = None

            # Shutdown existing connections
            try:
                self._mcp_service.shutdown()
            except Exception as e:
                pass  # Ignore shutdown errors

            # Attempt new connection
            return self.ensure_connections()

    def get_tool_count(self) -> int:
        """
        Get the number of available MCP tools.

        Returns:
            Number of tools available, 0 if not connected
        """
        with self._lock:
            return len(self._state.tools) if self._state.connected else 0

    def __del__(self):
        """Cleanup on destruction"""
        try:
            self.disconnect()
        except:
            pass  # Ignore cleanup errors
