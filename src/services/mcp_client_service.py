#!/usr/bin/env python3
"""
MCP Client Service for IDAssist.

This service provides a clean interface for MCP (Model Context Protocol) integration,
following the IDAssist SOA architecture patterns. Handles connection management,
tool discovery, and execution for multiple MCP servers.
"""

import asyncio
import concurrent.futures
import threading
import time
from typing import Dict, List, Optional, Any

try:
    import anyio
    ANYIO_AVAILABLE = True
except ImportError:
    ANYIO_AVAILABLE = False

from .settings_service import SettingsService
from .models.mcp_models import (
    MCPConfig, MCPServerConfig, MCPTool, MCPResource,
    MCPConnectionInfo, MCPConnectionStatus, MCPTestResult,
    MCPToolExecutionRequest, MCPToolExecutionResult
)
from .mcp_exceptions import (
    MCPError, MCPConnectionError, MCPToolError, MCPResourceError
)

from src.ida_compat import log


# Import MCP client implementation
try:
    from .mcp_client import MCPConnection
    MCP_CLIENT_AVAILABLE = True
except ImportError:
    log.log_warn("MCP client implementation not available")
    MCPConnection = None
    MCP_CLIENT_AVAILABLE = False


class MCPClientService:
    """
    MCP Client service providing clean interface for:
    - Connection lifecycle management
    - Tool discovery and execution
    - Settings integration
    - Health monitoring
    - Thread-safe operations
    """

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        """Singleton pattern implementation"""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        """Initialize the MCP client service"""
        if hasattr(self, '_initialized'):
            return

        self._initialized = True
        self._settings_service = SettingsService()
        self._config: Optional[MCPConfig] = None
        self._connections: Dict[str, MCPConnectionInfo] = {}
        self._managed_connections: Dict[str, MCPConnection] = {}
        self._connection_lock = threading.RLock()

        # Connection lifecycle state
        self._lifecycle_initialized = False
        self._lifecycle_lock = threading.Lock()
        self._connection_tasks: Dict[str, asyncio.Task] = {}
        self._shutdown_event = asyncio.Event()

        # Health monitoring
        self._last_health_check: Dict[str, float] = {}
        self._health_check_interval = 60.0  # seconds - less aggressive to avoid interfering with tool execution

        log.log_info("MCP Client Service initialized")

    # ===================================================================
    # Configuration Management
    # ===================================================================

    def load_configuration(self) -> bool:
        """Load MCP configuration from settings."""
        try:
            log.log_info("Loading MCP configuration from settings")

            # Load servers from settings using get_mcp_providers()
            servers_data = self._settings_service.get_mcp_providers()
            log.log_info(f"Loaded {len(servers_data)} MCP servers from settings")

            # Convert to server configs
            server_configs = []
            for server_data in servers_data:
                try:
                    # Convert settings format to MCPServerConfig format
                    config_dict = {
                        'name': server_data['name'],
                        'transport_type': server_data.get('transport', 'sse').lower(),
                        'enabled': server_data.get('enabled', True),
                        'url': server_data.get('url'),
                        'timeout': server_data.get('timeout', 30.0)
                    }

                    config = MCPServerConfig.from_dict(config_dict)
                    server_configs.append(config)
                except Exception as e:
                    log.log_error(f"Failed to load MCP server config: {e}")
                    continue

            # Create MCP config
            self._config = MCPConfig(servers=server_configs)

            log.log_info(f"Successfully loaded {len(server_configs)} MCP servers")
            return True

        except Exception as e:
            log.log_error(f"Failed to load MCP configuration: {e}")
            return False

    def save_configuration(self) -> bool:
        """Save current configuration to settings."""
        try:
            if self._config:
                servers_data = [server.to_dict() for server in self._config.servers]
                self._settings_service.set_json('mcp_servers', servers_data)
                log.log_info(f"Saved {len(servers_data)} MCP servers to settings")
                return True
            else:
                log.log_warn("No MCP config to save")
                return False
        except Exception as e:
            log.log_error(f"Failed to save MCP configuration: {e}")
            return False

    def get_configuration(self) -> Optional[MCPConfig]:
        """Get current MCP configuration."""
        return self._config

    def update_server_config(self, server_config: MCPServerConfig) -> bool:
        """Update or add a server configuration."""
        try:
            if not self._config:
                self._config = MCPConfig(servers=[])

            # Find existing server or add new one
            for i, existing in enumerate(self._config.servers):
                if existing.name == server_config.name:
                    self._config.servers[i] = server_config
                    log.log_info(f"Updated server config: {server_config.name}")
                    break
            else:
                self._config.servers.append(server_config)
                log.log_info(f"Added new server config: {server_config.name}")

            return self.save_configuration()

        except Exception as e:
            log.log_error(f"Failed to update server config: {e}")
            return False

    def remove_server_config(self, server_name: str) -> bool:
        """Remove a server configuration."""
        try:
            if not self._config:
                return False

            original_count = len(self._config.servers)
            self._config.servers = [s for s in self._config.servers if s.name != server_name]

            if len(self._config.servers) < original_count:
                log.log_info(f"Removed server config: {server_name}")
                return self.save_configuration()
            else:
                log.log_warn(f"Server config not found: {server_name}")
                return False

        except Exception as e:
            log.log_error(f"Failed to remove server config: {e}")
            return False

    # ===================================================================
    # Connection Testing (Synchronous Interface)
    # ===================================================================

    def test_server_connection(self, server_config: MCPServerConfig) -> MCPTestResult:
        """
        Test connection to an MCP server (synchronous).

        Args:
            server_config: Server configuration to test

        Returns:
            Test result with connection status and available tools/resources
        """
        if not MCP_CLIENT_AVAILABLE:
            return MCPTestResult.failure_result("MCP client implementation not available")

        log.log_info(f"Testing connection to MCP server: {server_config.name}")

        try:
            # Use anyio.run() to properly handle MCP's anyio-based async code
            # This ensures cancel scopes and other anyio internals work correctly
            if ANYIO_AVAILABLE:
                # anyio.run() creates a proper anyio event loop context
                def run_test_with_anyio():
                    return anyio.run(self._test_server_connection_async, server_config)

                try:
                    # Check if we're already in an event loop
                    asyncio.get_running_loop()
                    # We're in an event loop, run in separate thread to avoid nesting
                    with concurrent.futures.ThreadPoolExecutor() as executor:
                        future = executor.submit(run_test_with_anyio)
                        return future.result(timeout=15)
                except RuntimeError:
                    # No loop running, can run directly with anyio
                    return anyio.run(self._test_server_connection_async, server_config)
            else:
                # Fallback to raw asyncio (may have issues with anyio-based MCP)
                log.log_warn("anyio not available, falling back to raw asyncio")
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    return loop.run_until_complete(self._test_server_connection_async(server_config))
                finally:
                    loop.close()

        except Exception as e:
            log.log_error(f"Exception in test_server_connection: {e}")
            return MCPTestResult.failure_result(str(e))

    async def _test_server_connection_async(self, server_config: MCPServerConfig) -> MCPTestResult:
        """Test connection to MCP server asynchronously."""
        test_connection = None
        try:
            log.log_info(f"Creating test connection to {server_config.name}")

            # Create temporary connection for testing
            test_connection = MCPConnection(server_config)

            # Attempt connection with 10 second timeout
            try:
                success = await asyncio.wait_for(test_connection.connect(), timeout=10.0)
            except asyncio.TimeoutError:
                log.log_warn(f"Test connection timeout for {server_config.name} after 10 seconds")
                return MCPTestResult.failure_result("Connection test timed out after 10 seconds")

            if success:
                log.log_info(f"Test connection successful to {server_config.name}")

                # Get available tools and resources
                tools = list(test_connection.tools.values())
                resources = list(test_connection.resources.values())

                log.log_info(f"Found {len(tools)} tools and {len(resources)} resources")

                return MCPTestResult.success_result(tools, resources)
            else:
                log.log_warn(f"Test connection failed to {server_config.name}")
                return MCPTestResult.failure_result("Failed to connect to server")

        except asyncio.TimeoutError:
            # Catch timeout at outer level as well
            log.log_warn(f"Test connection timeout for {server_config.name}")
            return MCPTestResult.failure_result("Connection test timed out after 10 seconds")
        except Exception as e:
            log.log_error(f"Test connection error for {server_config.name}: {e}")
            return MCPTestResult.failure_result(str(e))
        finally:
            # Clean up test connection
            if test_connection:
                try:
                    await test_connection.disconnect()
                except Exception as cleanup_error:
                    pass  # Ignore cleanup errors

    # ===================================================================
    # Connection Management
    # ===================================================================

    def get_connection_status(self, server_name: str) -> MCPConnectionStatus:
        """Get connection status for a specific server."""
        with self._connection_lock:
            if server_name in self._connections:
                return self._connections[server_name].status
            return MCPConnectionStatus.DISCONNECTED

    def get_all_connection_statuses(self) -> Dict[str, MCPConnectionStatus]:
        """Get connection statuses for all configured servers."""
        with self._connection_lock:
            return {name: info.status for name, info in self._connections.items()}

    def initialize_connections(self) -> bool:
        """Initialize connections to all enabled servers."""
        with self._lifecycle_lock:
            if self._lifecycle_initialized:
                log.log_info("Connection lifecycle already initialized")
                return True

            if not MCP_CLIENT_AVAILABLE:
                log.log_error("Cannot initialize connections - MCP client not available")
                return False

            try:
                # Ensure configuration is loaded
                if not self._config:
                    if not self.load_configuration():
                        log.log_error("Cannot initialize - failed to load configuration")
                        return False

                # Run async initialization in thread
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(asyncio.run, self._initialize_connections_async())
                    result = future.result(timeout=60)  # 60 second timeout
                    self._lifecycle_initialized = result
                    return result

            except Exception as e:
                log.log_error(f"Failed to initialize connections: {e}")
                return False

    async def _initialize_connections_async(self) -> bool:
        """Initialize connections asynchronously."""
        try:
            log.log_info("Starting async connection initialization")

            # Connect to all enabled servers
            tasks = []
            for server_config in self._config.get_enabled_servers():
                task = asyncio.create_task(self._connect_server_async(server_config))
                tasks.append(task)

            if tasks:
                log.log_info(f"Connecting to {len(tasks)} enabled servers")
                results = await asyncio.gather(*tasks, return_exceptions=True)

                success_count = sum(1 for r in results if r is True)
                log.log_info(f"Connected to {success_count}/{len(tasks)} servers")

            # Start health monitoring (fire and forget)
            health_task = asyncio.create_task(self._health_monitor_loop())
            self._connection_tasks['health_monitor'] = health_task

            log.log_info("Connection initialization completed successfully")
            return True

        except Exception as e:
            log.log_error(f"Async connection initialization failed: {e}")
            return False

    async def _connect_server_async(self, server_config: MCPServerConfig) -> bool:
        """Connect to a specific server asynchronously."""
        try:
            log.log_info(f"Connecting to server: {server_config.name}")

            connection = MCPConnection(server_config)
            success = await connection.connect()

            if success:
                with self._connection_lock:
                    # Store managed connection
                    self._managed_connections[server_config.name] = connection

                    # Convert tools and resources to our format
                    mcp_tools = {}
                    for tool_name, tool_obj in connection.tools.items():
                        mcp_tool = MCPTool(
                            name=tool_name,
                            description=getattr(tool_obj, 'description', ''),
                            schema=getattr(tool_obj, 'schema', {}),
                            server_name=server_config.name
                        )
                        mcp_tools[tool_name] = mcp_tool

                    mcp_resources = {}
                    for res_uri, res_obj in connection.resources.items():
                        mcp_resource = MCPResource(
                            uri=res_uri,
                            name=getattr(res_obj, 'name', res_uri),
                            description=getattr(res_obj, 'description', None),
                            mime_type=getattr(res_obj, 'mime_type', None),
                            server_name=server_config.name
                        )
                        mcp_resources[res_uri] = mcp_resource

                    # Create connection info
                    connection_info = MCPConnectionInfo(
                        server_config=server_config,
                        status=MCPConnectionStatus.CONNECTED,
                        tools=mcp_tools,
                        resources=mcp_resources,
                        error_message=None
                    )
                    self._connections[server_config.name] = connection_info

                log.log_info(f"Connected to {server_config.name} with {len(connection.tools)} tools")
                return True
            else:
                log.log_error(f"Failed to connect to {server_config.name}")
                return False

        except Exception as e:
            log.log_error(f"Error connecting to {server_config.name}: {e}")
            return False

    # ===================================================================
    # Tool Discovery and Execution
    # ===================================================================

    def get_available_tools(self, server_filter: Optional[List[str]] = None) -> List[MCPTool]:
        """
        Get all available tools, optionally filtered by servers.

        Args:
            server_filter: Optional list of server names to include

        Returns:
            List of available MCP tools
        """
        tools = []

        with self._connection_lock:
            for connection_info in self._connections.values():
                if not connection_info.is_connected:
                    continue

                # Apply server filter if provided
                if server_filter and connection_info.server_config.name not in server_filter:
                    continue

                tools.extend(connection_info.tools.values())

        return tools

    def get_tools_for_llm(self, server_filter: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Get tools formatted for LLM integration in OpenAI format.

        Args:
            server_filter: Optional list of server names to include

        Returns:
            List of tool definitions in OpenAI format
        """
        tools = self.get_available_tools(server_filter)
        return [tool.to_llm_format() for tool in tools]

    def execute_tool(self, request: MCPToolExecutionRequest) -> MCPToolExecutionResult:
        """
        Execute an MCP tool (synchronous).

        Args:
            request: Tool execution request

        Returns:
            Tool execution result
        """
        start_time = time.time()

        try:
            log.log_info(f"Executing tool: {request.tool_name}")

            # Find the tool and its server
            tool_info = None
            server_name = None

            with self._connection_lock:
                for conn_name, connection_info in self._connections.items():
                    if not connection_info.is_connected:
                        continue

                    if request.tool_name in connection_info.tools:
                        tool_info = connection_info.tools[request.tool_name]
                        server_name = conn_name
                        break

            if not tool_info:
                raise MCPToolError(f"Tool '{request.tool_name}' not found in any connected server")

            # Get the managed connection
            if server_name not in self._managed_connections:
                raise MCPConnectionError(f"No managed connection for server '{server_name}'")

            connection = self._managed_connections[server_name]

            # Execute tool using thread executor
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(asyncio.run, self._execute_tool_async(connection, request))
                result = future.result(timeout=request.timeout)

            execution_time = time.time() - start_time
            log.log_info(f"Tool '{request.tool_name}' executed successfully in {execution_time:.2f}s")

            return MCPToolExecutionResult.success_result(
                result=result,
                execution_time=execution_time,
                server_name=server_name
            )

        except Exception as e:
            execution_time = time.time() - start_time
            log.log_error(f"Tool execution failed: {e}")

            return MCPToolExecutionResult.failure_result(
                error=str(e),
                execution_time=execution_time
            )

    async def _execute_tool_async(self, connection: MCPConnection, request: MCPToolExecutionRequest) -> Any:
        """Execute tool asynchronously with connection health verification."""
        try:

            # Verify connection health before executing
            if not self._verify_connection_health(connection):
                log.log_warn(f"Connection unhealthy, attempting to create fresh connection for tool execution")
                # Instead of using unhealthy connection, create a fresh one for this execution
                server_config = None
                if self._config:
                    for config in self._config.servers:
                        if hasattr(connection, 'config') and config.name == connection.config.name:
                            server_config = config
                            break

                if server_config:
                    return await self._execute_with_fresh_connection(server_config, request)
                else:
                    raise MCPConnectionError("Cannot find server config for fresh connection")

            result = await connection.call_tool(request.tool_name, request.arguments)
            return result
        except Exception as e:
            log.log_error(f"Async tool execution failed: {type(e).__name__}: {e}")

            # Check if this was a connection issue and try fresh connection as fallback
            error_type = type(e).__name__
            error_str = str(e)

            # Detect various connection-related errors
            is_connection_error = (
                "ClosedResourceError" in error_type or
                "ClosedResourceError" in error_str or
                "Connection" in error_str or
                "connection" in error_str.lower() or
                "stream" in error_str.lower() or
                "anyio" in error_str.lower()
            )

            if is_connection_error:
                log.log_info(f"Connection error detected ({error_type}), attempting fresh connection for {request.tool_name}")
                server_config = None
                if self._config and hasattr(connection, 'config'):
                    for config in self._config.servers:
                        if config.name == connection.config.name:
                            server_config = config
                            break

                if server_config:
                    try:
                        log.log_info(f"Creating fresh connection as fallback for {request.tool_name}")
                        return await self._execute_with_fresh_connection(server_config, request)
                    except Exception as fresh_error:
                        log.log_error(f"Fresh connection attempt also failed: {fresh_error}")
                        raise fresh_error
                else:
                    log.log_error(f"Cannot find server config for fresh connection fallback")

            raise

    # ===================================================================
    # Health Monitoring
    # ===================================================================

    async def _health_monitor_loop(self) -> None:
        """Background health monitoring loop."""
        log.log_info("Starting health monitoring loop")

        while not self._shutdown_event.is_set():
            try:
                await self._perform_health_checks()
                await asyncio.sleep(self._health_check_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                log.log_error(f"Error in health monitor: {e}")
                await asyncio.sleep(5)  # Brief pause before retry

        log.log_info("Health monitoring loop stopped")

    async def _perform_health_checks(self) -> None:
        """Perform health checks on all managed connections."""
        current_time = time.time()

        with self._connection_lock:
            for server_name, connection in self._managed_connections.copy().items():
                try:
                    # More thorough health check that doesn't interfere with active tool execution
                    if self._verify_connection_health(connection):
                        self._last_health_check[server_name] = current_time

                        # Update connection status
                        if server_name in self._connections:
                            self._connections[server_name].status = MCPConnectionStatus.CONNECTED
                    else:
                        # Don't immediately disconnect - connections might be temporarily busy
                        # Only disconnect if connection has been failing for extended period
                        last_good = self._last_health_check.get(server_name, 0)
                        if current_time - last_good > 120:  # 2 minutes of consecutive failures
                            log.log_warn(f"Connection {server_name} has been unhealthy for >2 minutes, handling failure")
                            await self._handle_connection_failure(server_name)

                except Exception as e:
                    log.log_error(f"Health check error for {server_name}: {e}")
                    # Only handle failure for repeated exceptions
                    last_good = self._last_health_check.get(server_name, 0)
                    if current_time - last_good > 120:  # 2 minutes of consecutive failures
                        await self._handle_connection_failure(server_name)

    async def _handle_connection_failure(self, server_name: str) -> None:
        """Handle connection failure."""
        log.log_warn(f"Handling connection failure for {server_name}")

        with self._connection_lock:
            # Update status
            if server_name in self._connections:
                self._connections[server_name].status = MCPConnectionStatus.FAILED

            # Clean up failed connection
            if server_name in self._managed_connections:
                try:
                    await self._managed_connections[server_name].disconnect()
                except:
                    pass  # Ignore disconnect errors
                del self._managed_connections[server_name]

        # Attempt reconnection
        if self._config:
            server_config = self._config.get_server_by_name(server_name)
            if server_config and server_config.enabled:
                log.log_info(f"Attempting to reconnect to {server_name}")
                await self._connect_server_async(server_config)

    def _verify_connection_health(self, connection: MCPConnection) -> bool:
        """Verify if a connection is healthy for tool execution."""
        try:
            # Check basic connection attributes
            if not hasattr(connection, 'connected') or not connection.connected:
                return False

            if not hasattr(connection, 'session') or not connection.session:
                return False

            # Check session streams if accessible
            session = connection.session
            try:
                # Try to access stream attributes if they exist
                if hasattr(session, '_read_stream') and hasattr(session, '_write_stream'):
                    read_stream = session._read_stream
                    write_stream = session._write_stream

                    # Check if streams have _closed attribute and are closed
                    if hasattr(read_stream, '_closed') and read_stream._closed:
                        return False
                    if hasattr(write_stream, '_closed') and write_stream._closed:
                        return False

                # Also check for anyio memory object states
                if hasattr(session, '_write_stream'):
                    write_stream = session._write_stream
                    # Check if it's a memory object stream that might be closed
                    if hasattr(write_stream, '_state'):
                        state = getattr(write_stream, '_state', None)
                        if state and hasattr(state, 'closed') and state.closed:
                            return False

            except Exception as stream_check_error:
                # If we can't check streams properly, assume connection might be problematic
                return False

            return True

        except Exception as e:
            return False

    async def _execute_with_fresh_connection(self, server_config, request: MCPToolExecutionRequest) -> Any:
        """Execute tool with a completely fresh connection."""
        fresh_connection = None
        try:
            log.log_info(f"Creating fresh connection for tool {request.tool_name} on {server_config.name}")

            # Create fresh connection
            fresh_connection = MCPConnection(server_config)

            # Connect to server
            success = await fresh_connection.connect()
            if not success:
                raise MCPConnectionError(f"Failed to establish fresh connection to {server_config.name}")

            log.log_info(f"Fresh connection established, executing {request.tool_name}")

            # Execute the tool
            result = await fresh_connection.call_tool(request.tool_name, request.arguments)
            log.log_info(f"Tool {request.tool_name} executed successfully via fresh connection")

            return result

        except Exception as e:
            log.log_error(f"Fresh connection execution failed: {e}")
            raise
        finally:
            # Always clean up the fresh connection
            if fresh_connection:
                try:
                    await fresh_connection.disconnect()
                except Exception as cleanup_error:
                    pass  # Ignore cleanup errors


    def shutdown(self) -> None:
        """Shutdown the MCP client service."""
        log.log_info("Shutting down MCP client service")

        try:
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(asyncio.run, self._shutdown_async())
                future.result(timeout=10)  # 10 second timeout
        except Exception as e:
            log.log_error(f"Error during shutdown: {e}")

    async def _shutdown_async(self) -> None:
        """Shutdown asynchronously."""
        # Signal shutdown
        self._shutdown_event.set()

        # Cancel background tasks
        for task_name, task in self._connection_tasks.items():
            if not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

        # Disconnect all connections
        with self._connection_lock:
            for server_name, connection in self._managed_connections.items():
                try:
                    await connection.disconnect()
                except Exception as e:
                    log.log_error(f"Error disconnecting from {server_name}: {e}")

            # Clear state
            self._managed_connections.clear()
            self._connections.clear()

        self._connection_tasks.clear()
        self._lifecycle_initialized = False

        log.log_info("MCP client service shutdown complete")
