#!/usr/bin/env python3

"""
IDAssist MCP Server

SSE transport MCP server running inside IDA Pro that exposes IDA-specific
tools to external LLM clients (Claude Desktop, other MCP tools).

All tool handlers that modify the IDB use execute_on_main_thread().
"""

import asyncio
import threading
from typing import Optional

from src.ida_compat import log, execute_on_main_thread

try:
    from mcp.server import Server
    from mcp.server.sse import SseServerTransport
    from mcp.types import Tool, TextContent, Resource, ResourceTemplate
    _MCP_AVAILABLE = True
except ImportError:
    _MCP_AVAILABLE = False

try:
    from aiohttp import web
    _AIOHTTP_AVAILABLE = True
except ImportError:
    _AIOHTTP_AVAILABLE = False


class IDAssistMCPServer:
    """MCP server that runs inside IDA and exposes IDA tools."""

    def __init__(self, port: int = 8765):
        self.port = port
        self._server_thread: Optional[threading.Thread] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._runner: Optional[web.AppRunner] = None
        self._running = False

        if _MCP_AVAILABLE:
            self._mcp_server = Server("idassist-mcp")
            self._setup_handlers()
        else:
            self._mcp_server = None
            log.log_warn("MCP library not available - MCP server disabled")

    @property
    def is_running(self) -> bool:
        return self._running

    def _setup_handlers(self):
        """Register MCP tool and resource handlers."""
        from .tools import register_tools
        from .resources import register_resources

        register_tools(self._mcp_server)
        register_resources(self._mcp_server)

    def start(self, port: Optional[int] = None):
        """Start the MCP server in a background thread."""
        if not _MCP_AVAILABLE:
            log.log_error("Cannot start MCP server: mcp library not installed")
            return

        if not _AIOHTTP_AVAILABLE:
            log.log_error("Cannot start MCP server: aiohttp not installed")
            return

        if self._running:
            log.log_warn("MCP server is already running")
            return

        if port is not None:
            self.port = port

        self._server_thread = threading.Thread(
            target=self._run_server,
            daemon=True,
            name="IDAssist-MCP-Server"
        )
        self._server_thread.start()
        log.log_info(f"MCP server starting on port {self.port}")

    def _run_server(self):
        """Run the MCP server event loop in a background thread."""
        try:
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
            self._loop.run_until_complete(self._serve())
        except Exception as e:
            log.log_error(f"MCP server error: {e}")
        finally:
            self._running = False

    async def _serve(self):
        """Async server main loop."""
        sse = SseServerTransport("/messages/")

        app = web.Application()
        app.router.add_route("GET", "/sse", sse.handle_sse_connection)
        app.router.add_route("POST", "/messages/", sse.handle_post_message)

        # Health check endpoint
        async def health_handler(request):
            return web.json_response({"status": "ok", "server": "idassist-mcp"})
        app.router.add_route("GET", "/health", health_handler)

        self._runner = web.AppRunner(app)
        await self._runner.setup()

        site = web.TCPSite(self._runner, "0.0.0.0", self.port)
        await site.start()

        self._running = True
        log.log_info(f"MCP server listening on http://0.0.0.0:{self.port}")

        # Run the MCP server session handler
        try:
            async with sse.connect_sse(
                app._state.get("scope", {}),
                receive=None,
                send=None,
            ) as streams:
                await self._mcp_server.run(
                    streams[0],
                    streams[1],
                    self._mcp_server.create_initialization_options()
                )
        except Exception:
            # SSE transport handles connections individually
            # Keep server running until stop() is called
            while self._running:
                await asyncio.sleep(1)

    def stop(self):
        """Stop the MCP server."""
        if not self._running:
            return

        self._running = False

        if self._loop and self._runner:
            async def _cleanup():
                await self._runner.cleanup()

            try:
                future = asyncio.run_coroutine_threadsafe(_cleanup(), self._loop)
                future.result(timeout=5)
            except Exception as e:
                log.log_warn(f"Error stopping MCP server: {e}")

        if self._loop:
            self._loop.call_soon_threadsafe(self._loop.stop)

        log.log_info("MCP server stopped")
