#!/usr/bin/env python3

"""
OAuth Callback Server - Local HTTP server for capturing OAuth callbacks

This module provides a reusable async HTTP server that captures OAuth authorization
callbacks, eliminating the need for users to manually copy/paste authorization codes.

Features:
- Listens on configurable port with automatic fallback to alternative ports
- Captures code/state parameters from callback URL
- Returns user-friendly success/error HTML pages to browser
- Configurable timeout (default 5 minutes)
- Automatic cleanup on completion or timeout
"""

import asyncio
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import parse_qs

try:
    from aiohttp import web
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    web = None

from src.ida_compat import log


class OAuthCallbackServer:
    """
    Async HTTP server for capturing OAuth callbacks.

    This server temporarily listens on localhost to capture the OAuth authorization
    callback, extract the authorization code, and return a success page to the browser.

    Usage:
        server = OAuthCallbackServer()
        redirect_uri, port = await server.start()
        # ... open browser with redirect_uri ...
        callback_params = await server.wait_for_callback()
        await server.stop()
    """

    DEFAULT_PORTS = [1455, 1456, 1457, 1458, 1459, 1460]
    DEFAULT_TIMEOUT = 300  # 5 minutes

    def __init__(self,
                 callback_path: str = "/callback",
                 ports: Optional[List[int]] = None,
                 timeout: int = DEFAULT_TIMEOUT,
                 provider_name: str = "OAuth"):
        """
        Initialize the OAuth callback server.

        Args:
            callback_path: URL path for callback (e.g., "/callback" or "/auth/callback")
            ports: List of ports to try (default: 1455-1460)
            timeout: Seconds to wait for callback (default: 300)
            provider_name: Name of provider for display in success page
        """
        if not AIOHTTP_AVAILABLE:
            raise ImportError("aiohttp package required for OAuth callback server. Install with: pip install aiohttp")

        self.callback_path = callback_path
        self.ports = ports or self.DEFAULT_PORTS
        self.timeout = timeout
        self.provider_name = provider_name

        # Server state
        self.app: Optional[web.Application] = None
        self.runner: Optional[web.AppRunner] = None
        self.site: Optional[web.TCPSite] = None
        self.bound_port: Optional[int] = None

        # Callback result
        self._result_future: Optional[asyncio.Future] = None
        self._is_running = False

    async def start(self) -> Tuple[str, int]:
        """
        Start the callback server.

        Attempts to bind to ports in order until one succeeds.

        Returns:
            Tuple of (redirect_uri, port) that was successfully bound

        Raises:
            RuntimeError: If no port is available
        """
        if self._is_running:
            raise RuntimeError("Server is already running")

        # Create the aiohttp application
        self.app = web.Application()
        self.app.router.add_get(self.callback_path, self._handle_callback)

        # Create the result future
        self._result_future = asyncio.get_event_loop().create_future()

        # Try each port in order
        last_error = None
        for port in self.ports:
            try:
                self.runner = web.AppRunner(self.app)
                await self.runner.setup()

                self.site = web.TCPSite(self.runner, 'localhost', port)
                await self.site.start()

                self.bound_port = port
                self._is_running = True

                redirect_uri = f"http://localhost:{port}{self.callback_path}"
                log.log_info(f"OAuth callback server started on port {port}")

                return (redirect_uri, port)

            except OSError as e:
                # Port in use or other binding error
                last_error = e
                log.log_debug(f"Port {port} unavailable: {e}")

                # Clean up failed attempt
                if self.runner:
                    await self.runner.cleanup()
                    self.runner = None
                continue

        # No port available
        raise RuntimeError(f"No available port in range {self.ports}. Last error: {last_error}")

    async def wait_for_callback(self) -> Dict[str, str]:
        """
        Wait for the OAuth callback.

        Blocks until a callback is received, timeout is reached, or cancelled.

        Returns:
            Dict with 'code', 'state', and any other query parameters

        Raises:
            asyncio.TimeoutError: If timeout exceeded before callback received
            asyncio.CancelledError: If the wait was cancelled (e.g., user cancelled)
            Exception: If callback contains an error parameter
        """
        if not self._is_running:
            raise RuntimeError("Server is not running. Call start() first.")

        if self._result_future is None:
            raise RuntimeError("Result future not initialized")

        try:
            result = await asyncio.wait_for(self._result_future, timeout=self.timeout)
            return result
        except asyncio.TimeoutError:
            log.log_warn(f"OAuth callback timed out after {self.timeout} seconds")
            raise
        except asyncio.CancelledError:
            log.log_info("OAuth callback wait was cancelled")
            raise

    async def stop(self):
        """Stop the server and cleanup resources."""
        if not self._is_running:
            return

        self._is_running = False

        if self.site:
            await self.site.stop()
            self.site = None

        if self.runner:
            await self.runner.cleanup()
            self.runner = None

        self.app = None
        self.bound_port = None

        # Cancel pending future if not done
        if self._result_future and not self._result_future.done():
            self._result_future.cancel()
        self._result_future = None

        log.log_info("OAuth callback server stopped")

    async def _handle_callback(self, request: web.Request) -> web.Response:
        """
        Handle the incoming OAuth callback request.

        Extracts query parameters, checks for errors, and signals completion.
        """
        try:
            # Parse query parameters
            params = {}
            for key, values in request.query.items():
                # Take first value for each key
                params[key] = values if isinstance(values, str) else values[0] if values else ""

            log.log_debug(f"OAuth callback received with params: {list(params.keys())}")

            # Check for OAuth error
            if 'error' in params:
                error_msg = params.get('error_description', params['error'])
                log.log_error(f"OAuth callback error: {error_msg}")

                # Set error on future
                if self._result_future and not self._result_future.done():
                    self._result_future.set_exception(Exception(f"OAuth error: {error_msg}"))

                return web.Response(
                    text=self._generate_error_html(error_msg),
                    content_type='text/html',
                    status=400
                )

            # Validate required parameters
            if 'code' not in params:
                error_msg = "Missing authorization code in callback"
                log.log_error(error_msg)

                if self._result_future and not self._result_future.done():
                    self._result_future.set_exception(Exception(error_msg))

                return web.Response(
                    text=self._generate_error_html(error_msg),
                    content_type='text/html',
                    status=400
                )

            # Success - set result on future
            if self._result_future and not self._result_future.done():
                self._result_future.set_result(params)

            log.log_info("OAuth callback received successfully")

            return web.Response(
                text=self._generate_success_html(),
                content_type='text/html',
                status=200
            )

        except Exception as e:
            log.log_error(f"Error handling OAuth callback: {e}")

            if self._result_future and not self._result_future.done():
                self._result_future.set_exception(e)

            return web.Response(
                text=self._generate_error_html(str(e)),
                content_type='text/html',
                status=500
            )

    def _generate_success_html(self) -> str:
        """Generate HTML page shown after successful authentication."""
        return f'''<!DOCTYPE html>
<html>
<head>
    <title>Authentication Successful - IDAssist</title>
    <meta charset="utf-8">
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }}
        .container {{
            background: white;
            padding: 50px 40px;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            text-align: center;
            max-width: 450px;
            width: 100%;
        }}
        .checkmark {{
            width: 80px;
            height: 80px;
            background: linear-gradient(135deg, #4CAF50 0%, #45a049 100%);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 25px;
            box-shadow: 0 4px 15px rgba(76, 175, 80, 0.4);
        }}
        .checkmark svg {{
            width: 40px;
            height: 40px;
            fill: white;
        }}
        h1 {{
            color: #1a1a2e;
            font-size: 24px;
            font-weight: 600;
            margin-bottom: 12px;
        }}
        .provider {{
            color: #667eea;
            font-weight: 600;
        }}
        p {{
            color: #666;
            font-size: 16px;
            line-height: 1.6;
            margin-bottom: 8px;
        }}
        .hint {{
            color: #999;
            font-size: 14px;
            margin-top: 20px;
            padding-top: 20px;
            border-top: 1px solid #eee;
        }}
        .app-name {{
            color: #764ba2;
            font-weight: 600;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="checkmark">
            <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                <path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/>
            </svg>
        </div>
        <h1>Authentication Successful</h1>
        <p>You have successfully authenticated with <span class="provider">{self.provider_name}</span>.</p>
        <p class="hint">You can close this tab and return to <span class="app-name">IDA Pro</span>.</p>
    </div>
</body>
</html>'''

    def _generate_error_html(self, error: str) -> str:
        """Generate HTML page shown when authentication fails."""
        # Escape HTML special characters in error message
        import html
        safe_error = html.escape(error)

        return f'''<!DOCTYPE html>
<html>
<head>
    <title>Authentication Failed - IDAssist</title>
    <meta charset="utf-8">
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }}
        .container {{
            background: white;
            padding: 50px 40px;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            text-align: center;
            max-width: 450px;
            width: 100%;
        }}
        .error-icon {{
            width: 80px;
            height: 80px;
            background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 25px;
            box-shadow: 0 4px 15px rgba(231, 76, 60, 0.4);
        }}
        .error-icon svg {{
            width: 40px;
            height: 40px;
            fill: white;
        }}
        h1 {{
            color: #1a1a2e;
            font-size: 24px;
            font-weight: 600;
            margin-bottom: 12px;
        }}
        p {{
            color: #666;
            font-size: 16px;
            line-height: 1.6;
            margin-bottom: 8px;
        }}
        .error-details {{
            background: #fff5f5;
            border: 1px solid #feb2b2;
            border-radius: 8px;
            padding: 15px;
            margin: 20px 0;
            color: #c53030;
            font-size: 14px;
            word-break: break-word;
        }}
        .hint {{
            color: #999;
            font-size: 14px;
            margin-top: 20px;
            padding-top: 20px;
            border-top: 1px solid #eee;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="error-icon">
            <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                <path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/>
            </svg>
        </div>
        <h1>Authentication Failed</h1>
        <p>An error occurred during authentication.</p>
        <div class="error-details">{safe_error}</div>
        <p class="hint">Please close this tab and try again in IDA Pro.</p>
    </div>
</body>
</html>'''


async def run_callback_server_with_timeout(
    callback_path: str = "/auth/callback",
    ports: Optional[List[int]] = None,
    timeout: int = 300,
    provider_name: str = "OAuth"
) -> Tuple[str, Dict[str, str]]:
    """
    Convenience function to run the callback server and wait for a callback.

    This is a helper that handles the full lifecycle:
    1. Start server
    2. Return redirect URI for caller to use
    3. Wait for callback
    4. Stop server
    5. Return callback parameters

    Args:
        callback_path: URL path for callback
        ports: List of ports to try
        timeout: Seconds to wait for callback
        provider_name: Name for success page display

    Returns:
        Tuple of (redirect_uri, callback_params)

    Raises:
        RuntimeError: If no port available
        asyncio.TimeoutError: If timeout exceeded
        Exception: If callback contains error
    """
    server = OAuthCallbackServer(
        callback_path=callback_path,
        ports=ports,
        timeout=timeout,
        provider_name=provider_name
    )

    try:
        redirect_uri, port = await server.start()
        params = await server.wait_for_callback()
        return (redirect_uri, params)
    finally:
        await server.stop()
