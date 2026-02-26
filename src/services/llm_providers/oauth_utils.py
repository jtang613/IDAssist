#!/usr/bin/env python3

"""
OAuth Utilities for Anthropic OAuth Provider

Standalone OAuth helper functions for PKCE authentication with Claude Pro/Max.
Used by both ProviderDialog (for initial authentication) and the provider
(for token refresh).

Based on the opencode-anthropic-auth implementation.

Supports two authentication modes:
1. Automatic callback: Uses local HTTP server to capture OAuth callback automatically
2. Manual fallback: Uses Anthropic's hosted callback page where user copies the code
"""

import base64
import hashlib
import json
import secrets
import time
import webbrowser
from typing import Dict, Any, Tuple, Optional, List
from urllib.parse import urlencode

from src.ida_compat import log

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False


# ============================================================================
# OAuth Configuration
# ============================================================================

# Official Anthropic OAuth Client ID (from Claude Code/OpenCode)
OAUTH_CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"

# OAuth endpoints
OAUTH_AUTH_URL = "https://claude.ai/oauth/authorize"
OAUTH_TOKEN_URL = "https://console.anthropic.com/v1/oauth/token"
# Default redirect URI - Anthropic's hosted callback page (for manual flow)
OAUTH_REDIRECT_URI = "https://console.anthropic.com/oauth/code/callback"
# Local callback for automatic flow
OAUTH_CALLBACK_PATH = "/callback"
OAUTH_CALLBACK_PORTS = [1456, 1457, 1458, 1459, 1460, 1461]  # Different range from OpenAI
OAUTH_SCOPES = "user:profile user:inference user:sessions:claude_code"


def get_redirect_uri(port: int = 1456) -> str:
    """
    Get local redirect URI for given port.

    Args:
        port: Port number for localhost callback

    Returns:
        Redirect URI string
    """
    return f"http://localhost:{port}{OAUTH_CALLBACK_PATH}"


# ============================================================================
# PKCE Functions
# ============================================================================

def generate_pkce() -> Tuple[str, str]:
    """
    Generate PKCE code verifier and challenge.

    Returns:
        Tuple of (verifier, challenge)
    """
    # Generate a random verifier (43 characters, matching openauth library)
    verifier = secrets.token_urlsafe(32)

    # Generate SHA-256 challenge
    challenge_bytes = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(challenge_bytes).rstrip(b"=").decode()

    return verifier, challenge


def generate_state() -> str:
    """
    Generate a random state parameter for CSRF protection.

    Returns:
        Random URL-safe string
    """
    return secrets.token_urlsafe(32)


def build_authorize_url(challenge: str, state: str, redirect_uri: Optional[str] = None) -> str:
    """
    Build the OAuth authorization URL.

    Args:
        challenge: PKCE code challenge
        state: Random state parameter for CSRF protection
        redirect_uri: Optional custom redirect URI (defaults to OAUTH_REDIRECT_URI)

    Returns:
        Authorization URL to open in browser
    """
    if redirect_uri is None:
        redirect_uri = OAUTH_REDIRECT_URI

    params = {
        "code": "true",  # Request authorization code display
        "client_id": OAUTH_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": OAUTH_SCOPES,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": state,
    }

    return f"{OAUTH_AUTH_URL}?{urlencode(params)}"


def open_auth_browser(challenge: str, state: str) -> str:
    """
    Open browser for OAuth authorization.

    Args:
        challenge: PKCE code challenge
        state: Random state parameter for CSRF protection

    Returns:
        The authorization URL that was opened
    """
    auth_url = build_authorize_url(challenge, state)
    webbrowser.open(auth_url)
    return auth_url


# ============================================================================
# Token Exchange Functions
# ============================================================================

async def exchange_code_for_tokens(code: str, verifier: str, state: str, redirect_uri: Optional[str] = None) -> Dict[str, Any]:
    """
    Exchange authorization code for OAuth tokens.

    Args:
        code: Authorization code from callback
        verifier: PKCE code verifier
        state: State parameter from callback (for validation)
        redirect_uri: Optional custom redirect URI (must match the one used in authorize URL)

    Returns:
        Token response dict with access_token, refresh_token, expires_in

    Raises:
        Exception if token exchange fails
    """
    if not AIOHTTP_AVAILABLE:
        raise ImportError("aiohttp package required for OAuth. Install with: pip install aiohttp")

    if redirect_uri is None:
        redirect_uri = OAUTH_REDIRECT_URI

    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": OAUTH_CLIENT_ID,
        "code_verifier": verifier,
        "state": state,
    }

    async with aiohttp.ClientSession() as session:
        async with session.post(
            OAUTH_TOKEN_URL,
            json=data,
            headers={"Content-Type": "application/json"},
        ) as response:
            if not response.ok:
                text = await response.text()
                raise Exception(f"Token exchange failed: {response.status} - {text}")
            return await response.json()


async def refresh_access_token(refresh_token: str) -> Dict[str, Any]:
    """
    Refresh an expired access token.

    Args:
        refresh_token: OAuth refresh token

    Returns:
        Token response dict with new access_token, optional new refresh_token

    Raises:
        Exception if token refresh fails
    """
    if not AIOHTTP_AVAILABLE:
        raise ImportError("aiohttp package required for OAuth. Install with: pip install aiohttp")

    data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": OAUTH_CLIENT_ID,
    }

    async with aiohttp.ClientSession() as session:
        async with session.post(
            OAUTH_TOKEN_URL,
            json=data,
            headers={"Content-Type": "application/json"},
        ) as response:
            if not response.ok:
                text = await response.text()
                raise Exception(f"Token refresh failed: {response.status} - {text}")
            return await response.json()


# ============================================================================
# Credential Helpers
# ============================================================================

def create_credentials_json(tokens: Dict[str, Any]) -> str:
    """
    Create JSON string for storing OAuth credentials in api_key field.

    Args:
        tokens: Token response from exchange or refresh

    Returns:
        JSON string with access_token, refresh_token, expires_at
    """
    expires_at = time.time() + tokens.get("expires_in", 3600)

    credentials = {
        "access_token": tokens["access_token"],
        "refresh_token": tokens.get("refresh_token", ""),
        "expires_at": expires_at
    }

    return json.dumps(credentials)


def parse_credentials_json(api_key: str) -> Optional[Dict[str, Any]]:
    """
    Parse OAuth credentials from api_key field.

    Args:
        api_key: JSON string containing OAuth credentials

    Returns:
        Dict with access_token, refresh_token, expires_at, or None if invalid
    """
    if not api_key:
        return None

    try:
        credentials = json.loads(api_key)
        # Validate required fields
        if not credentials.get("access_token"):
            return None
        return credentials
    except json.JSONDecodeError:
        return None


def is_token_expired(credentials: Dict[str, Any], buffer_seconds: int = 300) -> bool:
    """
    Check if OAuth token is expired or about to expire.

    Args:
        credentials: Parsed credentials dict
        buffer_seconds: Consider expired if within this many seconds of expiry

    Returns:
        True if token is expired or about to expire
    """
    expires_at = credentials.get("expires_at", 0)
    return time.time() >= expires_at - buffer_seconds


# ============================================================================
# Automatic OAuth Flow with Callback Server
# ============================================================================

async def authenticate_with_callback(timeout: int = 300) -> Dict[str, Any]:
    """
    Complete OAuth flow with automatic callback capture.

    This function handles the entire OAuth flow automatically:
    1. Starts a local HTTP server to capture the callback
    2. Generates PKCE codes and state parameter
    3. Opens the browser for user authorization
    4. Waits for the OAuth callback
    5. Validates state parameter
    6. Exchanges the authorization code for tokens

    Args:
        timeout: Seconds to wait for user to complete authentication (default 5 minutes)

    Returns:
        Dict containing:
        - access_token: OAuth access token
        - refresh_token: OAuth refresh token
        - expires_in: Token lifetime in seconds

    Raises:
        asyncio.TimeoutError: If user doesn't complete authentication in time
        RuntimeError: If no port is available for callback server
        ImportError: If aiohttp is not installed
        Exception: If OAuth flow fails
    """
    from .oauth_callback_server import OAuthCallbackServer

    log.log_info("Starting Anthropic OAuth flow with automatic callback")

    # Generate PKCE codes and state
    verifier, challenge = generate_pkce()
    state = generate_state()

    # Start callback server
    server = OAuthCallbackServer(
        callback_path=OAUTH_CALLBACK_PATH,
        ports=OAUTH_CALLBACK_PORTS,
        timeout=timeout,
        provider_name="Claude Pro/Max"
    )

    try:
        # Start server and get redirect URI
        redirect_uri, port = await server.start()
        log.log_info(f"OAuth callback server started on port {port}")

        # Build and open authorization URL
        auth_url = build_authorize_url(challenge, state, redirect_uri)
        log.log_info("Opening browser for Anthropic authentication")
        webbrowser.open(auth_url)

        # Wait for callback
        log.log_info("Waiting for OAuth callback...")
        callback_params = await server.wait_for_callback()

        # Extract authorization code
        code = callback_params.get('code')
        if not code:
            raise Exception("No authorization code in callback")

        # Validate state parameter to prevent CSRF attacks
        returned_state = callback_params.get('state', '')
        if returned_state != state:
            raise Exception("State mismatch - possible CSRF attack")

        log.log_info("Received authorization code, exchanging for tokens...")

        # Exchange code for tokens
        tokens = await exchange_code_for_tokens(code, verifier, state, redirect_uri)

        log.log_info("Anthropic OAuth authentication completed successfully")
        return tokens

    finally:
        # Always stop the server
        await server.stop()
