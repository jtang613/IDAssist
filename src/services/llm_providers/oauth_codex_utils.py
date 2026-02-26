#!/usr/bin/env python3

"""
OAuth Utilities for OpenAI Codex Provider

Standalone OAuth helper functions for PKCE authentication with ChatGPT Pro/Plus.
Used by both ProviderDialog (for initial authentication) and the provider
(for token refresh).

Based on the official Codex CLI (codex-cli-rs) authentication implementation.
CRITICAL: The originator must be "codex_cli_rs" - the API validates this.

Supports two authentication modes:
1. Automatic callback: Uses local HTTP server to capture OAuth callback automatically
2. Manual fallback: User manually copies code from browser URL bar
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

# Official OpenAI OAuth Client ID (from opencode/Claude Code Codex plugin)
OAUTH_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"

# OAuth endpoints
OAUTH_AUTH_URL = "https://auth.openai.com/oauth/authorize"
OAUTH_TOKEN_URL = "https://auth.openai.com/oauth/token"
# Default localhost callback - used when callback server is running
# If server isn't running, user can manually copy code from browser URL bar
OAUTH_REDIRECT_URI = "http://localhost:1455/auth/callback"
OAUTH_CALLBACK_PATH = "/auth/callback"
OAUTH_CALLBACK_PORTS = [1455, 1456, 1457, 1458, 1459, 1460]
OAUTH_SCOPES = "openid profile email offline_access"


def get_redirect_uri(port: int = 1455) -> str:
    """
    Get redirect URI for given port.

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
    """Generate a random state parameter for CSRF protection."""
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()


def build_authorize_url(challenge: str, state: str, redirect_uri: Optional[str] = None) -> str:
    """
    Build the OAuth authorization URL.

    Args:
        challenge: PKCE code challenge
        state: Random state for CSRF protection
        redirect_uri: Optional custom redirect URI (defaults to OAUTH_REDIRECT_URI)

    Returns:
        Authorization URL to open in browser
    """
    if redirect_uri is None:
        redirect_uri = OAUTH_REDIRECT_URI

    params = {
        "response_type": "code",
        "client_id": OAUTH_CLIENT_ID,
        "redirect_uri": redirect_uri,
        "scope": OAUTH_SCOPES,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": state,
        # Special params for Codex flow (from codex-cli-rs)
        "id_token_add_organizations": "true",
        "codex_cli_simplified_flow": "true",
        "originator": "codex_cli_rs",  # CRITICAL: Must be codex_cli_rs
    }

    return f"{OAUTH_AUTH_URL}?{urlencode(params)}"


def open_auth_browser(challenge: str, state: str) -> str:
    """
    Open browser for OAuth authorization.

    Args:
        challenge: PKCE code challenge
        state: Random state for CSRF protection

    Returns:
        The authorization URL that was opened
    """
    auth_url = build_authorize_url(challenge, state)
    webbrowser.open(auth_url)
    return auth_url


# ============================================================================
# JWT Parsing Functions
# ============================================================================

def parse_jwt_claims(token: str) -> Optional[Dict[str, Any]]:
    """
    Parse claims from a JWT token (without verification).

    Args:
        token: JWT token string

    Returns:
        Dict of claims or None if parsing fails
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None

    try:
        # Add padding if needed
        payload = parts[1]
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += "=" * padding

        decoded = base64.urlsafe_b64decode(payload)
        return json.loads(decoded)
    except Exception:
        return None


def extract_account_id(tokens: Dict[str, Any]) -> Optional[str]:
    """
    Extract ChatGPT account ID from OAuth tokens.

    The account ID is needed for organization subscriptions and is
    sent in the ChatGPT-Account-Id header.

    Args:
        tokens: Token response containing id_token and/or access_token

    Returns:
        Account ID string or None if not found
    """
    # Try id_token first
    if "id_token" in tokens:
        claims = parse_jwt_claims(tokens["id_token"])
        if claims:
            account_id = _extract_account_id_from_claims(claims)
            if account_id:
                return account_id

    # Fall back to access_token
    if "access_token" in tokens:
        claims = parse_jwt_claims(tokens["access_token"])
        if claims:
            return _extract_account_id_from_claims(claims)

    return None


def _extract_account_id_from_claims(claims: Dict[str, Any]) -> Optional[str]:
    """
    Extract account ID from JWT claims.

    Checks multiple possible locations where OpenAI stores the account ID.
    """
    # Direct claim
    if "chatgpt_account_id" in claims:
        return claims["chatgpt_account_id"]

    # Nested in auth namespace
    auth_namespace = claims.get("https://api.openai.com/auth", {})
    if isinstance(auth_namespace, dict) and "chatgpt_account_id" in auth_namespace:
        return auth_namespace["chatgpt_account_id"]

    # From organizations array
    orgs = claims.get("organizations", [])
    if isinstance(orgs, list) and len(orgs) > 0:
        first_org = orgs[0]
        if isinstance(first_org, dict) and "id" in first_org:
            return first_org["id"]

    return None


# ============================================================================
# Token Exchange Functions
# ============================================================================

async def exchange_code_for_tokens(code: str, verifier: str, redirect_uri: Optional[str] = None) -> Dict[str, Any]:
    """
    Exchange authorization code for OAuth tokens.

    Args:
        code: Authorization code from callback
        verifier: PKCE code verifier
        redirect_uri: Optional custom redirect URI (must match the one used in authorize URL)

    Returns:
        Token response dict with access_token, refresh_token, id_token, expires_in

    Raises:
        Exception if token exchange fails
    """
    if not AIOHTTP_AVAILABLE:
        raise ImportError("aiohttp package required for OAuth. Install with: pip install aiohttp")

    if redirect_uri is None:
        redirect_uri = OAUTH_REDIRECT_URI

    # Form-encoded body (OpenAI uses form encoding, not JSON)
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": OAUTH_CLIENT_ID,
        "code_verifier": verifier,
    }

    async with aiohttp.ClientSession() as session:
        async with session.post(
            OAUTH_TOKEN_URL,
            data=data,  # Form-encoded
            headers={"Content-Type": "application/x-www-form-urlencoded"},
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

    # Form-encoded body
    data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": OAUTH_CLIENT_ID,
    }

    async with aiohttp.ClientSession() as session:
        async with session.post(
            OAUTH_TOKEN_URL,
            data=data,  # Form-encoded
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        ) as response:
            if not response.ok:
                text = await response.text()
                raise Exception(f"Token refresh failed: {response.status} - {text}")
            return await response.json()


# ============================================================================
# Credential Helpers
# ============================================================================

def create_credentials_json(tokens: Dict[str, Any], account_id: Optional[str] = None) -> str:
    """
    Create JSON string for storing OAuth credentials in api_key field.

    Args:
        tokens: Token response from exchange or refresh
        account_id: Optional account ID (extracted separately if not in tokens)

    Returns:
        JSON string with access_token, refresh_token, expires_at, account_id
    """
    expires_at = time.time() + tokens.get("expires_in", 3600)

    # Extract account_id from tokens if not provided
    if account_id is None:
        account_id = extract_account_id(tokens)

    credentials = {
        "access_token": tokens["access_token"],
        "refresh_token": tokens.get("refresh_token", ""),
        "expires_at": expires_at,
        "account_id": account_id,
    }

    return json.dumps(credentials)


def parse_credentials_json(api_key: str) -> Optional[Dict[str, Any]]:
    """
    Parse OAuth credentials from api_key field.

    Args:
        api_key: JSON string containing OAuth credentials

    Returns:
        Dict with access_token, refresh_token, expires_at, account_id, or None if invalid
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
        buffer_seconds: Consider expired if within this many seconds of expiry (default 5 min)

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
    2. Generates PKCE codes and state
    3. Opens the browser for user authorization
    4. Waits for the OAuth callback
    5. Exchanges the authorization code for tokens
    6. Extracts account ID from tokens

    Args:
        timeout: Seconds to wait for user to complete authentication (default 5 minutes)

    Returns:
        Dict containing:
        - access_token: OAuth access token
        - refresh_token: OAuth refresh token
        - expires_in: Token lifetime in seconds
        - id_token: OpenID Connect ID token
        - account_id: ChatGPT account ID (extracted from tokens)

    Raises:
        asyncio.TimeoutError: If user doesn't complete authentication in time
        RuntimeError: If no port is available for callback server
        ImportError: If aiohttp is not installed
        Exception: If OAuth flow fails at any step
    """
    from .oauth_callback_server import OAuthCallbackServer

    log.log_info("Starting OpenAI OAuth flow with automatic callback")

    # Generate PKCE codes and state
    verifier, challenge = generate_pkce()
    state = generate_state()

    # Start callback server
    server = OAuthCallbackServer(
        callback_path=OAUTH_CALLBACK_PATH,
        ports=OAUTH_CALLBACK_PORTS,
        timeout=timeout,
        provider_name="ChatGPT Pro/Plus"
    )

    try:
        # Start server and get redirect URI
        redirect_uri, port = await server.start()
        log.log_info(f"OAuth callback server started on port {port}")

        # Build and open authorization URL
        auth_url = build_authorize_url(challenge, state, redirect_uri)
        log.log_info("Opening browser for OpenAI authentication")
        webbrowser.open(auth_url)

        # Wait for callback
        log.log_info("Waiting for OAuth callback...")
        callback_params = await server.wait_for_callback()

        # Validate state parameter
        received_state = callback_params.get('state', '')
        if received_state != state:
            log.log_warn(f"State mismatch in OAuth callback (CSRF protection)")
            # Continue anyway - some OAuth implementations don't return state

        # Extract authorization code
        code = callback_params.get('code')
        if not code:
            raise Exception("No authorization code in callback")

        log.log_info("Received authorization code, exchanging for tokens...")

        # Exchange code for tokens
        tokens = await exchange_code_for_tokens(code, verifier, redirect_uri)

        # Extract account ID
        account_id = extract_account_id(tokens)
        if account_id:
            tokens['account_id'] = account_id
            log.log_info(f"Extracted ChatGPT account ID")
        else:
            log.log_warn("Could not extract account ID from tokens")

        log.log_info("OpenAI OAuth authentication completed successfully")
        return tokens

    finally:
        # Always stop the server
        await server.stop()
