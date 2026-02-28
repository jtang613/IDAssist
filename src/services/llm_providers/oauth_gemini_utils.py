#!/usr/bin/env python3

"""
OAuth Utilities for Google Gemini OAuth Provider

Standalone OAuth helper functions for Google Gemini CLI authentication.
Used by both ProviderDialog (for initial authentication) and the provider
(for token refresh).

Supports two authentication modes:
1. Browser mode (automatic callback): NO PKCE, state-only CSRF protection
2. Headless mode (manual entry): WITH PKCE S256, codeassist.google.com redirect

Key difference from Anthropic/OpenAI OAuth: Gemini uses client_secret in
token exchange (form-encoded), not JSON. It's an "installed app" OAuth client.
"""

import base64
import hashlib
import json
import os
import platform
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
# OAuth Configuration - Official Gemini CLI Client (installed app - safe to embed)
# ============================================================================

OAUTH_CLIENT_ID = "681255809395-oo8ft2oprdrnp9e3aqf6av3hmdib135j.apps.googleusercontent.com"
OAUTH_CLIENT_SECRET = "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"

OAUTH_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
OAUTH_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
OAUTH_SCOPES = "https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile"

# Headless mode redirect (user copies code from browser)
OAUTH_HEADLESS_REDIRECT_URI = "https://codeassist.google.com/authcode"

# Local callback for automatic (browser) flow
OAUTH_CALLBACK_PATH = "/callback"
OAUTH_CALLBACK_PORTS = [1462, 1463, 1464, 1465, 1466, 1467]

# User info endpoint
USER_INFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"

# Code Assist endpoints
CODE_ASSIST_ENDPOINT = "https://cloudcode-pa.googleapis.com"
CODE_ASSIST_API_VERSION = "v1internal"


# ============================================================================
# PKCE Functions (for headless mode only)
# ============================================================================

def generate_pkce() -> Tuple[str, str]:
    """
    Generate PKCE code verifier and challenge.
    Used only in headless/manual mode.

    Returns:
        Tuple of (verifier, challenge)
    """
    verifier = secrets.token_urlsafe(32)
    challenge_bytes = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(challenge_bytes).rstrip(b"=").decode()
    return verifier, challenge


def generate_state() -> str:
    """
    Generate a random state parameter for CSRF protection.

    Returns:
        Random hex string (matches Gemini CLI format)
    """
    return secrets.token_hex(32)


# ============================================================================
# Authorization URL Builders
# ============================================================================

def build_browser_auth_url(state: str, redirect_uri: str) -> str:
    """
    Build browser mode authorization URL.
    Browser mode: NO PKCE, just state + access_type=offline.

    Args:
        state: Random state parameter for CSRF protection
        redirect_uri: Local callback URI

    Returns:
        Authorization URL to open in browser
    """
    params = {
        "client_id": OAUTH_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": OAUTH_SCOPES,
        "state": state,
        "access_type": "offline",
    }
    return f"{OAUTH_AUTH_ENDPOINT}?{urlencode(params)}"


def build_headless_auth_url(challenge: str, state: str) -> str:
    """
    Build headless mode authorization URL.
    Headless mode: WITH PKCE S256 + access_type=offline.

    Args:
        challenge: PKCE code challenge
        state: Random state parameter for CSRF protection

    Returns:
        Authorization URL to open in browser
    """
    params = {
        "client_id": OAUTH_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": OAUTH_HEADLESS_REDIRECT_URI,
        "scope": OAUTH_SCOPES,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": state,
        "access_type": "offline",
    }
    return f"{OAUTH_AUTH_ENDPOINT}?{urlencode(params)}"


def open_headless_auth_browser(challenge: str, state: str) -> str:
    """
    Open browser for headless OAuth authorization.

    Args:
        challenge: PKCE code challenge
        state: Random state parameter

    Returns:
        The authorization URL that was opened
    """
    auth_url = build_headless_auth_url(challenge, state)
    webbrowser.open(auth_url)
    return auth_url


# ============================================================================
# Token Exchange Functions
# ============================================================================

async def exchange_code_for_tokens(code: str, redirect_uri: str,
                                    code_verifier: Optional[str] = None) -> Dict[str, Any]:
    """
    Exchange authorization code for OAuth tokens.
    Uses form-encoded POST with client_secret (installed app flow).

    Args:
        code: Authorization code from callback
        redirect_uri: Redirect URI used in the auth request
        code_verifier: PKCE code verifier (only for headless mode)

    Returns:
        Token response dict with access_token, refresh_token, expires_in

    Raises:
        Exception if token exchange fails
    """
    if not AIOHTTP_AVAILABLE:
        raise ImportError("aiohttp package required for OAuth. Install with: pip install aiohttp")

    data = {
        "client_id": OAUTH_CLIENT_ID,
        "client_secret": OAUTH_CLIENT_SECRET,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": redirect_uri,
    }

    if code_verifier:
        data["code_verifier"] = code_verifier

    async with aiohttp.ClientSession() as session:
        async with session.post(
            OAUTH_TOKEN_ENDPOINT,
            data=data,  # form-encoded, not JSON
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        ) as response:
            if not response.ok:
                text = await response.text()
                raise Exception(f"Token exchange failed: {response.status} - {text}")
            return await response.json()


async def refresh_access_token(refresh_token: str) -> Dict[str, Any]:
    """
    Refresh an expired access token.
    Uses form-encoded POST with client_secret.

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
        "client_secret": OAUTH_CLIENT_SECRET,
    }

    async with aiohttp.ClientSession() as session:
        async with session.post(
            OAUTH_TOKEN_ENDPOINT,
            data=data,  # form-encoded
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        ) as response:
            if not response.ok:
                text = await response.text()
                raise Exception(f"Token refresh failed: {response.status} - {text}")
            return await response.json()


# ============================================================================
# User Info & Code Assist Setup
# ============================================================================

async def fetch_user_info(access_token: str) -> Optional[str]:
    """
    Fetch user email from Google's userinfo endpoint.

    Args:
        access_token: Valid OAuth access token

    Returns:
        User email string, or None if unavailable
    """
    if not AIOHTTP_AVAILABLE:
        return None

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                USER_INFO_URL,
                headers={"Authorization": f"Bearer {access_token}"},
            ) as response:
                if response.ok:
                    data = await response.json()
                    return data.get("email")
    except Exception as e:
        log.log_warn(f"Could not fetch user info: {e}")
    return None


def _get_os_platform() -> str:
    """Get OS platform string matching Gemini CLI format."""
    system = platform.system().lower()
    if "linux" in system:
        return "linux"
    elif "darwin" in system:
        return "darwin"
    elif "win" in system:
        return "win32"
    return system


def _get_os_arch() -> str:
    """Get OS architecture string matching Gemini CLI format."""
    machine = platform.machine().lower()
    if machine in ("amd64", "x86_64"):
        return "x86_64"
    elif machine in ("aarch64", "arm64"):
        return "arm64"
    return machine


async def setup_user(access_token: str) -> Dict[str, Any]:
    """
    Setup user via Code Assist endpoints (loadCodeAssist + onboardUser).
    Discovers the user's project ID and tier.

    Args:
        access_token: Valid OAuth access token

    Returns:
        Dict with project_id, tier, tier_name
    """
    if not AIOHTTP_AVAILABLE:
        return {}

    result = {"project_id": "", "tier": "", "tier_name": ""}
    ua = f"GeminiCLI/1.0.0/gemini-2.5-flash ({_get_os_platform()}; {_get_os_arch()})"

    # Check environment for project ID
    env_project = os.environ.get("GOOGLE_CLOUD_PROJECT") or os.environ.get("GOOGLE_CLOUD_PROJECT_ID") or ""

    try:
        # Step 1: loadCodeAssist
        load_body = {}
        metadata = {
            "ideType": "IDE_UNSPECIFIED",
            "platform": "PLATFORM_UNSPECIFIED",
            "pluginType": "GEMINI",
        }
        if env_project:
            load_body["cloudaicompanionProject"] = env_project
            metadata["duetProject"] = env_project
        load_body["metadata"] = metadata

        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{CODE_ASSIST_ENDPOINT}/{CODE_ASSIST_API_VERSION}:loadCodeAssist",
                json=load_body,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json",
                    "User-Agent": ua,
                },
            ) as response:
                if not response.ok:
                    log.log_debug(f"loadCodeAssist failed: {response.status}")
                    result["project_id"] = env_project
                    return result
                load_result = await response.json()

        # Check if user already has a current tier
        if load_result.get("currentTier"):
            result["project_id"] = load_result.get("cloudaicompanionProject", env_project)
            effective_tier = load_result.get("paidTier") or load_result.get("currentTier", {})
            result["tier"] = effective_tier.get("id", "")
            result["tier_name"] = effective_tier.get("name", "")
            log.log_info(f"Code Assist project: {result['project_id']}, tier: {result['tier']}")
            return result

        # Step 2: onboardUser - find default tier
        onboard_tier_id = "LEGACY"
        onboard_tier_name = ""
        for tier in load_result.get("allowedTiers", []):
            if tier.get("isDefault"):
                onboard_tier_id = tier.get("id", "LEGACY")
                onboard_tier_name = tier.get("name", "")
                break

        log.log_info(f"Onboarding user for tier: {onboard_tier_id}")

        onboard_body = {"tierId": onboard_tier_id}
        onboard_metadata = {
            "ideType": "IDE_UNSPECIFIED",
            "platform": "PLATFORM_UNSPECIFIED",
            "pluginType": "GEMINI",
        }
        if onboard_tier_id != "FREE" and env_project:
            onboard_body["cloudaicompanionProject"] = env_project
            onboard_metadata["duetProject"] = env_project
        onboard_body["metadata"] = onboard_metadata

        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{CODE_ASSIST_ENDPOINT}/{CODE_ASSIST_API_VERSION}:onboardUser",
                json=onboard_body,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json",
                    "User-Agent": ua,
                },
            ) as response:
                if response.ok:
                    onboard_result = await response.json()
                    # Extract project from response
                    resp_data = onboard_result.get("response", {})
                    cap = resp_data.get("cloudaicompanionProject", "")
                    if isinstance(cap, dict):
                        project = cap.get("id", "")
                    else:
                        project = str(cap) if cap else ""
                    result["project_id"] = project or env_project
                else:
                    result["project_id"] = env_project

        result["tier"] = onboard_tier_id
        result["tier_name"] = onboard_tier_name
        log.log_info(f"Code Assist setup complete. Project: {result['project_id']}, tier: {result['tier']}")

    except Exception as e:
        log.log_warn(f"Code Assist setup failed (non-fatal): {e}")
        result["project_id"] = env_project

    return result


# ============================================================================
# Credential Helpers
# ============================================================================

def create_credentials_json(tokens: Dict[str, Any], email: Optional[str] = None,
                            project_id: str = "", tier: str = "",
                            tier_name: str = "") -> str:
    """
    Create JSON string for storing Gemini OAuth credentials in api_key field.

    Args:
        tokens: Token response from exchange or refresh
        email: User email (optional)
        project_id: Code Assist project ID
        tier: Tier ID
        tier_name: Tier display name

    Returns:
        JSON string with all credential fields
    """
    expires_at = time.time() + tokens.get("expires_in", 3600)

    credentials = {
        "access_token": tokens["access_token"],
        "refresh_token": tokens.get("refresh_token", ""),
        "expires_at": expires_at,
        "email": email or "",
        "project_id": project_id,
        "tier": tier,
        "tier_name": tier_name,
    }

    return json.dumps(credentials)


def parse_credentials_json(api_key: str) -> Optional[Dict[str, Any]]:
    """
    Parse Gemini OAuth credentials from api_key field.

    Args:
        api_key: JSON string containing OAuth credentials

    Returns:
        Dict with credential fields, or None if invalid
    """
    if not api_key:
        return None

    try:
        credentials = json.loads(api_key)
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
