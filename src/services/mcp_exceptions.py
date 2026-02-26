"""
MCP-specific exceptions for IDAssist.

This module provides exception classes for MCP-related errors,
following the existing IDAssist error handling patterns.
"""


class MCPError(Exception):
    """Base exception for MCP-related errors."""
    pass


class MCPConfigurationError(MCPError):
    """Exception raised for MCP configuration errors."""
    pass


class MCPConnectionError(MCPError):
    """Exception raised for MCP connection errors."""
    pass


class MCPTimeoutError(MCPConnectionError):
    """Exception raised when MCP operations timeout."""
    pass


class MCPToolError(MCPError):
    """Exception raised for MCP tool-related errors."""
    pass


class MCPResourceError(MCPError):
    """Exception raised for MCP resource-related errors."""
    pass


class MCPTransportError(MCPConnectionError):
    """Exception raised for MCP transport-related errors."""
    pass


class MCPAuthenticationError(MCPConnectionError):
    """Exception raised for MCP authentication errors."""
    pass


class MCPProtocolError(MCPError):
    """Exception raised for MCP protocol-related errors."""
    pass
