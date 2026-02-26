#!/usr/bin/env python3

"""
IDAssist MCP Resources

MCP resources that expose binary metadata and function lists
to external LLM clients.
"""

from typing import Any, Dict, List

from src.ida_compat import log

try:
    from mcp.server import Server
    from mcp.types import Resource, TextContent
    _MCP_AVAILABLE = True
except ImportError:
    _MCP_AVAILABLE = False

# IDA imports
try:
    import idautils
    import ida_funcs
    import ida_ida
    import ida_nalt
    import idc
    _IN_IDA = True
except ImportError:
    _IN_IDA = False


def register_resources(server: 'Server'):
    """Register MCP resources."""
    if not _MCP_AVAILABLE:
        return

    @server.list_resources()
    async def list_resources() -> List[Resource]:
        resources = [
            Resource(
                uri="idassist://binary/metadata",
                name="Binary Metadata",
                description="Architecture, platform, filename, hash of the current binary",
                mimeType="application/json",
            ),
            Resource(
                uri="idassist://binary/functions",
                name="Function List",
                description="List of all functions with addresses",
                mimeType="text/plain",
            ),
        ]
        return resources

    @server.read_resource()
    async def read_resource(uri: str) -> str:
        if uri == "idassist://binary/metadata":
            return _get_binary_metadata()
        elif uri == "idassist://binary/functions":
            return _get_function_list()
        else:
            return f"Unknown resource: {uri}"


def _get_binary_metadata() -> str:
    """Get binary metadata as JSON string."""
    import json
    from src.ida_compat import get_binary_hash

    if not _IN_IDA:
        return json.dumps({"error": "Not running inside IDA"})

    try:
        metadata = {
            "filename": ida_nalt.get_root_filename() or "Unknown",
            "filepath": ida_nalt.get_input_file_path() or "Unknown",
            "architecture": ida_ida.inf_get_procname() or "Unknown",
            "is_64bit": ida_ida.inf_is_64bit(),
            "endianness": "big" if ida_ida.inf_is_be() else "little",
            "entry_point": hex(idc.get_inf_attr(idc.INF_START_EA)),
            "binary_hash": get_binary_hash() or "unknown",
            "total_functions": sum(1 for _ in idautils.Functions()),
        }
        return json.dumps(metadata, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


def _get_function_list() -> str:
    """Get all functions with addresses as text."""
    if not _IN_IDA:
        return "Not running inside IDA"

    try:
        lines = []
        for func_ea in idautils.Functions():
            name = ida_funcs.get_func_name(func_ea) or f"sub_{func_ea:x}"
            func = ida_funcs.get_func(func_ea)
            size = (func.end_ea - func.start_ea) if func else 0
            lines.append(f"0x{func_ea:08x}  {name}  (size: {size})")

        return f"Functions ({len(lines)} total):\n" + "\n".join(lines)
    except Exception as e:
        return f"Error: {str(e)}"
