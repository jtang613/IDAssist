#!/usr/bin/env python3
"""
MCP Tool Orchestration Service

Orchestrates MCP tool calls during LLM conversations, handling routing,
execution, and result aggregation across multiple MCP servers.
"""

import asyncio
import time
import threading
from typing import List, Dict, Any, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

from .models.llm_models import ToolCall, ToolResult
from .mcp_client_service import MCPClientService
from .models.mcp_models import MCPToolExecutionRequest
from .binary_context_service import BinaryContextService

from src.ida_compat import log


class MCPToolOrchestrator:
    """
    Orchestrates MCP tool calls during LLM conversations.

    Responsibilities:
    - Route tool calls to appropriate MCP servers
    - Execute tool calls with proper error handling
    - Aggregate and format results for LLM continuation
    - Inject binary context into tool arguments when needed
    """

    def __init__(self, mcp_service: MCPClientService, binary_context_service: Optional[BinaryContextService] = None):
        self.mcp_service = mcp_service
        self.binary_context_service = binary_context_service
        self._tool_server_map: Dict[str, str] = {}  # tool_name -> server_name
        self._last_tools_refresh = 0
        self._tools_cache_ttl = 30.0  # 30 second cache
        self._max_concurrent_tools = 3  # Limit concurrent tool execution
        self._tool_timeout = 30.0  # Default tool timeout


    def get_available_tools_for_llm(self) -> List[Dict[str, Any]]:
        """
        Get MCP tools formatted for LLM tool calling.

        Returns:
            List of tool definitions in OpenAI tool calling format
        """
        try:
            # Refresh tool cache if needed
            current_time = time.time()
            if current_time - self._last_tools_refresh > self._tools_cache_ttl:
                self._refresh_tool_cache()
                self._last_tools_refresh = current_time

            # Get available tools from MCP service
            available_tools = self.mcp_service.get_available_tools()

            if not available_tools:
                return []

            # Convert MCP tools to OpenAI tool calling format
            llm_tools = []
            for tool in available_tools:
                try:
                    llm_tool = self._convert_mcp_tool_to_llm_format(tool)
                    if llm_tool:
                        llm_tools.append(llm_tool)
                        # Update tool -> server mapping
                        self._tool_server_map[tool.name] = tool.server_name
                except Exception as e:
                    log.log_error(f"Error converting MCP tool {tool.name}: {e}")
                    continue

            return llm_tools

        except Exception as e:
            log.log_error(f"Error getting available tools for LLM: {e}")
            return []

    def _convert_mcp_tool_to_llm_format(self, mcp_tool) -> Optional[Dict[str, Any]]:
        """Convert MCP tool to OpenAI tool calling format"""
        try:
            # Base tool definition
            tool_def = {
                "type": "function",
                "function": {
                    "name": mcp_tool.name,
                    "description": mcp_tool.description or f"Tool from {mcp_tool.server_name}",
                }
            }

            # Add schema if available
            if mcp_tool.schema and isinstance(mcp_tool.schema, dict):
                # Convert MCP schema to OpenAI function calling schema
                if "properties" in mcp_tool.schema:
                    tool_def["function"]["parameters"] = {
                        "type": "object",
                        "properties": mcp_tool.schema["properties"],
                        "required": mcp_tool.schema.get("required", [])
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

            return tool_def

        except Exception as e:
            log.log_error(f"Error converting MCP tool {mcp_tool.name} to LLM format: {e}")
            return None

    def _refresh_tool_cache(self):
        """Refresh the internal tool cache"""
        try:
            # Clear existing mappings
            self._tool_server_map.clear()

            # Rebuild the tool mapping by getting available tools
            available_tools = self.mcp_service.get_available_tools()
            for tool in available_tools:
                self._tool_server_map[tool.name] = tool.server_name

        except Exception as e:
            log.log_error(f"Error refreshing tool cache: {e}")

    async def execute_tool_calls(self, tool_calls: List[ToolCall]) -> List[ToolResult]:
        """
        Execute multiple tool calls and return results.

        Args:
            tool_calls: List of tool calls from LLM

        Returns:
            List of tool execution results
        """
        if not tool_calls:
            return []

        results = []

        # Use ThreadPoolExecutor to run sync MCP calls concurrently
        with ThreadPoolExecutor(max_workers=self._max_concurrent_tools) as executor:
            # Submit all tool calls for execution
            future_to_tool_call = {
                executor.submit(self._execute_single_tool_call, tool_call): tool_call
                for tool_call in tool_calls
            }

            # Collect results as they complete
            for future in as_completed(future_to_tool_call, timeout=self._tool_timeout + 10):
                tool_call = future_to_tool_call[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    log.log_error(f"Exception executing tool '{tool_call.name}': {e}")
                    error_result = ToolResult(
                        tool_call_id=tool_call.id,
                        content="",
                        error=str(e),
                        server_name=self._tool_server_map.get(tool_call.name, "unknown")
                    )
                    results.append(error_result)

        # Sort results to match original tool call order
        results.sort(key=lambda r: next(i for i, tc in enumerate(tool_calls) if tc.id == r.tool_call_id))

        return results

    def _execute_single_tool_call(self, tool_call: ToolCall) -> ToolResult:
        """Execute a single tool call synchronously"""
        start_time = time.time()

        try:
            # Find which server handles this tool
            server_name = self._tool_server_map.get(tool_call.name)
            if not server_name:
                # Tool mapping might be stale, refresh it
                self._refresh_tool_cache()
                server_name = self._tool_server_map.get(tool_call.name)

            if not server_name:
                error_msg = f"No server found for tool '{tool_call.name}'"
                log.log_error(error_msg)
                return ToolResult(
                    tool_call_id=tool_call.id,
                    content="",
                    error=error_msg,
                    execution_time=time.time() - start_time
                )

            # Enhance arguments with binary context if needed
            enhanced_arguments = self._enhance_tool_arguments(tool_call)

            # Create MCP tool execution request
            mcp_request = MCPToolExecutionRequest(
                tool_name=tool_call.name,
                arguments=enhanced_arguments,
                timeout=self._tool_timeout
            )

            # Execute via MCP service
            mcp_result = self.mcp_service.execute_tool(mcp_request)

            execution_time = time.time() - start_time

            if mcp_result.success:
                result_content = str(mcp_result.result)
                return ToolResult(
                    tool_call_id=tool_call.id,
                    content=result_content,
                    execution_time=execution_time,
                    server_name=server_name
                )
            else:
                error_msg = mcp_result.error or "Unknown error"
                log.log_warn(f"Tool '{tool_call.name}' failed: {error_msg}")
                return ToolResult(
                    tool_call_id=tool_call.id,
                    content="",
                    error=error_msg,
                    execution_time=execution_time,
                    server_name=server_name
                )

        except Exception as e:
            execution_time = time.time() - start_time
            log.log_error(f"Exception executing tool '{tool_call.name}': {e}")
            return ToolResult(
                tool_call_id=tool_call.id,
                content="",
                error=str(e),
                execution_time=execution_time,
                server_name=self._tool_server_map.get(tool_call.name, "unknown")
            )

    def _enhance_tool_arguments(self, tool_call: ToolCall) -> Dict[str, Any]:
        """
        Enhance tool arguments with binary context information.

        Args:
            tool_call: Original tool call from LLM

        Returns:
            Enhanced arguments with binary context injected
        """
        enhanced_args = tool_call.arguments.copy()

        # Only enhance if we have a binary context service
        if not self.binary_context_service:
            return enhanced_args

        try:
            # Check if tool needs binary filename
            if self._tool_needs_filename(tool_call.name) and 'filename' not in enhanced_args:
                try:
                    if self.binary_context_service:
                        context = self.binary_context_service.get_current_context()
                        if context and context.get('binary_name'):
                            enhanced_args['filename'] = context['binary_name']
                except Exception as e:
                    log.log_error(f"Could not get binary filename for {tool_call.name}: {e}")

            # Check if tool needs current address
            if self._tool_needs_current_address(tool_call.name) and 'address' not in enhanced_args:
                try:
                    context = self.binary_context_service.get_current_context()
                    if context and context.get('current_address'):
                        enhanced_args['address'] = context['current_address']
                except Exception as e:
                    pass  # Address enhancement is optional

        except Exception as e:
            log.log_error(f"Error enhancing tool arguments for {tool_call.name}: {e}")

        return enhanced_args

    def _tool_needs_filename(self, tool_name: str) -> bool:
        """Check if a tool typically needs a filename parameter"""
        filename_tools = {
            'get_current_address', 'get_binary_status', 'get_function_info',
            'decompile_function', 'analyze_function', 'get_binary_info',
            'get_functions', 'get_imports', 'get_exports', 'get_strings'
        }
        return tool_name in filename_tools

    def _tool_needs_current_address(self, tool_name: str) -> bool:
        """Check if a tool typically needs the current address"""
        address_tools = {
            'get_function_at_address', 'disassemble_at_address',
            'get_data_at_address', 'analyze_address'
        }
        return tool_name in address_tools

    def format_tool_results_for_llm(self, tool_calls: List[ToolCall], results: List[ToolResult]) -> List[Dict[str, Any]]:
        """
        Format tool execution results for LLM conversation continuation.

        Args:
            tool_calls: Original tool calls
            results: Tool execution results

        Returns:
            List of tool result messages for LLM
        """
        tool_messages = []

        for tool_call, result in zip(tool_calls, results):
            try:
                if result.error:
                    # Format error result with details for LLM to understand and potentially retry
                    content = f"ERROR: Tool '{tool_call.name}' failed with error: {result.error}"
                    if result.server_name:
                        content += f" (Server: {result.server_name})"
                    if result.execution_time:
                        content += f" (Execution time: {result.execution_time:.2f}s)"
                else:
                    # Format success result
                    content = result.content

                # Create tool result message in OpenAI format (base format)
                # Provider-specific formatting will be handled by the provider
                tool_message = {
                    "role": "tool",
                    "content": content,
                    "tool_call_id": result.tool_call_id,
                    "name": tool_call.name
                }

                tool_messages.append(tool_message)

            except Exception as e:
                log.log_error(f"Error formatting tool result for {tool_call.name}: {e}")
                # Create error message as fallback
                error_message = {
                    "role": "tool",
                    "content": f"Error formatting tool result: {e}",
                    "tool_call_id": result.tool_call_id,
                    "name": tool_call.name
                }
                tool_messages.append(error_message)

        return tool_messages

    def get_tool_execution_summary(self, tool_calls: List[ToolCall], results: List[ToolResult]) -> str:
        """
        Generate a human-readable summary of tool execution for chat display.

        Args:
            tool_calls: Original tool calls
            results: Tool execution results

        Returns:
            Formatted summary text
        """
        if not tool_calls:
            return ""

        try:
            if not results:
                # No results yet - show pending status
                tool_names = [call.name for call in tool_calls]
                return f"**Executing tools:** {', '.join(tool_names)}..."

            summary_lines = ["**Tool Execution Summary:**"]

            for tool_call, result in zip(tool_calls, results):
                tool_name = tool_call.name
                server_name = result.server_name or "unknown"

                if result.error:
                    status = f"Failed: {result.error}"
                else:
                    exec_time = f" ({result.execution_time:.2f}s)" if result.execution_time else ""
                    status = f"Success{exec_time}"

                summary_lines.append(f"* **{tool_name}** ({server_name}): {status}")

            return "\\n".join(summary_lines) + "\\n\\n"

        except Exception as e:
            log.log_error(f"Error generating tool execution summary: {e}")
            return "**Tool Execution Summary:** Error generating summary\\n\\n"
