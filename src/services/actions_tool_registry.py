#!/usr/bin/env python3

"""
Actions Tool Registry

Registry for IDAssist action tools that integrates with the MCP system.
Manages the four action tools and accumulates their suggestions.
"""

from typing import Dict, Any, List, Optional
from .binary_context_service import BinaryContextService
from .actions_service import ActionsService
from .actions_tools import (
    RenameFunctionTool,
    RenameVariableTool,
    RetypeVariableTool,
    CreateStructTool
)
from .models.llm_models import ToolCall, ToolResult
from .models.action_models import ActionProposal

from src.ida_compat import log


class ActionsToolRegistry:
    """Registry for IDAssist action tools - integrates with MCP system"""

    def __init__(self, context_service: BinaryContextService, actions_service: ActionsService):
        self.context_service = context_service
        self.actions_service = actions_service

        # Initialize the four action tools
        self.tools = {
            "rename_function": RenameFunctionTool(context_service, actions_service),
            "rename_variable": RenameVariableTool(context_service, actions_service),
            "retype_variable": RetypeVariableTool(context_service, actions_service),
            "create_struct": CreateStructTool(context_service, actions_service)
        }

        # Accumulate suggestions from tool calls
        self.active_suggestions: List[ActionProposal] = []

        log.log_info("ActionsToolRegistry initialized with 4 action tools")

    def get_tool_definitions(self) -> List[Dict[str, Any]]:
        """Get OpenAI-format tool definitions for LLM"""
        tool_definitions = []

        for tool_name, tool in self.tools.items():
            tool_def = {
                "type": "function",
                "function": tool.definition
            }
            tool_definitions.append(tool_def)

        log.log_info(f"Generated {len(tool_definitions)} tool definitions for LLM")
        return tool_definitions

    def is_action_tool(self, tool_name: str) -> bool:
        """Check if tool name is one of our action tools"""
        return tool_name in self.tools

    def execute_tool(self, tool_call: ToolCall) -> ToolResult:
        """Execute action tool and accumulate suggestion"""
        start_time = 0.0

        try:
            import time
            start_time = time.time()

            # Check if this is one of our action tools
            tool = self.tools.get(tool_call.name)
            if not tool:
                error_msg = f"Unknown action tool: {tool_call.name}"
                log.log_error(error_msg)
                return ToolResult(
                    tool_call_id=tool_call.id,
                    content="",
                    error=error_msg,
                    execution_time=time.time() - start_time
                )

            # Execute the tool
            result = tool.execute(tool_call.arguments)
            execution_time = time.time() - start_time

            if result.get("success"):
                # Accumulate the proposal for later UI update
                proposal = result.get("proposal")
                if proposal:
                    self.active_suggestions.append(proposal)
                    log.log_info(f"Added suggestion to registry: {tool_call.name}")

                return ToolResult(
                    tool_call_id=tool_call.id,
                    content=result.get("message", "Action suggestion recorded"),
                    execution_time=execution_time
                )
            else:
                error_msg = result.get("error", "Unknown tool error")
                log.log_error(f"Tool {tool_call.name} failed: {error_msg}")
                return ToolResult(
                    tool_call_id=tool_call.id,
                    content="",
                    error=error_msg,
                    execution_time=execution_time
                )

        except Exception as e:
            import time
            execution_time = time.time() - start_time if start_time else 0.0
            error_msg = f"Tool execution failed: {str(e)}"
            log.log_error(f"Error executing action tool {tool_call.name}: {e}")
            return ToolResult(
                tool_call_id=tool_call.id,
                content="",
                error=error_msg,
                execution_time=execution_time
            )

    def clear_suggestions(self):
        """Clear all accumulated suggestions"""
        suggestion_count = len(self.active_suggestions)
        self.active_suggestions.clear()
        log.log_info(f"Cleared {suggestion_count} accumulated suggestions")

    def get_suggestions(self) -> List[ActionProposal]:
        """Get all accumulated suggestions"""
        return self.active_suggestions.copy()

    def get_suggestion_count(self) -> int:
        """Get count of accumulated suggestions"""
        return len(self.active_suggestions)

    def get_tool_names(self) -> List[str]:
        """Get list of all action tool names"""
        return list(self.tools.keys())

    def get_tool_descriptions(self) -> Dict[str, str]:
        """Get mapping of tool names to descriptions"""
        descriptions = {}
        for tool_name, tool in self.tools.items():
            descriptions[tool_name] = tool.definition.get("description", "No description")
        return descriptions
