#!/usr/bin/env python3

"""
IDAssist Actions Tools

Implements the four action types as native LLM tools that integrate with the MCP system.
These tools allow the LLM to directly suggest specific improvements to IDA Pro code.
"""

from typing import Dict, Any, List
from abc import ABC, abstractmethod
from .binary_context_service import BinaryContextService
from .actions_service import ActionsService
from .models.action_models import ActionType, ActionProposal

from src.ida_compat import log


class IDAssistActionTool(ABC):
    """Base class for IDAssist action tools"""

    def __init__(self, context_service: BinaryContextService, actions_service: ActionsService):
        self.context_service = context_service
        self.actions_service = actions_service

    @property
    @abstractmethod
    def definition(self) -> Dict[str, Any]:
        """Return OpenAI-style tool definition"""
        pass

    @abstractmethod
    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the tool and return result"""
        pass


class RenameFunctionTool(IDAssistActionTool):
    """Tool for suggesting better function names"""

    @property
    def definition(self) -> Dict[str, Any]:
        return {
            "name": "rename_function",
            "description": "Suggest a better name for a function based on its behavior, API calls, and purpose",
            "parameters": {
                "type": "object",
                "properties": {
                    "current_name": {
                        "type": "string",
                        "description": "Current function name (e.g., sub_401000, fcn_00401000)"
                    },
                    "suggested_name": {
                        "type": "string",
                        "description": "Proposed better name that describes function purpose"
                    },
                    "confidence": {
                        "type": "number",
                        "minimum": 0.0,
                        "maximum": 1.0,
                        "description": "Confidence level in the suggestion (0.0-1.0)"
                    },
                    "rationale": {
                        "type": "string",
                        "description": "Explanation of why this name is better based on function analysis"
                    }
                },
                "required": ["current_name", "suggested_name", "confidence", "rationale"]
            }
        }

    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Execute function rename suggestion"""
        try:
            # Validate arguments
            required_fields = ["current_name", "suggested_name", "confidence", "rationale"]
            for field in required_fields:
                if field not in arguments:
                    return {
                        "success": False,
                        "error": f"Missing required field: {field}"
                    }

            # Validate confidence range
            confidence = float(arguments["confidence"])
            if not (0.0 <= confidence <= 1.0):
                return {
                    "success": False,
                    "error": "Confidence must be between 0.0 and 1.0"
                }

            # Create ActionProposal
            proposal = ActionProposal(
                action_type=ActionType.RENAME_FUNCTION,
                target=arguments["current_name"],
                current_value=arguments["current_name"],
                proposed_value=arguments["suggested_name"],
                confidence=confidence,
                rationale=arguments["rationale"]
            )

            log.log_info(f"Function rename suggested: {arguments['current_name']} -> {arguments['suggested_name']} (confidence: {confidence:.2f})")

            return {
                "success": True,
                "message": f"Function rename suggested: {arguments['current_name']} -> {arguments['suggested_name']}",
                "proposal": proposal
            }

        except Exception as e:
            log.log_error(f"Error in rename_function tool: {e}")
            return {
                "success": False,
                "error": f"Tool execution failed: {str(e)}"
            }


class RenameVariableTool(IDAssistActionTool):
    """Tool for suggesting better variable names"""

    @property
    def definition(self) -> Dict[str, Any]:
        return {
            "name": "rename_variable",
            "description": "Suggest better names for variables based on their usage context and purpose",
            "parameters": {
                "type": "object",
                "properties": {
                    "current_name": {
                        "type": "string",
                        "description": "Current variable name (e.g., var_8, arg_1, rax_1)"
                    },
                    "suggested_name": {
                        "type": "string",
                        "description": "Proposed better name that describes variable purpose"
                    },
                    "confidence": {
                        "type": "number",
                        "minimum": 0.0,
                        "maximum": 1.0,
                        "description": "Confidence level in the suggestion (0.0-1.0)"
                    },
                    "rationale": {
                        "type": "string",
                        "description": "Explanation of why this name is better based on usage analysis"
                    }
                },
                "required": ["current_name", "suggested_name", "confidence", "rationale"]
            }
        }

    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Execute variable rename suggestion"""
        try:
            # Validate arguments
            required_fields = ["current_name", "suggested_name", "confidence", "rationale"]
            for field in required_fields:
                if field not in arguments:
                    return {
                        "success": False,
                        "error": f"Missing required field: {field}"
                    }

            # Validate confidence range
            confidence = float(arguments["confidence"])
            if not (0.0 <= confidence <= 1.0):
                return {
                    "success": False,
                    "error": "Confidence must be between 0.0 and 1.0"
                }

            # Create ActionProposal
            proposal = ActionProposal(
                action_type=ActionType.RENAME_VARIABLE,
                target=arguments["current_name"],
                current_value=arguments["current_name"],
                proposed_value=arguments["suggested_name"],
                confidence=confidence,
                rationale=arguments["rationale"]
            )

            log.log_info(f"Variable rename suggested: {arguments['current_name']} -> {arguments['suggested_name']} (confidence: {confidence:.2f})")

            return {
                "success": True,
                "message": f"Variable rename suggested: {arguments['current_name']} -> {arguments['suggested_name']}",
                "proposal": proposal
            }

        except Exception as e:
            log.log_error(f"Error in rename_variable tool: {e}")
            return {
                "success": False,
                "error": f"Tool execution failed: {str(e)}"
            }


class RetypeVariableTool(IDAssistActionTool):
    """Tool for suggesting more specific variable types"""

    @property
    def definition(self) -> Dict[str, Any]:
        return {
            "name": "retype_variable",
            "description": "Suggest more specific variable types based on usage patterns and API calls",
            "parameters": {
                "type": "object",
                "properties": {
                    "variable_name": {
                        "type": "string",
                        "description": "Name of the variable to retype"
                    },
                    "current_type": {
                        "type": "string",
                        "description": "Current type of the variable (e.g., void*, int, long)"
                    },
                    "suggested_type": {
                        "type": "string",
                        "description": "More specific type suggestion (e.g., char*, size_t, HANDLE)"
                    },
                    "confidence": {
                        "type": "number",
                        "minimum": 0.0,
                        "maximum": 1.0,
                        "description": "Confidence level in the type suggestion (0.0-1.0)"
                    },
                    "rationale": {
                        "type": "string",
                        "description": "Explanation of why this type is more accurate based on usage"
                    }
                },
                "required": ["variable_name", "current_type", "suggested_type", "confidence", "rationale"]
            }
        }

    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Execute variable retype suggestion"""
        try:
            # Validate arguments
            required_fields = ["variable_name", "current_type", "suggested_type", "confidence", "rationale"]
            for field in required_fields:
                if field not in arguments:
                    return {
                        "success": False,
                        "error": f"Missing required field: {field}"
                    }

            # Validate confidence range
            confidence = float(arguments["confidence"])
            if not (0.0 <= confidence <= 1.0):
                return {
                    "success": False,
                    "error": "Confidence must be between 0.0 and 1.0"
                }

            # Create ActionProposal
            proposal = ActionProposal(
                action_type=ActionType.RETYPE_VARIABLE,
                target=arguments["variable_name"],
                current_value=arguments["current_type"],
                proposed_value=arguments["suggested_type"],
                confidence=confidence,
                rationale=arguments["rationale"]
            )

            log.log_info(f"Variable retype suggested: {arguments['variable_name']} ({arguments['current_type']} -> {arguments['suggested_type']}) (confidence: {confidence:.2f})")

            return {
                "success": True,
                "message": f"Variable retype suggested: {arguments['variable_name']} ({arguments['current_type']} -> {arguments['suggested_type']})",
                "proposal": proposal
            }

        except Exception as e:
            log.log_error(f"Error in retype_variable tool: {e}")
            return {
                "success": False,
                "error": f"Tool execution failed: {str(e)}"
            }


class CreateStructTool(IDAssistActionTool):
    """Tool for suggesting struct definitions based on memory access patterns"""

    @property
    def definition(self) -> Dict[str, Any]:
        return {
            "name": "create_struct",
            "description": "Suggest struct definitions based on consistent memory access patterns and offset usage",
            "parameters": {
                "type": "object",
                "properties": {
                    "struct_name": {
                        "type": "string",
                        "description": "Proposed name for the struct"
                    },
                    "offset_pattern": {
                        "type": "string",
                        "description": "Description of the memory access pattern observed (e.g., '+0x0, +0x4, +0x8')"
                    },
                    "suggested_definition": {
                        "type": "string",
                        "description": "C struct definition with field names and types"
                    },
                    "confidence": {
                        "type": "number",
                        "minimum": 0.0,
                        "maximum": 1.0,
                        "description": "Confidence level in the struct definition (0.0-1.0)"
                    },
                    "rationale": {
                        "type": "string",
                        "description": "Explanation of the access pattern that suggests this struct"
                    }
                },
                "required": ["struct_name", "offset_pattern", "suggested_definition", "confidence", "rationale"]
            }
        }

    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Execute struct creation suggestion"""
        try:
            # Validate arguments
            required_fields = ["struct_name", "offset_pattern", "suggested_definition", "confidence", "rationale"]
            for field in required_fields:
                if field not in arguments:
                    return {
                        "success": False,
                        "error": f"Missing required field: {field}"
                    }

            # Validate confidence range
            confidence = float(arguments["confidence"])
            if not (0.0 <= confidence <= 1.0):
                return {
                    "success": False,
                    "error": "Confidence must be between 0.0 and 1.0"
                }

            # Create ActionProposal
            proposal = ActionProposal(
                action_type=ActionType.AUTO_CREATE_STRUCT,
                target=arguments["struct_name"],
                current_value=arguments["offset_pattern"],
                proposed_value=arguments["suggested_definition"],
                confidence=confidence,
                rationale=arguments["rationale"]
            )

            log.log_info(f"Struct creation suggested: {arguments['struct_name']} (confidence: {confidence:.2f})")

            return {
                "success": True,
                "message": f"Struct creation suggested: {arguments['struct_name']}",
                "proposal": proposal
            }

        except Exception as e:
            log.log_error(f"Error in create_struct tool: {e}")
            return {
                "success": False,
                "error": f"Tool execution failed: {str(e)}"
            }
