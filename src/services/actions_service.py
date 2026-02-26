#!/usr/bin/env python3

"""
Actions Service for IDAssist Actions Tab

Full rewrite of BinAssist's ActionsService for IDA Pro 9.x.
All apply methods use execute_on_main_thread() since IDA database
modifications are not thread-safe.
"""

from typing import List, Dict, Any, Optional
from .models.action_models import ActionType, ActionProposal, ActionResult
from .binary_context_service import BinaryContextService

from src.ida_compat import log, execute_on_main_thread

# IDA imports
try:
    import idaapi
    import ida_funcs
    import ida_hexrays
    import ida_name
    import ida_typeinf
    import idautils
    import idc
    _IN_IDA = True
except ImportError:
    _IN_IDA = False


class ActionsService:
    """Service for managing IDA Pro analysis actions"""

    def __init__(self, context_service: BinaryContextService):
        self.context_service = context_service
        self._available_actions = self._create_available_actions()
        log.log_info("ActionsService initialized")

    def _create_available_actions(self) -> List[Dict[str, Any]]:
        """Create the list of available actions"""
        return [
            {
                'name': 'Rename Function',
                'description': 'Suggest a better name for the current function',
                'action_type': ActionType.RENAME_FUNCTION
            },
            {
                'name': 'Rename Variable',
                'description': 'Suggest meaningful names for variables',
                'action_type': ActionType.RENAME_VARIABLE
            },
            {
                'name': 'Retype Variable',
                'description': 'Suggest better types for variables',
                'action_type': ActionType.RETYPE_VARIABLE
            },
            {
                'name': 'Auto Create Struct',
                'description': 'Create structures from offset patterns',
                'action_type': ActionType.AUTO_CREATE_STRUCT
            }
        ]

    def get_available_actions(self) -> List[Dict[str, Any]]:
        """Get all available action definitions"""
        return self._available_actions.copy()

    def get_function_context(self) -> Optional[Dict[str, Any]]:
        """Get current function context for LLM analysis"""
        try:
            context = self.context_service.get_current_context()
            if context.get("error"):
                log.log_error(f"Cannot get function context: {context['error']}")
                return None
            return context
        except Exception as e:
            log.log_error(f"Error getting function context: {e}")
            return None

    def apply_action(self, proposal: ActionProposal) -> ActionResult:
        """Apply an action proposal to the binary"""
        try:
            # Get context on main thread since it calls IDA APIs
            context_holder = [None]

            def _get_ctx():
                context_holder[0] = self.context_service.get_current_context()

            execute_on_main_thread(_get_ctx)
            context = context_holder[0]

            if context is None or context.get("error"):
                return ActionResult(
                    success=False,
                    message="Cannot apply action: no valid context",
                    action_type=proposal.action_type,
                    target=proposal.target,
                    error=context.get("error", "Context unavailable") if context else "Context unavailable"
                )

            function_address = context["offset"]

            if proposal.action_type == ActionType.RENAME_FUNCTION:
                return self._apply_rename_function(function_address, proposal)
            elif proposal.action_type == ActionType.RENAME_VARIABLE:
                return self._apply_rename_variable(function_address, proposal)
            elif proposal.action_type == ActionType.RETYPE_VARIABLE:
                return self._apply_retype_variable(function_address, proposal)
            elif proposal.action_type == ActionType.AUTO_CREATE_STRUCT:
                return self._apply_auto_create_struct(function_address, proposal)
            else:
                return ActionResult(
                    success=False,
                    message=f"Unknown action type: {proposal.action_type}",
                    action_type=proposal.action_type,
                    target=proposal.target,
                    error="Unknown action type"
                )

        except Exception as e:
            log.log_error(f"Error applying action: {e}")
            return ActionResult(
                success=False,
                message=f"Failed to apply action: {str(e)}",
                action_type=proposal.action_type,
                target=proposal.target,
                error=str(e)
            )

    def validate_function_name(self, current_name: str, suggested_name: str) -> bool:
        """Validate that a function rename is reasonable"""
        try:
            if not suggested_name or len(suggested_name) < 3:
                return False
            if not suggested_name.replace('_', '').replace('-', '').isalnum():
                return False
            if current_name == suggested_name:
                return False
            return True
        except Exception:
            return False

    def validate_variable_name(self, current_name: str, suggested_name: str) -> bool:
        """Validate that a variable rename is reasonable"""
        try:
            if not suggested_name or len(suggested_name) < 2:
                return False
            if not suggested_name.replace('_', '').isalnum():
                return False
            if current_name == suggested_name:
                return False
            return True
        except Exception:
            return False

    def validate_variable_type(self, current_type: str, suggested_type: str) -> bool:
        """Validate that a variable retype is reasonable"""
        try:
            if not suggested_type or len(suggested_type) < 3:
                return False
            if current_type == suggested_type:
                return False
            return True
        except Exception:
            return False

    def _apply_rename_function(self, function_address: int, proposal: ActionProposal) -> ActionResult:
        """Apply function rename via IDA API on main thread"""
        try:
            new_name = proposal.proposed_value
            # [success, old_name, error_msg]
            result_holder = [False, "", ""]

            def _do_rename():
                try:
                    func = ida_funcs.get_func(function_address)
                    if not func:
                        result_holder[2] = f"No function found at address {hex(function_address)}"
                        return
                    result_holder[1] = ida_funcs.get_func_name(func.start_ea)
                    result_holder[0] = ida_name.set_name(
                        func.start_ea, new_name, ida_name.SN_CHECK
                    )
                    if not result_holder[0]:
                        result_holder[2] = "ida_name.set_name returned False"
                except Exception as e:
                    result_holder[2] = str(e)

            execute_on_main_thread(_do_rename)

            if result_holder[0]:
                return ActionResult(
                    success=True,
                    message=f"Renamed function from '{result_holder[1]}' to '{new_name}'",
                    action_type=proposal.action_type,
                    target=proposal.target,
                    old_value=result_holder[1],
                    new_value=new_name
                )
            else:
                error = result_holder[2] or "Unknown error"
                return ActionResult(
                    success=False,
                    message=f"Failed to rename function: {error}",
                    action_type=proposal.action_type,
                    target=proposal.target,
                    error=error
                )

        except Exception as e:
            return ActionResult(
                success=False,
                message=f"Failed to rename function: {str(e)}",
                action_type=proposal.action_type,
                target=proposal.target,
                error=str(e)
            )

    def _apply_rename_variable(self, function_address: int, proposal: ActionProposal) -> ActionResult:
        """Apply variable rename via Hex-Rays API on main thread"""
        try:
            var_name = proposal.target
            new_name = proposal.proposed_value
            result_holder = [False, ""]

            def _do_rename():
                try:
                    func = ida_funcs.get_func(function_address)
                    if not func:
                        result_holder[1] = f"No function found at address {hex(function_address)}"
                        return

                    cfunc = ida_hexrays.decompile(func.start_ea)
                    if not cfunc:
                        result_holder[1] = "Decompilation failed"
                        return

                    # Find the variable by name in local vars
                    lvars = cfunc.get_lvars()
                    target_lvar = None
                    for lvar in lvars:
                        if lvar.name == var_name:
                            target_lvar = lvar
                            break

                    if not target_lvar:
                        result_holder[1] = f"Variable '{var_name}' not found"
                        return

                    # Rename the local variable
                    success = ida_hexrays.rename_lvar(cfunc, target_lvar, new_name)
                    result_holder[0] = success
                    if not success:
                        result_holder[1] = "rename_lvar returned False"
                except Exception as e:
                    result_holder[1] = str(e)

            execute_on_main_thread(_do_rename)

            if result_holder[0]:
                return ActionResult(
                    success=True,
                    message=f"Renamed variable from '{var_name}' to '{new_name}'",
                    action_type=proposal.action_type,
                    target=proposal.target,
                    old_value=var_name,
                    new_value=new_name
                )
            else:
                return ActionResult(
                    success=False,
                    message=f"Failed to rename variable: {result_holder[1]}",
                    action_type=proposal.action_type,
                    target=proposal.target,
                    error=result_holder[1]
                )

        except Exception as e:
            return ActionResult(
                success=False,
                message=f"Failed to rename variable: {str(e)}",
                action_type=proposal.action_type,
                target=proposal.target,
                error=str(e)
            )

    def _apply_retype_variable(self, function_address: int, proposal: ActionProposal) -> ActionResult:
        """Apply variable retype via Hex-Rays + typeinf API on main thread"""
        try:
            var_name = proposal.target
            new_type_str = proposal.proposed_value
            # [success, error_msg, old_type]
            result_holder = [False, "", ""]

            def _do_retype():
                try:
                    func = ida_funcs.get_func(function_address)
                    if not func:
                        result_holder[1] = f"No function found at address {hex(function_address)}"
                        return

                    cfunc = ida_hexrays.decompile(func.start_ea)
                    if not cfunc:
                        result_holder[1] = "Decompilation failed"
                        return

                    lvars = cfunc.get_lvars()
                    target_lvar = None
                    for lvar in lvars:
                        if lvar.name == var_name:
                            target_lvar = lvar
                            break

                    if not target_lvar:
                        result_holder[1] = f"Variable '{var_name}' not found"
                        return

                    result_holder[2] = str(target_lvar.type())

                    # Parse the new type string
                    tinfo = ida_typeinf.tinfo_t()
                    til = ida_typeinf.get_idati()
                    parsed = ida_typeinf.parse_decl(tinfo, til, new_type_str + ";", 0)
                    if parsed is None:
                        result_holder[1] = f"Failed to parse type '{new_type_str}'"
                        return

                    # Apply the new type
                    target_lvar.set_lvar_type(tinfo)
                    cfunc.save_lvars()
                    result_holder[0] = True

                except Exception as e:
                    result_holder[1] = str(e)

            execute_on_main_thread(_do_retype)

            if result_holder[0]:
                return ActionResult(
                    success=True,
                    message=f"Changed type of '{var_name}' from '{result_holder[2]}' to '{new_type_str}'",
                    action_type=proposal.action_type,
                    target=proposal.target,
                    old_value=result_holder[2],
                    new_value=new_type_str
                )
            else:
                return ActionResult(
                    success=False,
                    message=f"Failed to retype variable: {result_holder[1]}",
                    action_type=proposal.action_type,
                    target=proposal.target,
                    error=result_holder[1]
                )

        except Exception as e:
            return ActionResult(
                success=False,
                message=f"Failed to retype variable: {str(e)}",
                action_type=proposal.action_type,
                target=proposal.target,
                error=str(e)
            )

    def _apply_auto_create_struct(self, function_address: int, proposal: ActionProposal) -> ActionResult:
        """Apply automatic struct creation via IDA's type system"""
        try:
            struct_def = proposal.proposed_value
            struct_name = proposal.target
            result_holder = [False, ""]

            def _do_create():
                try:
                    tinfo = ida_typeinf.tinfo_t()
                    til = ida_typeinf.get_idati()
                    parsed = ida_typeinf.parse_decl(tinfo, til, struct_def + ";", 0)
                    if parsed is None:
                        result_holder[1] = f"Failed to parse struct definition"
                        return

                    rc = tinfo.set_named_type(til, struct_name, ida_typeinf.NTF_REPLACE)
                    if rc != 0:
                        result_holder[0] = True
                    else:
                        result_holder[1] = "set_named_type failed"

                except Exception as e:
                    result_holder[1] = str(e)

            execute_on_main_thread(_do_create)

            if result_holder[0]:
                return ActionResult(
                    success=True,
                    message=f"Created struct '{struct_name}'",
                    action_type=proposal.action_type,
                    target=proposal.target,
                    new_value=struct_def
                )
            else:
                return ActionResult(
                    success=False,
                    message=f"Failed to create struct: {result_holder[1]}",
                    action_type=proposal.action_type,
                    target=proposal.target,
                    error=result_holder[1]
                )

        except Exception as e:
            return ActionResult(
                success=False,
                message=f"Failed to create struct: {str(e)}",
                action_type=proposal.action_type,
                target=proposal.target,
                error=str(e)
            )

    def get_current_function(self):
        """Get the current function address for analysis"""
        try:
            context = self.context_service.get_current_context()
            if context.get("error"):
                return None
            return context.get("offset")
        except Exception as e:
            log.log_error(f"Error getting current function: {e}")
            return None
