#!/usr/bin/env python3

"""
Todo List Manager for ReAct Agent

Manages investigation steps: parsing LLM planning responses,
tracking progress, and formatting for prompt injection.
"""

from typing import List, Optional
import re

from ..models.react_models import Todo, TodoStatus

from src.ida_compat import log


class TodoListManager:
    """Manages investigation todo list for ReAct agent"""

    def __init__(self):
        self.todos: List[Todo] = []

    def initialize_from_llm_response(self, plan_response: str):
        """
        Parse LLM planning response to extract todo items.

        Supports formats:
        - Markdown checkbox: "- [ ] task description"
        - Numbered list: "1. task description"
        - Bullet points: "- task description"
        """
        self.todos.clear()

        # Pattern: "- [ ] task description" or "- [x] task description"
        checkbox_pattern = r'[-*]\s*\[[ x]\]\s*(.+?)(?:\n|$)'
        # Pattern: "1. task description" or "2) task description"
        numbered_pattern = r'^\s*\d+[.\)]\s*(.+?)(?:\n|$)'
        # Pattern: "- task description" (simple bullets without checkbox)
        bullet_pattern = r'^\s*[-*]\s+(?!\[)(.+?)(?:\n|$)'

        # Try checkbox format first (most specific)
        matches = re.findall(checkbox_pattern, plan_response, re.MULTILINE)

        if not matches:
            # Try numbered list
            matches = re.findall(numbered_pattern, plan_response, re.MULTILINE)

        if not matches:
            # Try simple bullet points
            matches = re.findall(bullet_pattern, plan_response, re.MULTILINE)

        for task in matches:
            task = task.strip()
            # Filter out very short items or metadata
            if task and len(task) > 5 and not task.startswith('#'):
                self.todos.append(Todo(task=task))

        # Ensure we have at least one todo
        if not self.todos:
            log.log_warn("No todos parsed from LLM response, adding default")
            self.todos.append(Todo(task="Investigate the user's question"))

        log.log_info(f"TodoListManager: Initialized {len(self.todos)} todos")

    def get_next_pending(self) -> Optional[Todo]:
        """Get the next pending todo item"""
        for todo in self.todos:
            if todo.status == TodoStatus.PENDING:
                return todo
        return None

    def get_current_in_progress(self) -> Optional[Todo]:
        """Get the currently in-progress todo item"""
        for todo in self.todos:
            if todo.status == TodoStatus.IN_PROGRESS:
                return todo
        return None

    def mark_current_in_progress(self) -> Optional[Todo]:
        """Mark the next pending todo as in_progress and return it"""
        todo = self.get_next_pending()
        if todo:
            todo.mark_in_progress()
            log.log_debug(f"TodoListManager: Marked in_progress: {todo.task[:50]}...")
        return todo

    def mark_current_complete(self, evidence: str = None):
        """Mark the current in_progress todo as complete"""
        for todo in self.todos:
            if todo.status == TodoStatus.IN_PROGRESS:
                todo.mark_complete(evidence)
                log.log_debug(f"TodoListManager: Marked complete: {todo.task[:50]}...")
                return

    def add_tool_used(self, tool_name: str):
        """Add a tool to the current in_progress todo"""
        todo = self.get_current_in_progress()
        if todo and tool_name not in todo.tools_used:
            todo.tools_used.append(tool_name)

    def all_complete(self) -> bool:
        """Check if all todos are complete"""
        return all(t.status == TodoStatus.COMPLETE for t in self.todos)

    def get_pending_count(self) -> int:
        """Get count of pending todos"""
        return sum(1 for t in self.todos if t.status == TodoStatus.PENDING)

    def get_complete_count(self) -> int:
        """Get count of completed todos"""
        return sum(1 for t in self.todos if t.status == TodoStatus.COMPLETE)

    def format_for_prompt(self) -> str:
        """
        Format todo list for prompt injection.

        Uses markdown checkbox format:
        - [x] Completed task
        - [->] In progress task
        - [ ] Pending task
        """
        if not self.todos:
            return "*No investigation steps defined*"

        lines = []
        for todo in self.todos:
            if todo.status == TodoStatus.COMPLETE:
                marker = "[x]"
            elif todo.status == TodoStatus.IN_PROGRESS:
                marker = "[->]"
            else:
                marker = "[ ]"
            lines.append(f"- {marker} {todo.task}")

        return "\n".join(lines)

    def add_todo(self, task: str):
        """Add a new todo item"""
        self.todos.append(Todo(task=task))
        log.log_debug(f"TodoListManager: Added todo: {task[:50]}...")

    def remove_todo_by_task(self, task_text: str):
        """Remove a todo by matching task text (case-insensitive partial match)"""
        original_count = len(self.todos)
        task_lower = task_text.lower()
        self.todos = [t for t in self.todos if task_lower not in t.task.lower()]
        removed = original_count - len(self.todos)
        if removed > 0:
            log.log_debug(f"TodoListManager: Removed {removed} todo(s) matching: {task_text[:50]}...")

    def update_from_reflection(self, new_tasks: List[str], tasks_to_remove: List[str]):
        """
        Update todo list based on reflection.

        Args:
            new_tasks: List of new task descriptions to add
            tasks_to_remove: List of task descriptions to remove (partial match)
        """
        changes_made = False

        # Remove tasks first
        for task_text in tasks_to_remove:
            original_count = len(self.todos)
            # Only remove pending tasks to avoid removing in-progress or completed ones
            self.todos = [t for t in self.todos
                         if t.status != TodoStatus.PENDING or task_text.lower() not in t.task.lower()]
            removed = original_count - len(self.todos)
            if removed > 0:
                log.log_info(f"TodoListManager: Removed {removed} pending todo(s) matching: {task_text[:50]}...")
                changes_made = True

        # Add new tasks
        for task_text in new_tasks:
            # Check if similar task already exists
            task_lower = task_text.lower()
            exists = any(task_lower in t.task.lower() for t in self.todos)
            if not exists:
                self.todos.append(Todo(task=task_text))
                log.log_info(f"TodoListManager: Added new todo from reflection: {task_text[:50]}...")
                changes_made = True

        return changes_made

    def reset(self):
        """Reset all todos to pending"""
        for todo in self.todos:
            todo.status = TodoStatus.PENDING
            todo.evidence = None
            todo.tools_used.clear()
        log.log_debug("TodoListManager: Reset all todos to pending")

    def clear(self):
        """Clear all todos"""
        self.todos.clear()
        log.log_debug("TodoListManager: Cleared all todos")
