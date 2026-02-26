#!/usr/bin/env python3
"""
Context Window Manager for IDAssist

This module provides intelligent context window management for LLM conversations,
preventing context overflow during long-running agentic workflows.

Features:
- Pre-flight token counting using provider APIs
- Automatic context compression when approaching limits
- LLM-based summarization of older conversation history
- Preservation of recent tool call/result pairs for coherence
- Truncation of oversized individual tool results
"""

from dataclasses import dataclass
from typing import List, Dict, Any, Optional, Tuple
from copy import deepcopy

from .models.llm_models import (
    ChatMessage, ChatRequest, MessageRole, ToolCall
)
from .models.context_models import ContextWindowConfig, ContextStatus
from .llm_providers.base_provider import BaseLLMProvider

from src.ida_compat import log


class ContextWindowManager:
    """
    Manages conversation history to prevent context window overflow.

    This class monitors token usage and automatically compresses conversation
    history when approaching the context limit, using LLM-based summarization
    to preserve important context while reducing token count.

    Example usage:
        manager = ContextWindowManager(llm_provider, config)

        # Before each LLM call
        managed_history = await manager.check_and_manage(
            conversation_history,
            tools=mcp_tools
        )

        # Use managed_history instead of original
        request = ChatRequest(messages=managed_history, ...)
    """

    # Summarization prompt template
    SUMMARY_PROMPT = """Summarize the following investigation conversation concisely.

Preserve these key elements:
- Important discoveries and findings
- Tools that were used and their significant results
- Current investigation progress and state
- Any identified patterns, vulnerabilities, or issues
- Key addresses, function names, or code references mentioned

Previous conversation to summarize:
{conversation}

Provide a concise summary (target: ~500 words) that captures the essential context needed to continue this investigation effectively. Focus on facts and findings, not the conversation flow."""

    def __init__(
        self,
        llm_provider: BaseLLMProvider,
        config: Optional[ContextWindowConfig] = None
    ):
        """
        Initialize the context window manager.

        Args:
            llm_provider: LLM provider for token counting and summarization
            config: Optional configuration, uses defaults if not provided
        """
        self.llm_provider = llm_provider
        self.config = config or ContextWindowConfig()

        # Track compression statistics
        self._compression_count = 0
        self._total_tokens_saved = 0

        log.log_info(
            f"ContextWindowManager initialized: limit={self.config.context_limit_tokens:,}, "
            f"threshold={self.config.threshold_percent:.0%}"
        )

    async def get_status(
        self,
        messages: List[ChatMessage],
        tools: Optional[List[Dict[str, Any]]] = None
    ) -> ContextStatus:
        """
        Get current context window status without modifying messages.

        Args:
            messages: Current conversation history
            tools: Optional tool definitions

        Returns:
            ContextStatus with current usage information
        """
        # Count tokens
        token_count = await self._count_tokens(messages, tools)

        # Count tool pairs
        tool_pairs = self._extract_tool_pairs(messages)

        percent_used = token_count / self.config.context_limit_tokens
        needs_compression = token_count >= self.config.trigger_threshold

        return ContextStatus(
            total_tokens=token_count,
            limit_tokens=self.config.context_limit_tokens,
            percent_used=percent_used,
            needs_compression=needs_compression,
            message_count=len(messages),
            tool_pair_count=len(tool_pairs)
        )

    async def check_and_manage(
        self,
        messages: List[ChatMessage],
        tools: Optional[List[Dict[str, Any]]] = None
    ) -> List[ChatMessage]:
        """
        Check context size and compress if needed.

        This is the main entry point for context management. Call this before
        each LLM request to ensure the conversation stays within limits.

        Args:
            messages: Current conversation history
            tools: Optional tool definitions (affects token count)

        Returns:
            Managed message list (may be compressed if over threshold)
        """
        # ALWAYS validate tool pairs first to prevent API errors
        # This catches any orphaned tool calls/results that may exist
        validated_messages = self._validate_and_fix_tool_pairs(messages)

        if len(validated_messages) != len(messages):
            log.log_info(
                f"Tool pair validation removed {len(messages) - len(validated_messages)} "
                f"orphaned messages"
            )

        # Get current status
        status = await self.get_status(validated_messages, tools)

        log.log_debug(f"Context status: {status}")

        if not status.needs_compression:
            return validated_messages

        log.log_info(
            f"Context compression triggered: {status.total_tokens:,} tokens "
            f"({status.percent_used:.1%} of {self.config.context_limit_tokens:,} limit)"
        )

        # Perform compression
        compressed = await self._compress_history(validated_messages, tools)

        # Verify compression worked
        new_status = await self.get_status(compressed, tools)
        tokens_saved = status.total_tokens - new_status.total_tokens

        self._compression_count += 1
        self._total_tokens_saved += tokens_saved

        log.log_info(
            f"Context compressed: {status.total_tokens:,} -> {new_status.total_tokens:,} tokens "
            f"(saved {tokens_saved:,}, {new_status.percent_used:.1%} used)"
        )

        # Check if still over limit after compression
        if new_status.needs_compression:
            log.log_warn(
                f"Context still high after compression: {new_status.total_tokens:,} tokens. "
                "Applying emergency truncation."
            )
            compressed = await self._emergency_truncate(compressed, tools)

        return compressed

    def truncate_tool_result(self, content: str, max_tokens: Optional[int] = None) -> str:
        """
        Truncate a tool result if it exceeds the maximum token limit.

        Args:
            content: Tool result content
            max_tokens: Maximum tokens allowed (uses config default if not specified)

        Returns:
            Truncated content with indicator if truncation occurred
        """
        max_tokens = max_tokens or self.config.max_tool_result_tokens

        # Estimate tokens (~4 chars per token)
        estimated_tokens = len(content) // 4

        if estimated_tokens <= max_tokens:
            return content

        # Calculate truncation point
        max_chars = max_tokens * 4
        truncated = content[:max_chars]

        # Try to truncate at a line boundary
        last_newline = truncated.rfind('\n')
        if last_newline > max_chars * 0.8:  # Only if we don't lose too much
            truncated = truncated[:last_newline]

        truncation_notice = (
            f"\n\n[... truncated: {estimated_tokens - max_tokens:,} tokens removed "
            f"({len(content) - len(truncated):,} chars) ...]"
        )

        return truncated + truncation_notice

    async def _count_tokens(
        self,
        messages: List[ChatMessage],
        tools: Optional[List[Dict[str, Any]]] = None
    ) -> int:
        """Count tokens for a message list using the provider's token counter."""
        # Create a temporary request for token counting
        request = ChatRequest(
            messages=messages,
            model=self.llm_provider.model,
            tools=tools
        )

        try:
            return await self.llm_provider.count_tokens(request)
        except Exception as e:
            log.log_warn(f"Token counting failed, using estimation: {e}")
            # Fall back to character-based estimation
            total_chars = sum(len(m.content or '') for m in messages)
            return total_chars // 4

    async def _compress_history(
        self,
        messages: List[ChatMessage],
        tools: Optional[List[Dict[str, Any]]] = None
    ) -> List[ChatMessage]:
        """
        Compress conversation history by summarizing older messages.

        Strategy:
        1. Always keep: system prompt, recent tool pairs, last user message
        2. Summarize: everything in between
        3. CRITICAL: Ensure tool call/result pairs are never split
        """
        if len(messages) <= self.config.min_recent_messages:
            return messages

        # Identify message segments
        system_messages = []
        other_messages = []

        for msg in messages:
            if msg.role == MessageRole.SYSTEM:
                system_messages.append(msg)
            else:
                other_messages.append(msg)

        if not other_messages:
            return messages

        # Extract ALL tool pairs to understand message relationships
        all_tool_pairs = self._extract_tool_pairs(other_messages)

        # Build a map of which messages belong to which tool pair
        # This ensures we never split a tool call from its results
        message_to_pair_idx: Dict[int, int] = {}
        for pair_idx, (assistant_msg, tool_msgs) in enumerate(all_tool_pairs):
            if assistant_msg in other_messages:
                msg_idx = other_messages.index(assistant_msg)
                message_to_pair_idx[msg_idx] = pair_idx
            for tm in tool_msgs:
                if tm in other_messages:
                    msg_idx = other_messages.index(tm)
                    message_to_pair_idx[msg_idx] = pair_idx

        # Determine which tool pairs to keep (the most recent ones)
        pairs_to_keep = set()
        if all_tool_pairs:
            # Keep the last N tool pairs
            keep_count = min(self.config.min_recent_tool_pairs, len(all_tool_pairs))
            for i in range(len(all_tool_pairs) - keep_count, len(all_tool_pairs)):
                pairs_to_keep.add(i)

        # Build the set of message indices to keep
        indices_to_keep = set()

        # Always keep recent messages (last min_recent_messages)
        recent_start = max(0, len(other_messages) - self.config.min_recent_messages)
        for i in range(recent_start, len(other_messages)):
            indices_to_keep.add(i)
            # If this message is part of a tool pair, keep the ENTIRE pair
            if i in message_to_pair_idx:
                pair_idx = message_to_pair_idx[i]
                pairs_to_keep.add(pair_idx)

        # Add all messages from tool pairs we're keeping
        for pair_idx in pairs_to_keep:
            assistant_msg, tool_msgs = all_tool_pairs[pair_idx]
            if assistant_msg in other_messages:
                indices_to_keep.add(other_messages.index(assistant_msg))
            for tm in tool_msgs:
                if tm in other_messages:
                    indices_to_keep.add(other_messages.index(tm))

        # Separate messages to summarize vs keep
        messages_to_summarize = []
        messages_to_keep = []

        for i, msg in enumerate(other_messages):
            if i in indices_to_keep:
                messages_to_keep.append(msg)
            else:
                # Don't include orphaned tool results in summary
                # (they would cause issues if somehow kept)
                if msg.role == MessageRole.TOOL:
                    log.log_debug(f"Skipping orphaned tool result in compression: {msg.tool_call_id}")
                    continue
                # Don't include assistant messages with tool calls that aren't in kept pairs
                # (their results would be missing)
                if msg.role == MessageRole.ASSISTANT and msg.tool_calls:
                    log.log_debug(f"Skipping assistant message with orphaned tool calls in compression")
                    continue
                messages_to_summarize.append(msg)

        # If nothing to summarize, return as-is
        if not messages_to_summarize:
            return messages

        # Generate summary
        summary_text = await self._generate_summary(messages_to_summarize)

        # Create summary message
        summary_message = ChatMessage(
            role=MessageRole.USER,
            content=f"[Previous Investigation Summary]\n\n{summary_text}\n\n[End of Summary - Continuing Investigation]"
        )

        # Reconstruct message list and validate
        result = system_messages + [summary_message] + messages_to_keep

        # Final validation: ensure no orphaned tool calls or results
        result = self._validate_and_fix_tool_pairs(result)

        return result

    async def _generate_summary(self, messages: List[ChatMessage]) -> str:
        """Generate an LLM summary of the messages."""
        # Format messages for summarization
        conversation_text = self._format_messages_for_summary(messages)

        # Create summarization request
        summary_prompt = self.SUMMARY_PROMPT.format(conversation=conversation_text)

        summary_request = ChatRequest(
            messages=[
                ChatMessage(
                    role=MessageRole.USER,
                    content=summary_prompt
                )
            ],
            model=self.llm_provider.model,
            max_tokens=self.config.summary_target_tokens,
            temperature=0.3  # Lower temperature for more factual summary
        )

        try:
            response = await self.llm_provider.chat_completion(summary_request)
            return response.content
        except Exception as e:
            log.log_error(f"LLM summarization failed: {e}")
            # Fall back to extractive summary
            return self._extractive_summary(messages)

    def _extractive_summary(self, messages: List[ChatMessage]) -> str:
        """
        Create a simple extractive summary when LLM summarization fails.

        Extracts key information like tool calls, findings, and important content.
        """
        summary_parts = []

        tool_calls_seen = []
        findings = []

        for msg in messages:
            # Track tool calls
            if msg.tool_calls:
                for tc in msg.tool_calls:
                    tool_calls_seen.append(tc.name)

            # Extract potential findings from assistant messages
            if msg.role == MessageRole.ASSISTANT and msg.content:
                # Look for key indicators
                content = msg.content.lower()
                if any(kw in content for kw in ['found', 'discovered', 'identified', 'detected', 'vulnerability', 'issue']):
                    # Take first 200 chars of relevant content
                    findings.append(msg.content[:200])

        if tool_calls_seen:
            summary_parts.append(f"Tools used: {', '.join(set(tool_calls_seen))}")

        if findings:
            summary_parts.append(f"Key findings:\n" + "\n".join(f"- {f}..." for f in findings[:5]))

        if not summary_parts:
            summary_parts.append(f"(Summarized {len(messages)} messages)")

        return "\n\n".join(summary_parts)

    def _format_messages_for_summary(self, messages: List[ChatMessage]) -> str:
        """Format messages as text for summarization prompt."""
        formatted = []

        for msg in messages:
            role = msg.role.value.upper()
            content = msg.content or ""

            # Truncate very long messages
            if len(content) > 2000:
                content = content[:2000] + "... [truncated]"

            # Include tool call info
            if msg.tool_calls:
                tool_info = ", ".join(tc.name for tc in msg.tool_calls)
                formatted.append(f"{role}: [Called tools: {tool_info}]\n{content}")
            else:
                formatted.append(f"{role}: {content}")

        return "\n\n".join(formatted)

    def _extract_tool_pairs(
        self,
        messages: List[ChatMessage]
    ) -> List[Tuple[ChatMessage, List[ChatMessage]]]:
        """
        Extract tool call/result pairs from messages.

        Returns pairs of (assistant_message_with_tool_calls, [tool_result_messages]).
        Tool pairs are atomic and should be kept or removed together.
        """
        pairs = []
        i = 0

        while i < len(messages):
            msg = messages[i]

            # Look for assistant messages with tool calls
            if msg.role == MessageRole.ASSISTANT and msg.tool_calls:
                tool_call_ids = {tc.id for tc in msg.tool_calls}
                tool_results = []

                # Collect following tool result messages
                j = i + 1
                while j < len(messages):
                    next_msg = messages[j]
                    if next_msg.role == MessageRole.TOOL and next_msg.tool_call_id in tool_call_ids:
                        tool_results.append(next_msg)
                        tool_call_ids.discard(next_msg.tool_call_id)
                    elif next_msg.role != MessageRole.TOOL:
                        break
                    j += 1

                if tool_results:
                    pairs.append((msg, tool_results))
                    i = j
                    continue

            i += 1

        return pairs

    def _extract_tool_call_ids_from_message(self, msg: ChatMessage) -> set:
        """
        Extract all tool call IDs from a message, checking both tool_calls field
        and native_content for tool_use blocks.

        Args:
            msg: Message to extract tool call IDs from

        Returns:
            Set of tool call IDs found in the message
        """
        tool_ids = set()

        # Check the tool_calls field
        if msg.tool_calls:
            for tc in msg.tool_calls:
                tool_ids.add(tc.id)

        # Also check native_content for tool_use blocks (Anthropic format)
        if msg.native_content and isinstance(msg.native_content, list):
            for block in msg.native_content:
                if isinstance(block, dict) and block.get('type') == 'tool_use':
                    tool_id = block.get('id')
                    if tool_id:
                        tool_ids.add(tool_id)

        return tool_ids

    def _extract_tool_result_ids_from_message(self, msg: ChatMessage) -> set:
        """
        Extract all tool result IDs from a message, checking both tool_call_id field
        and native_content for tool_result blocks.

        Args:
            msg: Message to extract tool result IDs from

        Returns:
            Set of tool result IDs found in the message
        """
        result_ids = set()

        # Check the tool_call_id field (for TOOL role messages)
        if msg.tool_call_id:
            result_ids.add(msg.tool_call_id)

        # Also check native_content for tool_result blocks (Anthropic format)
        if msg.native_content and isinstance(msg.native_content, list):
            for block in msg.native_content:
                if isinstance(block, dict) and block.get('type') == 'tool_result':
                    tool_use_id = block.get('tool_use_id')
                    if tool_use_id:
                        result_ids.add(tool_use_id)

        return result_ids

    def _message_has_tool_calls(self, msg: ChatMessage) -> bool:
        """Check if a message contains any tool calls (in tool_calls or native_content)."""
        if msg.tool_calls:
            return True
        if msg.native_content and isinstance(msg.native_content, list):
            for block in msg.native_content:
                if isinstance(block, dict) and block.get('type') == 'tool_use':
                    return True
        return False

    def _strip_tool_calls_from_native_content(self, native_content: list) -> list:
        """
        Remove tool_use blocks from native content, keeping other blocks like text and thinking.

        Args:
            native_content: List of content blocks

        Returns:
            Filtered list with tool_use blocks removed
        """
        if not native_content:
            return []
        return [
            block for block in native_content
            if not (isinstance(block, dict) and block.get('type') == 'tool_use')
        ]

    def _validate_and_fix_tool_pairs(
        self,
        messages: List[ChatMessage]
    ) -> List[ChatMessage]:
        """
        Validate that all tool calls have corresponding results IMMEDIATELY AFTER.

        Anthropic requires tool_result blocks to come in the NEXT message after
        the assistant message with tool_use blocks. This validation checks both:
        1. That all tool_use IDs have matching tool_result IDs
        2. That tool_results come immediately after their tool_use (positional check)

        IMPORTANT: This checks both the tool_calls field AND native_content for
        tool_use/tool_result blocks, as Anthropic's native format stores these
        directly in content blocks.

        Args:
            messages: List of messages to validate

        Returns:
            Cleaned message list with no orphaned tool calls/results
        """
        if not messages:
            return messages

        # First, do a global ID collection to find completely orphaned IDs
        all_tool_call_ids = set()
        all_tool_result_ids = set()

        for msg in messages:
            if msg.role == MessageRole.ASSISTANT:
                all_tool_call_ids.update(self._extract_tool_call_ids_from_message(msg))
            elif msg.role == MessageRole.TOOL:
                all_tool_result_ids.update(self._extract_tool_result_ids_from_message(msg))
            elif msg.role == MessageRole.USER:
                all_tool_result_ids.update(self._extract_tool_result_ids_from_message(msg))

        globally_orphaned_calls = all_tool_call_ids - all_tool_result_ids
        globally_orphaned_results = all_tool_result_ids - all_tool_call_ids

        # Second, do positional validation: tool_results must come IMMEDIATELY after tool_use
        # Find assistant messages with tool_use that don't have results immediately after
        positionally_orphaned_calls = set()

        for i, msg in enumerate(messages):
            if msg.role == MessageRole.ASSISTANT:
                tool_ids = self._extract_tool_call_ids_from_message(msg)
                if tool_ids:
                    # Check if the next message(s) contain tool_results for these IDs
                    # Tool results should be in the immediately following message(s)
                    found_result_ids = set()
                    j = i + 1

                    # Collect tool results from immediately following TOOL or USER messages
                    while j < len(messages):
                        next_msg = messages[j]
                        if next_msg.role == MessageRole.TOOL:
                            found_result_ids.update(self._extract_tool_result_ids_from_message(next_msg))
                            j += 1
                        elif next_msg.role == MessageRole.USER:
                            # User message with tool_results in native_content (Anthropic format)
                            user_result_ids = self._extract_tool_result_ids_from_message(next_msg)
                            if user_result_ids:
                                found_result_ids.update(user_result_ids)
                                j += 1
                            else:
                                # User message without tool_results - stop looking
                                break
                        else:
                            # Another assistant message or system - stop looking
                            break

                    # Any tool_use IDs not found immediately after are positionally orphaned
                    missing = tool_ids - found_result_ids
                    if missing:
                        log.log_debug(
                            f"Message {i}: tool_use IDs {missing} don't have results immediately after"
                        )
                        positionally_orphaned_calls.update(missing)

        # Combine all orphaned IDs
        orphaned_call_ids = globally_orphaned_calls | positionally_orphaned_calls
        orphaned_result_ids = globally_orphaned_results

        log.log_debug(
            f"Tool pair validation: {len(all_tool_call_ids)} calls, {len(all_tool_result_ids)} results, "
            f"{len(orphaned_call_ids)} orphaned calls ({len(globally_orphaned_calls)} global, "
            f"{len(positionally_orphaned_calls)} positional), {len(orphaned_result_ids)} orphaned results"
        )

        if orphaned_call_ids:
            log.log_warn(
                f"Found {len(orphaned_call_ids)} tool calls without valid results: "
                f"{list(orphaned_call_ids)[:5]}{'...' if len(orphaned_call_ids) > 5 else ''}. "
                f"Removing to prevent API errors."
            )

        if orphaned_result_ids:
            log.log_warn(
                f"Found {len(orphaned_result_ids)} tool results without calls: "
                f"{list(orphaned_result_ids)[:5]}{'...' if len(orphaned_result_ids) > 5 else ''}. "
                f"Removing to prevent API errors."
            )

        # If no orphans, return as-is
        if not orphaned_call_ids and not orphaned_result_ids:
            return messages

        # Third pass: filter out messages with orphaned tool calls/results
        result = []
        for msg in messages:
            if msg.role == MessageRole.ASSISTANT:
                msg_tool_ids = self._extract_tool_call_ids_from_message(msg)

                if msg_tool_ids & orphaned_call_ids:
                    # This message has orphaned tool calls
                    # Try to preserve non-tool content
                    if msg.native_content:
                        # Strip ONLY orphaned tool_use blocks from native content
                        cleaned_native = [
                            block for block in msg.native_content
                            if not (isinstance(block, dict) and
                                   block.get('type') == 'tool_use' and
                                   block.get('id') in orphaned_call_ids)
                        ]
                        if cleaned_native:
                            # There's other content to keep (text, thinking blocks, non-orphaned tool_use)
                            # Also filter tool_calls field
                            cleaned_tool_calls = None
                            if msg.tool_calls:
                                cleaned_tool_calls = [
                                    tc for tc in msg.tool_calls
                                    if tc.id not in orphaned_call_ids
                                ] or None

                            cleaned_msg = ChatMessage(
                                role=MessageRole.ASSISTANT,
                                content=msg.content or "",
                                native_content=cleaned_native,
                                tool_calls=cleaned_tool_calls
                            )
                            result.append(cleaned_msg)
                            log.log_debug(
                                f"Stripped orphaned tool_use blocks from assistant message, "
                                f"kept {len(cleaned_native)} other blocks"
                            )
                        elif msg.content:
                            # Only text content remains
                            cleaned_msg = ChatMessage(
                                role=MessageRole.ASSISTANT,
                                content=msg.content,
                                native_content=None,
                                tool_calls=None
                            )
                            result.append(cleaned_msg)
                            log.log_debug("Converted assistant message to text-only")
                        else:
                            log.log_debug("Dropped assistant message with only orphaned tool calls")
                    elif msg.content:
                        # No native content, just use text content
                        cleaned_msg = ChatMessage(
                            role=MessageRole.ASSISTANT,
                            content=msg.content,
                            native_content=None,
                            tool_calls=None
                        )
                        result.append(cleaned_msg)
                        log.log_debug("Converted assistant message to text-only (no native content)")
                    else:
                        log.log_debug("Dropped assistant message with orphaned tool calls (no content)")
                else:
                    result.append(msg)

            elif msg.role == MessageRole.TOOL:
                # Remove orphaned tool results
                if msg.tool_call_id in orphaned_result_ids:
                    log.log_debug(f"Dropped orphaned tool result: {msg.tool_call_id}")
                else:
                    result.append(msg)

            elif msg.role == MessageRole.USER:
                # User messages might contain tool_result blocks in native_content
                msg_result_ids = self._extract_tool_result_ids_from_message(msg)
                if msg_result_ids & orphaned_result_ids:
                    # This user message has orphaned tool results in native content
                    if msg.native_content:
                        # Filter out orphaned tool_result blocks
                        cleaned_native = [
                            block for block in msg.native_content
                            if not (isinstance(block, dict) and
                                   block.get('type') == 'tool_result' and
                                   block.get('tool_use_id') in orphaned_result_ids)
                        ]
                        if cleaned_native:
                            cleaned_msg = ChatMessage(
                                role=MessageRole.USER,
                                content=msg.content or "",
                                native_content=cleaned_native
                            )
                            result.append(cleaned_msg)
                        elif msg.content:
                            cleaned_msg = ChatMessage(
                                role=MessageRole.USER,
                                content=msg.content,
                                native_content=None
                            )
                            result.append(cleaned_msg)
                        # else drop the message
                    elif msg.content:
                        result.append(msg)
                else:
                    result.append(msg)
            else:
                result.append(msg)

        return result

    async def _emergency_truncate(
        self,
        messages: List[ChatMessage],
        tools: Optional[List[Dict[str, Any]]] = None
    ) -> List[ChatMessage]:
        """
        Emergency truncation when normal compression isn't enough.

        Progressively removes content until within limits.
        """
        result = deepcopy(messages)

        # First pass: aggressively truncate tool results
        for msg in result:
            if msg.role == MessageRole.TOOL and msg.content:
                # Truncate to 1/4 of normal limit
                msg.content = self.truncate_tool_result(
                    msg.content,
                    max_tokens=self.config.max_tool_result_tokens // 4
                )

        # Validate after truncation
        result = self._validate_and_fix_tool_pairs(result)

        # Check if that's enough
        status = await self.get_status(result, tools)
        if not status.needs_compression:
            return result

        # Second pass: keep only system + last N messages, preserving tool pairs
        system_msgs = [m for m in result if m.role == MessageRole.SYSTEM]
        other_msgs = [m for m in result if m.role != MessageRole.SYSTEM]

        # Find complete tool pairs in the recent messages
        # We need to be careful to keep tool call/result pairs together
        keep_count = self.config.min_recent_messages
        kept_messages = []

        # Work backwards from the end, keeping complete tool pairs
        i = len(other_msgs) - 1
        while i >= 0 and len(kept_messages) < keep_count * 2:  # Allow some extra for pairs
            msg = other_msgs[i]

            if msg.role == MessageRole.TOOL:
                # This is a tool result - find its corresponding assistant message
                tool_call_id = msg.tool_call_id
                kept_messages.insert(0, msg)

                # Look backwards for the assistant message with this tool call
                for j in range(i - 1, -1, -1):
                    prev_msg = other_msgs[j]
                    if prev_msg.role == MessageRole.ASSISTANT and prev_msg.tool_calls:
                        if any(tc.id == tool_call_id for tc in prev_msg.tool_calls):
                            # Found the assistant message - include it
                            if prev_msg not in kept_messages:
                                kept_messages.insert(0, prev_msg)
                            break
                    elif prev_msg.role == MessageRole.TOOL:
                        # Another tool result - might be part of same assistant message
                        if prev_msg not in kept_messages:
                            kept_messages.insert(0, prev_msg)
                    else:
                        break
            elif msg.role == MessageRole.ASSISTANT and msg.tool_calls:
                # Skip - we'll add these when we find their tool results
                pass
            else:
                # Regular message - just add it
                kept_messages.insert(0, msg)

            i -= 1

        result = system_msgs + kept_messages

        # Final validation
        result = self._validate_and_fix_tool_pairs(result)

        log.log_warn(f"Emergency truncation: kept only {len(result)} messages")

        return result

    def get_statistics(self) -> Dict[str, Any]:
        """Get context management statistics."""
        return {
            "compression_count": self._compression_count,
            "total_tokens_saved": self._total_tokens_saved,
            "config": {
                "context_limit_tokens": self.config.context_limit_tokens,
                "threshold_percent": self.config.threshold_percent,
                "max_tool_result_tokens": self.config.max_tool_result_tokens
            }
        }
