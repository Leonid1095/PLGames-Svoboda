"""AI Decision Engine — central autonomous agent for DPI bypass.

Instead of linear pipeline (ISP → classifier → enum → GA → apply),
AI Engine is the orchestrator that decides what to do next.

Architecture:
    AI observes → forms hypothesis → calls tool → analyzes result → repeats

Tools available to AI:
    - run_enumerator: fast strategy search
    - run_per_host_solver: find strategy for specific blocked host
    - test_strategy: test a strategy against hosts
    - get_block_analysis: classify blocking type for a host
    - apply_strategy: apply strategy to permanent winws2
    - report: send results to server

The AI receives structured context (packet events, test history, TSPU profile)
and reasons like a network engineer, not a text generator.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Optional, Callable

logger = logging.getLogger("svoboda.ai_engine")


# ─── Tool definitions ─────────────────────────────────────────────────────────

TOOLS = [
    {
        "name": "run_enumerator",
        "description": "Fast search through 25 known strategies. Returns best fitness and strategy.",
        "parameters": {
            "hosts": {"type": "list[str]", "description": "Target hosts to test"},
            "forbid_genes": {"type": "list[str]", "description": "Functions to exclude (e.g. ['fake'] if fake always fails)"},
            "stop_on_fitness": {"type": "float", "description": "Stop when fitness exceeds this value"},
        },
    },
    {
        "name": "run_per_host_solver",
        "description": "Find a strategy that works for ONE specific host that other strategies miss.",
        "parameters": {
            "host": {"type": "str", "description": "The blocked host to solve"},
        },
    },
    {
        "name": "test_strategy",
        "description": "Test a specific strategy against all target hosts. Returns per-host results.",
        "parameters": {
            "strategy": {"type": "str", "description": "lua-desync strategy string (pipe-separated calls)"},
            "hosts": {"type": "list[str]", "description": "Hosts to test against"},
        },
    },
    {
        "name": "get_block_analysis",
        "description": "Analyze HOW a specific host is blocked: SNI filtering, RST injection, H2 stream kill, IP block, throttling.",
        "parameters": {
            "host": {"type": "str", "description": "Host to analyze"},
        },
    },
    {
        "name": "apply_strategy",
        "description": "Apply a strategy permanently to winws2 with hostlist. Restarts the DPI bypass engine.",
        "parameters": {
            "strategy": {"type": "str", "description": "Strategy to apply"},
            "extra_profiles": {"type": "list[dict]", "description": "Optional per-host profiles: [{hosts: [...], strategy: '...'}]"},
        },
    },
    {
        "name": "done",
        "description": "Signal that all goals are achieved or no further improvement is possible.",
        "parameters": {
            "summary": {"type": "str", "description": "What was achieved"},
            "failed_hosts": {"type": "list[str]", "description": "Hosts that could not be unblocked"},
        },
    },
]

SYSTEM_PROMPT = """\
You are an autonomous network engineer specializing in DPI bypass.
Your goal: unblock ALL target hosts on the user's ISP.

DECISION RULES:

1. ALWAYS start with run_enumerator — it's fastest (30 sec).
   If it finds fitness > 0.5, apply it immediately.

2. After applying, check which hosts are still FAIL.
   For each FAIL host, run get_block_analysis to understand WHY.

3. Based on block analysis:
   - SNI_FILTERING → multisplit/multidisorder strategies work
   - HTTP2_STREAM_KILL → needs wssize:wsize=1 + multidisorder
   - RST_INJECTION → fake with correct TTL may work (check TSPU hops)
   - IP_BLOCK → nothing works at packet level, need proxy
   - THROTTLING → wssize manipulation + QUIC fallback

4. For each FAIL host, run run_per_host_solver.
   If it finds a strategy → apply with extra per-host profile.

5. NEVER try fake strategies if test history shows fake = 0.0 consistently.
   Exclude fake from forbid_genes in enumerator.

6. Call done() when:
   - All hosts have fitness > 0.5, OR
   - You've tried 3+ approaches for a host and nothing works

7. Maximum 8 tool calls per session. Be efficient.

RESPOND WITH EXACTLY ONE TOOL CALL IN JSON:
{"tool": "tool_name", "args": {...}, "reasoning": "1 sentence why"}
"""


@dataclass
class ToolResult:
    """Result from executing a tool."""
    tool: str
    success: bool
    data: dict = field(default_factory=dict)
    error: str = ""


class AIEngine:
    """Central AI Decision Engine with agentic loop.

    Usage:
        engine = AIEngine(config, tools={...})
        engine.run(context)  # autonomous loop until goal reached
    """

    def __init__(
        self,
        config: dict,
        ai_chat_fn: Callable,  # function to call LLM (ai_advisor._chat)
        tool_handlers: dict[str, Callable] = None,
        max_iterations: int = 8,
    ):
        self._config = config
        self._chat = ai_chat_fn
        self._handlers = tool_handlers or {}
        self._max_iterations = max_iterations
        self._history: list[dict] = []  # conversation history

    def register_tool(self, name: str, handler: Callable) -> None:
        """Register a tool handler."""
        self._handlers[name] = handler

    def run(self, context: dict) -> dict:
        """Run agentic loop until goal achieved or max iterations.

        Args:
            context: Initial context (TSPU profile, test history, blocked hosts, etc.)

        Returns:
            Final result dict with applied strategies and status per host.
        """
        logger.info("AI Engine starting with %d blocked hosts", len(context.get("blocked_hosts", [])))

        # Build initial message
        self._history = []
        context_str = json.dumps(context, ensure_ascii=False, indent=2)

        final_result = {
            "applied_strategy": None,
            "per_host_strategies": {},
            "host_status": {},
            "iterations": 0,
        }

        for iteration in range(self._max_iterations):
            final_result["iterations"] = iteration + 1

            # Build prompt for AI
            if iteration == 0:
                user_msg = f"Here is the current network state:\n\n{context_str}\n\nWhat should we do first?"
            else:
                # Include last tool result
                last = self._history[-1] if self._history else {}
                user_msg = f"Tool result:\n{json.dumps(last, ensure_ascii=False, indent=2)}\n\nWhat next?"

            # Call LLM
            try:
                response = self._call_ai(user_msg)
            except Exception as exc:
                logger.warning("AI Engine LLM call failed: %s", exc)
                # Fallback: run enumerator directly
                return self._fallback_run(context)

            # Parse tool call
            tool_call = self._parse_tool_call(response)
            if not tool_call:
                logger.warning("AI Engine: could not parse tool call from response")
                continue

            tool_name = tool_call.get("tool", "")
            tool_args = tool_call.get("args", {})
            reasoning = tool_call.get("reasoning", "")

            logger.info("AI Engine [%d/%d]: %s — %s",
                        iteration + 1, self._max_iterations, tool_name, reasoning)

            # Check for done
            if tool_name == "done":
                final_result["applied_strategy"] = tool_args.get("summary", "")
                final_result["failed_hosts"] = tool_args.get("failed_hosts", [])
                logger.info("AI Engine done: %s", tool_args.get("summary", ""))
                return final_result

            # Execute tool
            result = self._execute_tool(tool_name, tool_args)
            self._history.append({
                "tool": tool_name,
                "args": tool_args,
                "result": result.data if result.success else {"error": result.error},
                "success": result.success,
            })

            # Update final result based on tool results
            if tool_name == "apply_strategy" and result.success:
                final_result["applied_strategy"] = tool_args.get("strategy", "")
                final_result["host_status"] = result.data.get("host_status", {})
            elif tool_name == "run_per_host_solver" and result.success:
                host = tool_args.get("host", "")
                if result.data.get("strategy"):
                    final_result["per_host_strategies"][host] = result.data["strategy"]

        logger.info("AI Engine: max iterations reached (%d)", self._max_iterations)
        return final_result

    def _call_ai(self, user_message: str) -> str:
        """Call LLM with system prompt + conversation history."""
        # Build messages for LLM
        full_prompt = f"{SYSTEM_PROMPT}\n\n{user_message}"

        # Include relevant history (last 3 tool results)
        if self._history:
            history_str = "\n\nPrevious actions:\n"
            for h in self._history[-3:]:
                history_str += f"- {h['tool']}({json.dumps(h['args'], ensure_ascii=False)[:100]}) → {'OK' if h['success'] else 'FAIL'}\n"
            full_prompt += history_str

        return self._chat(full_prompt)

    def _parse_tool_call(self, response: str) -> Optional[dict]:
        """Parse LLM response into tool call dict."""
        text = response.strip()

        # Try direct JSON parse
        try:
            data = json.loads(text)
            if isinstance(data, dict) and "tool" in data:
                return data
        except json.JSONDecodeError:
            pass

        # Try to find JSON in response
        start = text.find("{")
        end = text.rfind("}") + 1
        if start >= 0 and end > start:
            try:
                data = json.loads(text[start:end])
                if isinstance(data, dict) and "tool" in data:
                    return data
            except json.JSONDecodeError:
                pass

        # Try to find in markdown code block
        if "```" in text:
            for block in text.split("```"):
                block = block.strip()
                if block.startswith("json"):
                    block = block[4:].strip()
                try:
                    data = json.loads(block)
                    if isinstance(data, dict) and "tool" in data:
                        return data
                except (json.JSONDecodeError, ValueError):
                    continue

        logger.debug("Could not parse tool call: %s", text[:200])
        return None

    def _execute_tool(self, name: str, args: dict) -> ToolResult:
        """Execute a registered tool."""
        handler = self._handlers.get(name)
        if not handler:
            return ToolResult(tool=name, success=False, error=f"Unknown tool: {name}")

        try:
            result = handler(**args)
            if isinstance(result, dict):
                return ToolResult(tool=name, success=True, data=result)
            return ToolResult(tool=name, success=True, data={"result": result})
        except Exception as exc:
            logger.warning("Tool %s failed: %s", name, exc)
            return ToolResult(tool=name, success=False, error=str(exc))

    def _fallback_run(self, context: dict) -> dict:
        """Fallback when AI is unavailable — skip, let community/enum handle it."""
        logger.info("AI Engine fallback: skipping to community/enum pipeline")
        # Don't run enumerator here — it duplicates work and doesn't apply strategy.
        # Return empty result so main flow handles it.

        return {"applied_strategy": None, "iterations": 0, "fallback": True}


def build_engine_context(
    isp: str,
    asn: str,
    tspu_profile: dict,
    block_analysis: dict[str, dict],
    test_history: list[dict],
    excluded_functions: list[str],
    best_known_strategy: str = "",
    best_known_fitness: float = 0.0,
) -> dict:
    """Build structured context for AI Engine.

    This is what AI sees — the more detailed, the better AI reasons.
    """
    return {
        "isp": isp,
        "asn": asn,
        "tspu": tspu_profile,
        "blocked_hosts": [
            {
                "host": host,
                "block_type": analysis.get("block_type", "unknown"),
                "confidence": analysis.get("confidence", 0.0),
                "evidence": analysis.get("evidence", ""),
            }
            for host, analysis in block_analysis.items()
        ],
        "test_history": test_history[-10:],  # last 10 tests
        "excluded_functions": excluded_functions,
        "best_known": {
            "strategy": best_known_strategy,
            "fitness": best_known_fitness,
        },
        "goal": "Unblock ALL hosts. Fitness > 0.5 for each.",
    }
