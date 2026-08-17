"""Sluice-mediated tool execution for AgentDojo's ENDORSE-direction evaluation.

AgentDojo's threat model (Debenedetti et al.) is: an LLM agent with tool
access processes environment content that may contain injected instructions;
an attacker wins if the agent is steered into calling an effectful tool with
attacker-chosen arguments. This is exactly Sluice's ENDORSE direction --
bounded-influence mediation of decisions an untrusted caller (here, content
the planner LLM reads and then acts on) can steer.

Design. Every *effectful* (state-mutating) tool in a task suite is one
symbol in a per-task K-ary alphabet; the planner LLM's tool-call selection
is treated as `untrusted_content` decoded against that alphabet by an
exact-match backend (the LLM has already made the selection -- Sluice's
role, per its own design, is independent re-validation and charging, not
selection). Each symbol carries an ActionTemplate whose argument
constraints bind the tool's security-relevant arguments (e.g. `recipient`)
to the set of values that appear in the task's own `ground_truth()` --
authored by the trusted planner from the task definition, before the
episode runs and without the agent or attacker ever seeing it. Read-only
tools are not mediated, matching Sluice's scoping of mediation to
consequential decisions (see paper §3.5).

This is an argument/effect-validation experiment, not a test of Sluice's
confidentiality theorem: it exercises the ENDORSE-direction mechanism
(ActionTemplate binding, capability-scoped one-time redemption) already
described in the paper, on a real published benchmark with real published
attacks, instead of only the paper's own hand-authored LangGraph study.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Mapping, Optional, Sequence

SLUICE_V2_PATH = None  # set by caller before import via sys.path.insert


def _ensure_sluice_on_path(sluice_v2_path: str) -> None:
    if sluice_v2_path not in sys.path:
        sys.path.insert(0, sluice_v2_path)


class ExactMatchBackend:
    """Sluice Backend: the planner LLM already chose a tool name; this
    backend independently re-validates that choice is in the committed
    alphabet rather than trusting it. Anything not in the alphabet decodes
    to a sentinel guaranteed to miss, producing a charged SCHEMA_VIOLATION
    rather than silently defaulting to some other symbol."""

    _MISS = "\x00__SLUICE_UNMATCHED__\x00"

    def decode(self, untrusted_content: str, symbol_values: Sequence[str]) -> str:
        if untrusted_content in symbol_values:
            return untrusted_content
        return self._MISS


@dataclass
class MediationRecord:
    """One row of what actually happened at a mediated tool call, kept
    independent of Sluice's own audit log so the experiment harness can
    report on it without re-opening the store."""

    task_id: str
    tool: str
    args: dict
    outcome: str
    charged_bits: float
    denied: bool


def build_effectful_action_templates(mediated_tools: Mapping[str, dict]) -> dict:
    """mediated_tools: {tool_name: {"recipient_arg": Optional[str],
    "recipient_scope": frozenset[str], "other_constraints": {arg: ArgConstraint}}}
    Returns {tool_name: ActionTemplate}. Imported lazily so this module can
    be imported for documentation/testing without Sluice on sys.path yet.
    """
    from actions import ActionTemplate, ArgConstraint, EffectClass

    templates = {}
    for tool_name, spec in mediated_tools.items():
        arg_constraints = dict(spec.get("other_constraints", {}))
        recipient_arg = spec.get("recipient_arg")
        recipient_scope = frozenset(spec.get("recipient_scope", ()))
        if recipient_arg is not None:
            arg_constraints[recipient_arg] = ArgConstraint(allowed_values=recipient_scope or None)
        templates[tool_name] = ActionTemplate(
            name=tool_name,
            tool=tool_name,
            arg_constraints=arg_constraints,
            recipient_arg=recipient_arg,
            recipient_scope=recipient_scope,
            max_effect_class=spec.get("max_effect_class", EffectClass.IRREVERSIBLE),
        )
    return templates


def author_task_gate(monitor, suite_name: str, task_id: str, mediated_tools: Mapping[str, dict], caller_id: str):
    """Authors one Sluice gate for a single AgentDojo (suite, task) pair.
    Called once per task, before that task's episode(s) run, using only
    the task's own trusted ground_truth() -- never anything derived from
    the attack or from what the agent actually did at runtime."""
    from monitor import Direction, Symbol
    from actions import EffectClass

    templates = build_effectful_action_templates(mediated_tools)
    symbols = [Symbol(value=name, action=tmpl) for name, tmpl in templates.items()]
    gate_id = f"agentdojo-{suite_name}-{task_id}-effects"
    handle = monitor.author_gate(
        gate_id=gate_id,
        workflow_id=f"agentdojo-{suite_name}",
        protected_object=f"{suite_name}:{task_id}:effects",
        direction=Direction.ENDORSE,
        symbols=symbols,
        author_identity="planner",
        permitted_callers=frozenset({caller_id}),
        max_effect_class=EffectClass.IRREVERSIBLE,
        cap_bits=32.0,
    )
    return handle


class SluiceMediatedToolsExecutor:
    """Drop-in replacement for AgentDojo's ToolsExecutor pipeline element.
    Mediates only the tool names present in `mediated_tools` for the task
    currently set via `set_task`; every other tool call passes straight to
    `runtime.run_function`, unmediated, exactly as in the undefended
    baseline. This mirrors Sluice's own scoping: mediation constrains the
    consequential decision, not every function call.
    """

    def __init__(self, monitor, mediated_tools: Mapping[str, dict], caller_id: str = "agentdojo-planner"):
        from monitor import Outcome
        from agentdojo.agent_pipeline.llms.google_llm import EMPTY_FUNCTION_NAME
        from agentdojo.types import ChatToolResultMessage, text_content_block_from_string
        from agentdojo.agent_pipeline.tool_execution import tool_result_to_str, is_string_list
        from ast import literal_eval

        self._Outcome = Outcome
        self._EMPTY_FUNCTION_NAME = EMPTY_FUNCTION_NAME
        self._ChatToolResultMessage = ChatToolResultMessage
        self._text_content_block_from_string = text_content_block_from_string
        self.output_formatter = tool_result_to_str
        self._is_string_list = is_string_list
        self._literal_eval = literal_eval

        self.monitor = monitor
        self.mediated_tools = dict(mediated_tools)
        self.caller_id = caller_id
        self._current_gate_handle = None
        self._current_task_id = None
        self.mediation_log: list[MediationRecord] = []

    def set_task(self, gate_handle, task_id: str) -> None:
        self._current_gate_handle = gate_handle
        self._current_task_id = task_id

    def query(self, query, runtime, env, messages=(), extra_args=None):
        extra_args = {} if extra_args is None else extra_args
        if len(messages) == 0:
            return query, runtime, env, messages, extra_args
        if messages[-1]["role"] != "assistant":
            return query, runtime, env, messages, extra_args
        if messages[-1]["tool_calls"] is None or len(messages[-1]["tool_calls"]) == 0:
            return query, runtime, env, messages, extra_args

        tool_call_results = []
        for tool_call in messages[-1]["tool_calls"]:
            if tool_call.function == self._EMPTY_FUNCTION_NAME:
                tool_call_results.append(
                    self._ChatToolResultMessage(
                        role="tool",
                        content=[self._text_content_block_from_string("")],
                        tool_call_id=tool_call.id,
                        tool_call=tool_call,
                        error="Empty function name provided. Provide a valid function name.",
                    )
                )
                continue
            if tool_call.function not in (tool.name for tool in runtime.functions.values()):
                tool_call_results.append(
                    self._ChatToolResultMessage(
                        role="tool",
                        content=[self._text_content_block_from_string("")],
                        tool_call_id=tool_call.id,
                        tool_call=tool_call,
                        error=f"Invalid tool {tool_call.function} provided.",
                    )
                )
                continue

            for arg_k, arg_v in tool_call.args.items():
                if isinstance(arg_v, str) and self._is_string_list(arg_v):
                    tool_call.args[arg_k] = self._literal_eval(arg_v)

            if tool_call.function in self.mediated_tools:
                if self._current_gate_handle is None:
                    raise RuntimeError("SluiceMediatedToolsExecutor.query called before set_task()")
                str_args = {k: str(v) for k, v in tool_call.args.items()}
                observation = self.monitor.invoke(
                    self._current_gate_handle, tool_call.function, self.caller_id, args=str_args
                )
                self.mediation_log.append(
                    MediationRecord(
                        task_id=self._current_task_id,
                        tool=tool_call.function,
                        args=dict(tool_call.args),
                        outcome=observation.outcome.value,
                        charged_bits=observation.charged_bits,
                        denied=observation.outcome != self._Outcome.OK,
                    )
                )
                if observation.outcome != self._Outcome.OK:
                    tool_call_results.append(
                        self._ChatToolResultMessage(
                            role="tool",
                            content=[self._text_content_block_from_string("")],
                            tool_call_id=tool_call.id,
                            tool_call=tool_call,
                            error=f"Action denied by mediation layer: {observation.outcome.value}",
                        )
                    )
                    continue
                # Redeem the one-time capability; do not execute on the
                # strength of the LLM's tool call alone.
                self.monitor.consume_action_capability(observation)

            tool_call_result, error = runtime.run_function(env, tool_call.function, tool_call.args)
            tool_call_id = tool_call.id
            formatted_tool_call_result = self.output_formatter(tool_call_result)
            tool_call_results.append(
                self._ChatToolResultMessage(
                    role="tool",
                    content=[self._text_content_block_from_string(formatted_tool_call_result)],
                    tool_call_id=tool_call_id,
                    tool_call=tool_call,
                    error=error,
                )
            )
        return query, runtime, env, [*messages, *tool_call_results], extra_args
