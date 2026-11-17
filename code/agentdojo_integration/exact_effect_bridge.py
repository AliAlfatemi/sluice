"""Prospective, fail-closed AgentDojo bridge.

The original RQ6 pilot used one one-time gate for an entire episode and
classified only 19 of AgentDojo v1's 27 mutating tools.  Its measurements
are therefore invalid as defense evidence.  This module is the corrected
bridge for a future rerun; the paper does not report results from it.

Each exact mutating call in the trusted task ground truth receives its own
single-use Sluice gate.  All arguments are canonicalized and bound exactly.
An effectful call with no unused exact template is denied.  Before executing
any tool, the bridge also checks that the runtime registry is exactly the
declared read-only/effectful partition, so a newly added mutator cannot fall
through unmediated.

The trusted effects form an unordered multiset: repeated identical calls each
need a distinct grant, but independent effects may be executed in either
order.  This is an authorization policy, not a ground-truth trace checker.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from typing import Mapping, Sequence


class ExactMatchBackend:
    """Return only an exact member of the committed symbol alphabet."""

    _MISS = "\x00__SLUICE_UNMATCHED__\x00"

    def decode(self, untrusted_content: str, symbol_values: Sequence[str]) -> str:
        return untrusted_content if untrusted_content in symbol_values else self._MISS


def _typed_value(value):
    """Return an injective, JSON-serializable representation of a tool value.

    AgentDojo's declared argument domain is JSON-like.  Explicit type tags
    prevent values such as ``1`` and ``"1"`` (or ``["x"]`` and the string
    containing that JSON text) from authorizing one another.  Unsupported
    objects and non-finite floats fail closed instead of being stringified.
    """

    if value is None:
        return ["null"]
    if isinstance(value, bool):
        return ["bool", value]
    if isinstance(value, int):
        return ["int", str(value)]
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("tool arguments may not contain non-finite floats")
        return ["float", value.hex()]
    if isinstance(value, str):
        return ["str", value]
    if isinstance(value, list):
        return ["list", [_typed_value(item) for item in value]]
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise TypeError("tool argument object keys must be strings")
        return [
            "object",
            [[key, _typed_value(value[key])] for key in sorted(value)],
        ]
    raise TypeError(f"unsupported tool argument type: {type(value).__name__}")


def canonicalize_value(value) -> str:
    """Injective canonical string shared by trusted and runtime calls."""

    return json.dumps(
        _typed_value(value),
        separators=(",", ":"),
        ensure_ascii=False,
    )


def canonicalize_args(args: Mapping) -> dict[str, str]:
    if not isinstance(args, Mapping):
        raise TypeError("tool arguments must be a mapping")
    if not all(isinstance(key, str) for key in args):
        raise TypeError("tool argument names must be strings")
    return {
        key: canonicalize_value(value)
        for key, value in sorted(args.items())
    }


@dataclass(frozen=True)
class AuthorizedEffect:
    episode_id: str
    template_id: str
    gate_id: str
    tool: str
    canonical_args: tuple[tuple[str, str], ...]
    handle: object


@dataclass(frozen=True)
class MediationRecord:
    episode_id: str
    template_id: str | None
    gate_id: str | None
    tool: str
    args: dict[str, str]
    outcome: str
    charged_bits: float
    denied: bool


def author_exact_effects(
    monitor,
    *,
    suite_name: str,
    episode_id: str,
    ground_truth_calls,
    effectful_tools: frozenset[str],
    read_only_tools: frozenset[str],
    caller_id: str,
    author_identity: str = "planner",
) -> list[AuthorizedEffect]:
    """Author one exact, single-use gate for every trusted mutating call."""

    from sluice_v2.actions import ActionTemplate, ArgConstraint, EffectClass
    from sluice_v2.monitor import Direction, Symbol

    grants: list[AuthorizedEffect] = []
    effect_index = 0
    for call in ground_truth_calls:
        if call.function not in effectful_tools | read_only_tools:
            raise ValueError(f"unclassified ground-truth tool: {call.function!r}")
        if call.function not in effectful_tools:
            continue
        args = canonicalize_args(call.args)
        template_id = f"effect-{effect_index}"
        gate_id = f"agentdojo-{suite_name}-{episode_id}-{template_id}"
        action = ActionTemplate(
            name=template_id,
            tool=call.function,
            arg_constraints={
                key: ArgConstraint(allowed_values=frozenset({value}))
                for key, value in args.items()
            },
            max_effect_class=EffectClass.IRREVERSIBLE,
        )
        handle = monitor.author_gate(
            gate_id=gate_id,
            workflow_id=f"agentdojo-{suite_name}",
            protected_object=f"{suite_name}:{episode_id}:{template_id}",
            direction=Direction.ENDORSE,
            symbols=[Symbol(value=call.function, action=action)],
            author_identity=author_identity,
            permitted_callers=frozenset({caller_id}),
            max_effect_class=EffectClass.IRREVERSIBLE,
            cap_bits=32.0,
        )
        grants.append(
            AuthorizedEffect(
                episode_id=episode_id,
                template_id=template_id,
                gate_id=gate_id,
                tool=call.function,
                canonical_args=tuple(sorted(args.items())),
                handle=handle,
            )
        )
        effect_index += 1
    return grants


class SluiceExactEffectExecutor:
    """AgentDojo tool executor with an exhaustive fail-closed partition."""

    def __init__(
        self,
        monitor,
        *,
        suite_name: str,
        effectful_tools: frozenset[str],
        read_only_tools: frozenset[str],
        caller_id: str = "agentdojo-planner",
    ) -> None:
        from ast import literal_eval

        from agentdojo.agent_pipeline.llms.google_llm import EMPTY_FUNCTION_NAME
        from agentdojo.agent_pipeline.tool_execution import is_string_list, tool_result_to_str
        from agentdojo.functions_runtime import FunctionCall
        from agentdojo.types import ChatToolResultMessage, text_content_block_from_string
        from sluice_v2.monitor import Outcome

        if effectful_tools & read_only_tools:
            raise ValueError("tool classification overlaps")
        self._Outcome = Outcome
        self._FunctionCall = FunctionCall
        self._EMPTY_FUNCTION_NAME = EMPTY_FUNCTION_NAME
        self._ChatToolResultMessage = ChatToolResultMessage
        self._text_content_block_from_string = text_content_block_from_string
        self._is_string_list = is_string_list
        self._literal_eval = literal_eval
        self.output_formatter = tool_result_to_str

        self.monitor = monitor
        self.suite_name = suite_name
        self.effectful_tools = frozenset(effectful_tools)
        self.read_only_tools = frozenset(read_only_tools)
        self.declared_tools = self.effectful_tools | self.read_only_tools
        self.caller_id = caller_id
        self._episode_id: str | None = None
        self._unused_effects: list[AuthorizedEffect] = []
        self.mediation_log: list[MediationRecord] = []

    def _contains_nested_call(self, value) -> bool:
        """Reject runtime-recursive calls before AgentDojo can dispatch them."""

        if isinstance(value, self._FunctionCall):
            return True
        if isinstance(value, Mapping):
            return any(self._contains_nested_call(item) for item in value.values())
        if isinstance(value, (list, tuple)):
            return any(self._contains_nested_call(item) for item in value)
        return False

    def set_episode(self, episode_id: str, effects: Sequence[AuthorizedEffect]) -> None:
        if any(effect.episode_id != episode_id for effect in effects):
            raise ValueError("authorized effect belongs to another episode")
        self._episode_id = episode_id
        self._unused_effects = list(effects)

    @property
    def unused_effect_count(self) -> int:
        return len(self._unused_effects)

    def _tool_error(self, tool_call, message: str):
        return self._ChatToolResultMessage(
            role="tool",
            content=[self._text_content_block_from_string("")],
            tool_call_id=tool_call.id,
            tool_call=tool_call,
            error=message,
        )

    def _check_registry(self, runtime) -> set[str]:
        runtime_tools = {tool.name for tool in runtime.functions.values()}
        unclassified = runtime_tools - self.declared_tools
        missing = self.declared_tools - runtime_tools
        if unclassified or missing:
            raise RuntimeError(
                "AgentDojo tool registry/classification mismatch: "
                f"unclassified={sorted(unclassified)!r}, missing={sorted(missing)!r}"
            )
        return runtime_tools

    def query(self, query, runtime, env, messages=(), extra_args=None):
        extra_args = {} if extra_args is None else extra_args
        runtime_tools = self._check_registry(runtime)
        if not messages or messages[-1]["role"] != "assistant":
            return query, runtime, env, messages, extra_args
        calls = messages[-1]["tool_calls"]
        if not calls:
            return query, runtime, env, messages, extra_args
        if self._episode_id is None:
            raise RuntimeError("set_episode() must be called before tool execution")

        results = []
        for tool_call in calls:
            if tool_call.function == self._EMPTY_FUNCTION_NAME:
                results.append(self._tool_error(tool_call, "Empty function name provided."))
                continue
            if tool_call.function not in runtime_tools:
                results.append(self._tool_error(tool_call, f"Invalid tool {tool_call.function} provided."))
                continue

            for key, value in tool_call.args.items():
                if isinstance(value, str) and self._is_string_list(value):
                    tool_call.args[key] = self._literal_eval(value)

            # FunctionsRuntime recursively executes FunctionCall-valued
            # arguments.  Reject every such value, even below read-only outer
            # calls, so nested mutations cannot bypass this executor.
            if self._contains_nested_call(tool_call.args):
                results.append(
                    self._tool_error(tool_call, "Nested function calls are not authorized.")
                )
                continue

            if tool_call.function in self.effectful_tools:
                canonical_args = canonicalize_args(tool_call.args)
                wanted = (tool_call.function, tuple(sorted(canonical_args.items())))
                match_index = next(
                    (
                        index
                        for index, effect in enumerate(self._unused_effects)
                        if (effect.tool, effect.canonical_args) == wanted
                    ),
                    None,
                )
                if match_index is None:
                    self.mediation_log.append(
                        MediationRecord(
                            episode_id=self._episode_id,
                            template_id=None,
                            gate_id=None,
                            tool=tool_call.function,
                            args=canonical_args,
                            outcome="UNAUTHORIZED_EFFECT",
                            charged_bits=0.0,
                            denied=True,
                        )
                    )
                    results.append(
                        self._tool_error(tool_call, "Action denied: no unused exact authorized effect.")
                    )
                    continue

                effect = self._unused_effects.pop(match_index)
                observation = self.monitor.invoke(
                    effect.handle,
                    tool_call.function,
                    self.caller_id,
                    args=canonical_args,
                )
                denied = observation.outcome != self._Outcome.OK
                self.mediation_log.append(
                    MediationRecord(
                        episode_id=self._episode_id,
                        template_id=effect.template_id,
                        gate_id=effect.gate_id,
                        tool=tool_call.function,
                        args=canonical_args,
                        outcome=observation.outcome.value,
                        charged_bits=observation.charged_bits,
                        denied=denied,
                    )
                )
                if denied:
                    results.append(
                        self._tool_error(
                            tool_call,
                            f"Action denied by Sluice: {observation.outcome.value}",
                        )
                    )
                    continue
                self.monitor.consume_action_capability(observation)

            tool_result, error = runtime.run_function(env, tool_call.function, tool_call.args)
            results.append(
                self._ChatToolResultMessage(
                    role="tool",
                    content=[
                        self._text_content_block_from_string(
                            self.output_formatter(tool_result)
                        )
                    ],
                    tool_call_id=tool_call.id,
                    tool_call=tool_call,
                    error=error,
                )
            )
        return query, runtime, env, [*messages, *results], extra_args
