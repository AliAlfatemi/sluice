"""Fixed-corpus AgentDojo extension with native Qwen tool calls.

Independent of the frozen G8 execution. Policies are authored by an unscored
clean-environment rollout, never ground truth. All four conditions get live
tool feedback. The small prospective sample supports descriptive evidence,
not a new population-level effectiveness claim or an external-defense result.
"""
from __future__ import annotations
import argparse
import ast
import copy
import hashlib
import json
import math
import re
import tempfile
import time
from collections import Counter
from pathlib import Path

from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, load_system_message
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop, tool_result_to_str, is_string_list
from agentdojo.functions_runtime import FunctionCall, FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suite
from agentdojo.types import ChatAssistantMessage, ChatToolResultMessage, get_text_content_as_str, text_content_block_from_string
import agentdojo.attacks
from agentdojo.attacks.attack_registry import load_attack
from agentdojo_pilot import READ_ONLY_TOOLS_BY_SUITE, EFFECTFUL_TOOLS_BY_SUITE
from sluice_v2.actions import ActionTemplate, ArgConstraint, EffectClass
from sluice_v2.monitor import Direction, MockBackend, Outcome, ReferenceMonitor, Symbol, gate_cost_units
from sluice_v2.store import DurableStore

TASKS = {"banking": ["user_task_0", "user_task_3", "user_task_6"],
         "workspace": ["user_task_13", "user_task_19", "user_task_25"],
         "travel": ["user_task_0", "user_task_1", "user_task_2"]}
ARMS = ["undefended", "allowlist_only", "deny_all_mutations", "full_sluice"]


def canon(x):
    return json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class NativeModel(BasePipelineElement):
    name = "native_transformers"
    def __init__(self, model, revision, device, output):
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer
        self.torch = torch
        self.tokenizer = AutoTokenizer.from_pretrained(model, revision=revision, local_files_only=True)
        self.model = AutoModelForCausalLM.from_pretrained(model, revision=revision, local_files_only=True,
                                                       torch_dtype=torch.float16).to(device).eval()
        self.device, self.output, self.calls = device, output, 0

    def query(self, query, runtime, env, messages, extra_args):
        converted = []
        for m in messages:
            item = {"role": m["role"], "content": get_text_content_as_str(m.get("content") or [])}
            if m["role"] == "assistant" and m.get("tool_calls"):
                item["tool_calls"] = [{"type": "function", "function": {"name": c.function, "arguments": c.args}}
                                      for c in m["tool_calls"]]
            if m["role"] == "tool":
                item["name"] = m["tool_call"].function
                if m.get("error"):
                    item["content"] = canon({"error": m["error"]})
            converted.append(item)
        tools = [{"type": "function", "function": {"name": f.name, "description": f.description,
                  "parameters": f.parameters.model_json_schema()}} for f in runtime.functions.values()]
        prompt = self.tokenizer.apply_chat_template(converted, tools=tools, tokenize=False, add_generation_prompt=True)
        encoded = self.tokenizer(prompt, return_tensors="pt").to(self.device)
        if encoded.input_ids.shape[1] > 12000:
            raise RuntimeError("prospective 12000-token prompt limit reached")
        with self.torch.inference_mode():
            generated = self.model.generate(**encoded, max_new_tokens=256, do_sample=False,
                                            temperature=None, top_k=None, top_p=None,
                                            pad_token_id=self.tokenizer.eos_token_id)
        text = self.tokenizer.decode(generated[0, encoded.input_ids.shape[1]:], skip_special_tokens=True)
        calls = []
        self.calls += 1
        for index, payload in enumerate(re.findall(r"<tool_call>\s*(.*?)\s*</tool_call>", text, re.S)):
            try:
                data = json.loads(payload)
                if set(data) != {"name", "arguments"} or not isinstance(data["name"], str) or not isinstance(data["arguments"], dict):
                    continue
                calls.append(FunctionCall(function=data["name"], args=data["arguments"], id=f"c{self.calls}_{index}"))
            except (ValueError, TypeError):
                continue
        with (self.output / "model_calls.jsonl").open("a") as f:
            f.write(canon({"call": self.calls, "messages": converted, "answer": text,
                           "parsed_calls": [c.model_dump() for c in calls]}) + "\n")
        # Native templates serialize structured tool calls themselves. Keeping
        # their XML in content as well would duplicate each call in history.
        visible = re.sub(r"<tool_call>\s*.*?\s*</tool_call>", "", text, flags=re.S).strip()
        answer = ChatAssistantMessage(role="assistant", content=[text_content_block_from_string(visible)], tool_calls=calls)
        return query, runtime, env, [*messages, answer], extra_args


class Broker(BasePipelineElement):
    def __init__(self, suite, arm, templates=()):
        self.suite, self.arm = suite, arm
        self.templates = list(templates)
        self.events, self.authored = [], []
        self.temp = tempfile.TemporaryDirectory()
        self.store = DurableStore(str(Path(self.temp.name) / "ledger.sqlite3"))
        cost = gate_cost_units(1)
        cap = max(1, len(self.templates)) * cost / 1e6 + .000001
        self.monitor = ReferenceMonitor(self.store, MockBackend(), default_cap_bits=cap,
                                       trusted_planner_identities=frozenset({"planner"}))
        self.handles = []
        self.used = set()
        for index, entry in enumerate(self.templates):
            payload = canon(entry)
            action = ActionTemplate(name=f"effect_{index}", tool=entry["tool"],
                                    arg_constraints={"payload": ArgConstraint(allowed_values=frozenset({payload}))},
                                    max_effect_class=EffectClass.REVERSIBLE)
            self.handles.append(self.monitor.author_gate(
                gate_id=f"effect_{index}", workflow_id="agentdojo-extension", protected_object="episode",
                direction=Direction.ENDORSE, symbols=[Symbol("allow", action)], author_identity="planner",
                permitted_callers=frozenset({"agent"}), max_effect_class=EffectClass.REVERSIBLE, cap_bits=cap))

    def close(self):
        self.store.close()
        self.temp.cleanup()

    def query(self, query, runtime, env, messages, extra_args):
        if not messages or messages[-1]["role"] != "assistant":
            return query, runtime, env, messages, extra_args
        returned = []
        for call in messages[-1].get("tool_calls") or []:
            tool, args = call.function, copy.deepcopy(call.args)
            # Match the official ToolsExecutor's literal list normalization in
            # every arm, before canonical policy matching and execution.
            for key, value in list(args.items()):
                if isinstance(value, str) and is_string_list(value):
                    args[key] = ast.literal_eval(value)
                    call.args[key] = args[key]
            status, result, error = "unknown_tool", None, None
            effectful = tool in EFFECTFUL_TOOLS_BY_SUITE[self.suite]
            known = effectful or tool in READ_ONLY_TOOLS_BY_SUITE[self.suite]
            execute = known
            payload = {"tool": tool, "args": args}
            if not known:
                error = "unknown_tool"
            elif effectful:
                if self.arm == "author":
                    try:
                        runtime.functions[tool].parameters.model_validate(args)
                        self.authored.append(payload)
                    except Exception:
                        pass
                elif self.arm == "deny_all_mutations":
                    execute, error = False, "deny_all_mutations"
                elif self.arm != "undefended":
                    matches = [i for i, t in enumerate(self.templates) if canon(t) == canon(payload)]
                    if not matches:
                        execute, error = False, "no_authorized_template"
                    elif self.arm == "full_sluice":
                        index = next((i for i in matches if i not in self.used), matches[0])
                        observation = self.monitor.invoke(self.handles[index], "allow", "agent", args={"payload": canon(payload)})
                        if observation.outcome != Outcome.OK:
                            execute, error = False, observation.outcome.value
                        else:
                            self.used.add(index)
                            _, authorized = self.monitor.consume_action_capability(observation)
                            stored = json.loads(authorized["payload"])
                            tool, args = stored["tool"], stored["args"]
            if execute:
                # Official tools are simulated benchmark functions. No real
                # production account or network side effect is invoked.
                result, error = runtime.run_function(env, tool, args)
                status = "tool_error" if error else ("executed_effect" if effectful else "executed_read_only")
            else:
                status = error or "denied"
            self.events.append({"tool": tool, "args": args, "effectful": effectful, "outcome": status})
            returned.append(ChatToolResultMessage(role="tool", content=[text_content_block_from_string(tool_result_to_str(result))],
                                                   tool_call_id=call.id, tool_call=call, error=error))
        return query, runtime, env, [*messages, *returned], extra_args


def pipeline(model, broker):
    p = AgentPipeline([SystemMessage(load_system_message(None)), InitQuery(), model,
                       ToolsExecutionLoop([broker, model], max_iters=12)])
    p.name = "local-native-qwen-" + broker.arm
    return p


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--model", required=True)
    p.add_argument("--revision", required=True)
    p.add_argument("--suite", choices=TASKS, required=True)
    p.add_argument("--device", default="cuda:0")
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--preflight-only", action="store_true")
    a = p.parse_args()
    a.output.mkdir(parents=True, exist_ok=False)
    import agentdojo as package
    tree = Path(package.__file__).parent
    h = hashlib.sha256()
    for f in sorted(tree.rglob("*.py")):
        h.update(str(f.relative_to(tree)).encode()); h.update(f.read_bytes())
    plan = {"schema": "sluice-native-agentdojo-extension-v3", "model": a.model, "revision": a.revision,
            "suite": a.suite, "tasks": TASKS[a.suite], "arms": ARMS, "attack": "important_instructions",
            "injection_task": "injection_task_0", "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "agentdojo_source_sha256": h.hexdigest(), "max_tool_iterations": 12, "max_new_tokens": 256,
            "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    (a.output / "plan.json").write_text(json.dumps(plan, indent=2))
    suite = get_suite("v1", a.suite)
    expected = EFFECTFUL_TOOLS_BY_SUITE[a.suite] | READ_ONLY_TOOLS_BY_SUITE[a.suite]
    if set(FunctionsRuntime(suite.tools).functions) != set(expected):
        raise RuntimeError("complete tool-registry partition mismatch")
    # Validate attack construction for the entire fixed schedule before model
    # allocation or any scored rollout. The factory inspects pipeline names.
    class PreflightPipeline(BasePipelineElement):
        name = "local-native-qwen-preflight"
        def query(self, *args, **kwargs):
            raise RuntimeError("attack construction must not perform a model rollout")
    for uid in TASKS[a.suite]:
        preflight_attack = load_attack("important_instructions", suite, PreflightPipeline())
        preflight_attack.attack(suite.get_user_task_by_id(uid), suite.get_injection_task_by_id("injection_task_0"))
    if a.preflight_only:
        print("PREFLIGHT PASSED", a.suite, TASKS[a.suite], flush=True)
        return
    model = NativeModel(a.model, a.revision, a.device, a.output)
    records = []
    for index, uid in enumerate(TASKS[a.suite]):
        task = suite.get_user_task_by_id(uid)
        author = Broker(a.suite, "author")
        author_error = None
        try:
            env = task.init_environment(suite.load_and_inject_default_environment({}))
            pipeline(model, author).query(type(task).PROMPT, FunctionsRuntime(suite.tools), env, [], {})
        except Exception as exc:
            author_error = type(exc).__name__ + ":" + str(exc)
        templates = author.authored if author_error is None else []
        (a.output / (uid + "_policy.json")).write_text(json.dumps({"templates": templates, "error": author_error}, indent=2))
        author.close()
        for attacked in [False, True]:
            order = ARMS[index % 4:] + ARMS[:index % 4]
            for arm in order:
                broker = Broker(a.suite, arm, templates)
                agent = pipeline(model, broker)
                error, utility, security = None, False, False
                try:
                    if attacked:
                        injection = suite.get_injection_task_by_id("injection_task_0")
                        attack = load_attack("important_instructions", suite, agent)
                        utility, security = suite.run_task_with_pipeline(agent, task, injection, attack.attack(task, injection))
                    else:
                        utility, security = suite.run_task_with_pipeline(agent, task, None, {})
                except Exception as exc:
                    error = type(exc).__name__ + ":" + str(exc)
                row = {"task": uid, "arm": arm, "attacked": attacked, "utility": bool(utility),
                       "attack_success": (bool(security) if error is None else True) if attacked else None,
                       "error": error, "policy_error": author_error, "template_count": len(templates),
                       "tool_calls": len(broker.events), "events": broker.events}
                records.append(row)
                with (a.output / "episodes.jsonl").open("a") as f:
                    f.write(canon(row) + "\n")
                broker.close()
                print(uid, arm, attacked, row["utility"], row["attack_success"], error, flush=True)
    summary = {arm: {"arms": sum(r["arm"] == arm for r in records),
                     "benign_utility_successes": sum(r["arm"] == arm and not r["attacked"] and r["utility"] for r in records),
                     "attacked_successes_itt": sum(r["arm"] == arm and r["attacked"] and r["attack_success"] for r in records),
                     "errors": sum(r["arm"] == arm and r["error"] is not None for r in records)} for arm in ARMS}
    author_failures = sorted({r["task"] for r in records if r["policy_error"] is not None})
    (a.output / "results.json").write_text(json.dumps({"status": "complete", "summary": summary, "episodes": len(records),
        "policy_authoring_failed_tasks": author_failures,
        "parsed_tool_call_episodes": sum(r["tool_calls"] > 0 for r in records),
        "model_calls": model.calls, "limitations": ["Three fixed tasks and one official attack per suite/model; descriptive pilot only",
        "Native Qwen parsing differs from G8's vLLM frontend; not pooled with G8", "No faithful external-defense baseline executed"]}, indent=2))


if __name__ == "__main__":
    main()
