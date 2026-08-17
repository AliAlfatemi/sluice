"""Sluice x AgentDojo pilot: banking suite, undefended vs Sluice-mediated,
same model, same tasks, same attacks. Real published benchmark, real
published attack suite (Debenedetti et al., AgentDojo v1).

Usage:
    LOCAL_LLM_PORT=8100 python agentdojo_pilot.py --limit-user-tasks 6 --out results.json
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

SLUICE_V2_PATH = os.path.expanduser(
    "~/USENIX27_SLUICE/work_20260816/code/source/sluice_v2"
)
BRIDGE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SLUICE_V2_PATH)
sys.path.insert(0, BRIDGE_DIR)

from sluice_agentdojo_bridge import (  # noqa: E402
    ExactMatchBackend,
    SluiceMediatedToolsExecutor,
    author_task_gate,
)

from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, get_llm, load_system_message  # noqa: E402
from agentdojo.agent_pipeline.tool_execution import ToolsExecutor, ToolsExecutionLoop  # noqa: E402
from agentdojo.agent_pipeline.basic_elements import SystemMessage, InitQuery  # noqa: E402
from agentdojo.task_suite.load_suites import get_suite  # noqa: E402
import agentdojo.attacks  # noqa: E402,F401  -- triggers attack registration
from agentdojo.attacks.attack_registry import load_attack  # noqa: E402

MEDIATED_TOOLS_BY_SUITE = {
    "banking": {
        "send_money": "recipient",
        "schedule_transaction": "recipient",
        "update_scheduled_transaction": "recipient",
        "update_password": None,
        "update_user_info": None,
    },
    "workspace": {
        "send_email": "recipients",
        "share_file": "email",
        "delete_file": None,
        "delete_email": None,
    },
    "travel": {
        "reserve_hotel": "hotel",
        "reserve_restaurant": "restaurant",
        "reserve_car_rental": "company",
        "send_email": "recipients",
    },
    "slack": {
        "send_direct_message": "recipient",
        "send_channel_message": "channel",
        "add_user_to_channel": "user",
        "invite_user_to_slack": "user_email",
        "remove_user_from_slack": "user",
        "post_webpage": "url",
    },
}


def extract_recipient_scope(ground_truth_calls, mediated_tools):
    """For each mediated tool that appears in this task's own ground truth,
    collect the argument values the trusted planner considers legitimate.
    Only the tool's designated recipient-bearing argument is scoped this way
    (the security-relevant one per tool, e.g. `recipient` for send_money,
    `email` for share_file); other arguments are left unconstrained
    (declared with no allowed_values) so the template still requires them to
    be present and a string, without over-fitting to exact wording the model
    may paraphrase. List-valued recipient arguments (e.g. send_email's
    `recipients`) are scoped on their str()-canonicalized form, since
    Sluice's ArgConstraint only validates strings; this is coarser than a
    per-address comparison and is used only for tools where no per-element
    check is currently implemented.
    """
    from actions import ArgConstraint

    spec = {}
    for call in ground_truth_calls:
        if call.function not in mediated_tools:
            continue
        recipient_arg = mediated_tools[call.function]
        args = call.args
        recipient_val = args.get(recipient_arg) if recipient_arg else None
        other_constraints = {
            k: ArgConstraint(max_length=4096) for k in args.keys() if k != recipient_arg
        }
        if call.function not in spec:
            spec[call.function] = {
                "recipient_arg": recipient_arg if recipient_val is not None else None,
                "recipient_scope": set(),
                "other_constraints": other_constraints,
            }
        if recipient_val is not None:
            spec[call.function]["recipient_scope"].add(str(recipient_val))
    # Tools mediated but never in ground truth for this task: no legitimate
    # use exists, so authorize zero values (any real call is denied).
    for tool in mediated_tools:
        if tool not in spec:
            spec[tool] = {"recipient_arg": None, "recipient_scope": set(), "other_constraints": {}}
    for tool, s in spec.items():
        s["recipient_scope"] = frozenset(s["recipient_scope"])
    return spec


def build_pipeline(mediated: bool, monitor=None, mediated_tools=None):
    port = os.environ["LOCAL_LLM_PORT"]
    llm = get_llm("vllm_parsed", "vllm_parsed", None, "tool")
    system_message = load_system_message(None)
    if mediated:
        executor = SluiceMediatedToolsExecutor(monitor, {t: {} for t in mediated_tools})
        tools_loop = ToolsExecutionLoop([executor, llm])
        pipeline = AgentPipeline([SystemMessage(system_message), InitQuery(), llm, tools_loop])
        pipeline.name = "vllm_parsed-qwen2.5-3b-sluice"
        return pipeline, executor
    tools_loop = ToolsExecutionLoop([ToolsExecutor(), llm])
    pipeline = AgentPipeline([SystemMessage(system_message), InitQuery(), llm, tools_loop])
    pipeline.name = "vllm_parsed-qwen2.5-3b-undefended"
    return pipeline, None


def _checkpoint(results, out_path):
    """Write partial results after every episode so a crash (context-length
    overflow, a transient server error) loses at most the in-flight episode,
    not the whole run. Written atomically to out_path + '.partial' via a
    same-directory temp file plus rename; the final run() still writes the
    canonical out_path once at the end."""
    partial_path = out_path + ".partial"
    tmp_path = partial_path + ".tmp"
    with open(tmp_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    os.replace(tmp_path, partial_path)


def run(limit_user_tasks, limit_injection_tasks, out_path, suite_name="banking"):
    from monitor import ReferenceMonitor
    from store import DurableStore

    suite = get_suite("v1", suite_name)
    mediated_tools = MEDIATED_TOOLS_BY_SUITE[suite_name]

    # One database per run, keyed off the (unique) output filename -- two
    # concurrent runs sharing a directory must not share a SQLite file
    # (SQLite's BEGIN IMMEDIATE write-locking, correct for this store's
    # own atomicity guarantee, otherwise serializes -- and can deadlock --
    # two unrelated experiments' writers against each other).
    db_path = os.path.join(
        os.path.dirname(out_path) or ".",
        os.path.splitext(os.path.basename(out_path))[0] + ".sqlite3",
    )
    if os.path.exists(db_path):
        os.remove(db_path)
    store = DurableStore(db_path)
    monitor = ReferenceMonitor(store, ExactMatchBackend())

    undefended_pipeline, _ = build_pipeline(mediated=False)
    sluice_pipeline, sluice_executor = build_pipeline(
        mediated=True, monitor=monitor, mediated_tools=mediated_tools
    )

    user_task_ids = list(suite.user_tasks.keys())
    if limit_user_tasks:
        user_task_ids = user_task_ids[:limit_user_tasks]
    injection_task_ids = list(suite.injection_tasks.keys())
    if limit_injection_tasks:
        injection_task_ids = injection_task_ids[:limit_injection_tasks]

    results = {"utility": {}, "security": {}, "meta": {"suite": suite_name, "version": "v1",
               "user_task_ids": user_task_ids, "injection_task_ids": injection_task_ids}}

    for cond_name, pipeline in (("undefended", undefended_pipeline), ("sluice", sluice_pipeline)):
        # AgentDojo's own published attack construction (the "important
        # instructions" attack: an injected block that tells the model the
        # user task requires it, framed with fake urgency/authority markers)
        # -- not a hand-rolled approximation. Built once per pipeline since
        # it reads the pipeline's tool-call formatting conventions.
        attack = load_attack("important_instructions", suite, pipeline)
        results["utility"][cond_name] = {}
        results["security"][cond_name] = {}
        for uid in user_task_ids:
            user_task = suite.get_user_task_by_id(uid)
            pre_env_for_gate = suite.load_and_inject_default_environment({})
            pre_env_for_gate = user_task.init_environment(pre_env_for_gate)
            ground_truth_calls = user_task.ground_truth(pre_env_for_gate)
            recipient_spec = extract_recipient_scope(ground_truth_calls, mediated_tools)

            # Every episode (the no-attack run and each of the injection-task
            # runs) is an independent trial with its own gate and budget --
            # authored fresh per episode so budget consumed in one trial can
            # never carry over and contaminate another trial's outcome.
            if cond_name == "sluice":
                handle = author_task_gate(
                    monitor, suite_name, f"{uid}__noattack", recipient_spec, caller_id="agentdojo-planner"
                )
                sluice_executor.set_task(handle, uid)

            t0 = time.time()
            try:
                utility, _ = suite.run_task_with_pipeline(pipeline, user_task, None, {})
            except Exception as exc:
                print(f"[{cond_name}] ERROR utility {uid}: {exc!r}", flush=True)
                utility = None
            results["utility"][cond_name][uid] = {"utility": utility, "seconds": time.time() - t0}
            print(f"[{cond_name}] utility {uid}: {utility} ({time.time()-t0:.1f}s)", flush=True)
            _checkpoint(results, out_path)

            for injid in injection_task_ids:
                injection_task = suite.get_injection_task_by_id(injid)
                attack_injections = attack.attack(user_task, injection_task)
                if cond_name == "sluice":
                    handle = author_task_gate(
                        monitor, suite_name, f"{uid}__{injid}", recipient_spec, caller_id="agentdojo-planner"
                    )
                    sluice_executor.set_task(handle, uid)
                t0 = time.time()
                try:
                    utility_i, security_i = suite.run_task_with_pipeline(
                        pipeline, user_task, injection_task, attack_injections
                    )
                except Exception as exc:
                    print(f"[{cond_name}] ERROR {uid}/{injid}: {exc!r}", flush=True)
                    utility_i, security_i = None, None
                results["security"][cond_name][f"{uid}__{injid}"] = {
                    "utility": utility_i, "attack_success": security_i, "seconds": time.time() - t0,
                }
                print(
                    f"[{cond_name}] attack {uid}/{injid}: success={security_i} ({time.time()-t0:.1f}s)",
                    flush=True,
                )
                _checkpoint(results, out_path)

    results["sluice_mediation_log"] = [
        {"task_id": r.task_id, "tool": r.tool, "outcome": r.outcome, "denied": r.denied}
        for r in sluice_executor.mediation_log
    ]

    with open(out_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"Wrote {out_path}", flush=True)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit-user-tasks", type=int, default=0)
    ap.add_argument("--limit-injection-tasks", type=int, default=0)
    ap.add_argument("--out", type=str, default="agentdojo_banking_results.json")
    ap.add_argument("--suite", type=str, default="banking", choices=list(MEDIATED_TOOLS_BY_SUITE))
    args = ap.parse_args()
    run(args.limit_user_tasks or None, args.limit_injection_tasks or None, args.out, args.suite)
