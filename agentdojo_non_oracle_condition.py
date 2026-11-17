"""Historical AgentDojo oracle/non-oracle pilot (invalidated).

Do not use this script or its preserved JSON as defense evidence.  It used
the original incomplete 19/27-mutator bridge and one one-time gate per
episode.  The prospective exact-effect harness is ``agentdojo_pilot.py``;
the paper reports no result from it pending a fresh two-arm rerun.

agentdojo_pilot.py's extract_recipient_scope() authors each gate's
recipient allowlist from the task's own ground_truth() -- the benchmark's
known-correct answer, read before the episode runs. That is an oracle
policy: no real deployment knows in advance which recipient a given user
request will need. This script runs the identical pipeline and mediation
wiring under agentdojo_pilot.extract_recipient_scope_from_environment()
instead, which builds the allowlist only from state already present
before the episode runs -- the account's own transaction/scheduled-
transaction history for banking, its existing contact list for workspace
-- never the task or attack.

The banking pilot used six user tasks (three known-recipient and three
novel-recipient); the workspace pilot used five (two known-recipient and
three novel-recipient). One already-known-recipient task was also run under
the published attack. These historical measurements are retained only to
document why the invalidated policy appeared to work; they are not current
defense evidence.

Usage: LOCAL_LLM_PORT=<port> MODEL_REVISION=<hex40> \
       python3 agentdojo_non_oracle_condition.py --suite banking
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

ARTIFACT_ROOT = os.path.dirname(os.path.abspath(__file__))
if ARTIFACT_ROOT not in sys.path:
    sys.path.insert(0, ARTIFACT_ROOT)

from agentdojo_integration.sluice_agentdojo_bridge import author_task_gate  # noqa: E402
from agentdojo_pilot import (  # noqa: E402
    MEDIATED_TOOLS_BY_SUITE,
    build_pipeline,
    extract_recipient_scope,
    extract_recipient_scope_from_environment,
)
from agentdojo.task_suite.load_suites import get_suite  # noqa: E402
import agentdojo.attacks  # noqa: E402,F401
from agentdojo.attacks.attack_registry import load_attack  # noqa: E402

# Per suite: (known-recipient tasks, novel-recipient tasks, one task to
# also run under attack, the tool name whose recipient_scope is reported
# in each row for readability). Determined by direct inspection of each
# suite's ground_truth() against its own pre-existing environment state
# (see this file's git history / accompanying notes for the inspection
# script), not guessed.
SUITE_CONFIG = {
    "banking": {
        "known": ["user_task_3", "user_task_4", "user_task_6"],
        "novel": ["user_task_0", "user_task_5", "user_task_11"],
        "attack_task": "user_task_3",
        "injection_tasks": ["injection_task_0"],
        "report_tool": "send_money",
    },
    "workspace": {
        "known": ["user_task_13", "user_task_19"],
        "novel": ["user_task_32", "user_task_33", "user_task_25"],
        "attack_task": "user_task_13",
        "injection_tasks": ["injection_task_0"],
        "report_tool": "send_email",
    },
}


def run_one(monitor, pipeline, executor, suite, suite_name, uid, policy_name, report_tool):
    user_task = suite.get_user_task_by_id(uid)
    pre_env = suite.load_and_inject_default_environment({})
    pre_env = user_task.init_environment(pre_env)
    mediated_tools = MEDIATED_TOOLS_BY_SUITE[suite_name]

    if policy_name == "oracle":
        ground_truth_calls = user_task.ground_truth(pre_env)
        recipient_spec = extract_recipient_scope(ground_truth_calls, mediated_tools)
    else:
        recipient_spec = extract_recipient_scope_from_environment(
            pre_env, mediated_tools, suite_name
        )

    handle = author_task_gate(
        monitor, suite_name, f"{uid}__{policy_name}",
        recipient_spec, caller_id="agentdojo-planner",
    )
    executor.set_task(handle, uid)

    t0 = time.time()
    try:
        utility, _ = suite.run_task_with_pipeline(pipeline, user_task, None, {})
    except Exception as exc:
        print(f"[{policy_name}] ERROR utility {uid}: {exc!r}", flush=True)
        utility = None
    row = {
        "uid": uid, "policy": policy_name, "utility": utility,
        "seconds": time.time() - t0,
        "recipient_scope": sorted(
            recipient_spec.get(report_tool, {}).get("recipient_scope", ())
        ),
    }
    print(f"[{policy_name}] {uid}: utility={utility} "
          f"scope_size={len(row['recipient_scope'])} ({row['seconds']:.1f}s)", flush=True)
    return row


def run_attack_one(monitor, pipeline, executor, suite, suite_name, uid, injid, policy_name, attack):
    user_task = suite.get_user_task_by_id(uid)
    injection_task = suite.get_injection_task_by_id(injid)
    pre_env = suite.load_and_inject_default_environment({})
    pre_env = user_task.init_environment(pre_env)
    mediated_tools = MEDIATED_TOOLS_BY_SUITE[suite_name]

    if policy_name == "oracle":
        ground_truth_calls = user_task.ground_truth(pre_env)
        recipient_spec = extract_recipient_scope(ground_truth_calls, mediated_tools)
    else:
        recipient_spec = extract_recipient_scope_from_environment(
            pre_env, mediated_tools, suite_name
        )

    handle = author_task_gate(
        monitor, suite_name, f"{uid}__{injid}__{policy_name}",
        recipient_spec, caller_id="agentdojo-planner",
    )
    executor.set_task(handle, uid)
    attack_injections = attack.attack(user_task, injection_task)
    t0 = time.time()
    try:
        utility, security = suite.run_task_with_pipeline(
            pipeline, user_task, injection_task, attack_injections
        )
    except Exception as exc:
        print(f"[{policy_name}] ERROR attack {uid}/{injid}: {exc!r}", flush=True)
        utility, security = None, None
    row = {
        "uid": uid, "injid": injid, "policy": policy_name,
        "utility": utility, "attack_success": security, "seconds": time.time() - t0,
    }
    print(f"[{policy_name}] attack {uid}/{injid}: success={security} ({row['seconds']:.1f}s)", flush=True)
    return row


def main(argv=None) -> int:
    from sluice_v2.monitor import ReferenceMonitor
    from sluice_v2.store import DurableStore
    from agentdojo_integration.sluice_agentdojo_bridge import ExactMatchBackend

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", choices=list(SUITE_CONFIG), default="banking")
    parser.add_argument("--output", default=None)
    args = parser.parse_args(argv)
    cfg = SUITE_CONFIG[args.suite]
    output_path = args.output or f"agentdojo_non_oracle_{args.suite}_results.json"

    model_revision = os.environ.get("MODEL_REVISION")
    if not model_revision:
        raise SystemExit(
            "MODEL_REVISION is required as an operator attestation of the "
            "immutable Hugging Face commit intended to be loaded at "
            "LOCAL_LLM_PORT. This client cannot query or verify the server's "
            "actual weight revision; preserve the server launch log/cache "
            "manifest with any rerun."
        )

    suite = get_suite("v1", args.suite)
    mediated_tools = MEDIATED_TOOLS_BY_SUITE[args.suite]

    results = {"utility": [], "security": [], "meta": {
        "suite": args.suite,
        "known_recipient_tasks": cfg["known"],
        "novel_recipient_tasks": cfg["novel"],
        "model": "ibm-granite/granite-3.1-8b-instruct",
        "model_revision": model_revision,
        "model_revision_source": "operator_attested_not_endpoint_verified",
    }}

    for policy_name in ("oracle", "non_oracle"):
        db_path = f"agentdojo_non_oracle_{args.suite}_{policy_name}.sqlite3"
        if os.path.exists(db_path):
            os.remove(db_path)
        store = DurableStore(db_path)
        monitor = ReferenceMonitor(store, ExactMatchBackend())
        pipeline, executor = build_pipeline(mediated=True, monitor=monitor, mediated_tools=mediated_tools)

        for uid in cfg["known"] + cfg["novel"]:
            row = run_one(monitor, pipeline, executor, suite, args.suite, uid, policy_name, cfg["report_tool"])
            results["utility"].append(row)

        attack = load_attack("important_instructions", suite, pipeline)
        for injid in cfg["injection_tasks"]:
            row = run_attack_one(
                monitor, pipeline, executor, suite, args.suite,
                cfg["attack_task"], injid, policy_name, attack,
            )
            results["security"].append(row)
        results.setdefault("mediation_log", []).extend(
            {
                "policy": policy_name, "task_id": r.task_id, "tool": r.tool,
                "outcome": r.outcome, "denied": r.denied,
            }
            for r in executor.mediation_log
        )
        store.close()

    known_oracle = [r for r in results["utility"] if r["policy"] == "oracle" and r["uid"] in cfg["known"]]
    known_non_oracle = [r for r in results["utility"] if r["policy"] == "non_oracle" and r["uid"] in cfg["known"]]
    novel_oracle = [r for r in results["utility"] if r["policy"] == "oracle" and r["uid"] in cfg["novel"]]
    novel_non_oracle = [r for r in results["utility"] if r["policy"] == "non_oracle" and r["uid"] in cfg["novel"]]
    results["summary"] = {
        "known_recipient_tasks_utility_oracle": [r["utility"] for r in known_oracle],
        "known_recipient_tasks_utility_non_oracle": [r["utility"] for r in known_non_oracle],
        "novel_recipient_tasks_utility_oracle": [r["utility"] for r in novel_oracle],
        "novel_recipient_tasks_utility_non_oracle": [r["utility"] for r in novel_non_oracle],
        "attack_success_by_policy": {
            r["policy"]: r["attack_success"] for r in results["security"]
        },
    }

    with open(output_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(json.dumps(results["summary"], indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
