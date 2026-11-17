"""Re-run only the attack trial for the CaMeL baseline, reusing the
already-completed utility results on disk (which took a long time and
do not need re-running)."""
import json
import os
import sys
import time
import traceback

os.environ.setdefault("SLUICE_LOCAL_BASE_URL", "http://localhost:8101/v1")

import agentdojo.task_suite.load_suites  # noqa: E402
import agentdojo.attacks  # noqa: E402,F401
from agentdojo.attacks.attack_registry import load_attack  # noqa: E402
from agentdojo.task_suite import get_suite  # noqa: E402

import camel.custom_yaml  # noqa: E402
from camel.models import make_tools_pipeline  # noqa: E402
from camel.interpreter.interpreter import MetadataEvalMode  # noqa: E402

MODEL = "local:ibm-granite/granite-3.1-8b-instruct"
ATTACK_TASK = "user_task_3"
INJECTION_TASK = "injection_task_0"


def build_pipeline(suite):
    pipeline = make_tools_pipeline(
        MODEL, use_original=False, replay_with_policies=False,
        attack_name="important_instructions", reasoning_effort="medium",
        thinking_budget_tokens=None, suite="banking", ad_defense=None,
        eval_mode=MetadataEvalMode.NORMAL, q_llm=None,
    )
    pipeline.name = f"{pipeline.name}-vllm_parsed"
    return pipeline


def main():
    with open("camel_baseline_results.json") as f:
        results = json.load(f)

    suite = get_suite("v1", "banking")
    pipeline = build_pipeline(suite)
    attack = load_attack("important_instructions", suite, pipeline)
    user_task = suite.get_user_task_by_id(ATTACK_TASK)
    injection_task = suite.get_injection_task_by_id(INJECTION_TASK)
    attack_injections = attack.attack(user_task, injection_task)
    t0 = time.time()
    try:
        utility_i, security_i = suite.run_task_with_pipeline(
            pipeline, user_task, injection_task, attack_injections
        )
    except Exception as exc:
        print(f"ERROR attack {ATTACK_TASK}/{INJECTION_TASK}: {exc!r}", flush=True)
        traceback.print_exc()
        utility_i, security_i = None, None
    elapsed = time.time() - t0
    results["security"][f"{ATTACK_TASK}__{INJECTION_TASK}"] = {
        "utility": utility_i, "attack_success": security_i, "seconds": elapsed,
    }
    print(f"[camel] attack {ATTACK_TASK}/{INJECTION_TASK}: success={security_i} ({elapsed:.1f}s)", flush=True)

    with open("camel_baseline_results.json", "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(json.dumps(results, indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
