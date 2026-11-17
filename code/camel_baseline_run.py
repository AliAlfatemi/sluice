"""Historical CaMeL compatibility smoke driver.

This executed six selected AgentDojo v1 banking utility tasks and one attack
pair through a local granite endpoint. Only four utility tasks completed, and
the attack pair was not vulnerable in the shared undefended arm. It therefore
does not support a relative security or utility claim. The result is retained
only to document that the endpoint adapter exercised a subset of CaMeL's
pipeline; a security-discriminating comparison requires a fresh shared
vulnerable-pair matrix.
"""
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
MODEL_REVISION = "4009206d5fc95d2e65a7b7633e159d6e97e25d35"
# Same tasks as agentdojo_non_oracle_condition.py's banking config.
UTILITY_TASKS = ["user_task_3", "user_task_4", "user_task_6", "user_task_0", "user_task_5", "user_task_11"]
ATTACK_TASK = "user_task_3"
INJECTION_TASK = "injection_task_0"


def build_pipeline(suite):
    return make_tools_pipeline(
        MODEL, use_original=False, replay_with_policies=False,
        attack_name="important_instructions", reasoning_effort="medium",
        thinking_budget_tokens=None, suite="banking", ad_defense=None,
        eval_mode=MetadataEvalMode.NORMAL, q_llm=None,
    )


def main():
    suite = get_suite("v1", "banking")
    results = {
        "schema_version": "sluice.camel_baseline.v1",
        "experiment_id": "camel_baseline_banking",
        "model": "ibm-granite/granite-3.1-8b-instruct",
        "model_revision": MODEL_REVISION,
        "model_revision_source": "operator_attested_not_endpoint_verified",
        "base_url": "<redacted-endpoint>",
        "note": (
            "CaMeL run through a Sluice-side adapter (patched "
            "camel/models.py + camel/pipeline_elements/privileged_llm.py) "
            "that redirects HTTP calls to a local vLLM endpoint; "
            "CaMeL's own interpreter/capability/security-policy logic is "
            "unmodified. Not an official CaMeL result -- CaMeL's own "
            "paper evaluates cloud frontier models, not this one. "
            "Compatibility smoke only: the single attack pair was not "
            "vulnerable undefended and two utility tasks hit context limits."
        ),
        "utility": {},
        "security": {},
    }

    for uid in UTILITY_TASKS:
        pipeline = build_pipeline(suite)
        user_task = suite.get_user_task_by_id(uid)
        t0 = time.time()
        try:
            utility, _ = suite.run_task_with_pipeline(pipeline, user_task, None, {})
        except Exception as exc:
            print(f"ERROR utility {uid}: {exc!r}", flush=True)
            traceback.print_exc()
            utility = None
        elapsed = time.time() - t0
        results["utility"][uid] = {"utility": utility, "seconds": elapsed}
        print(f"[camel] {uid}: utility={utility} ({elapsed:.1f}s)", flush=True)
        with open("camel_baseline_results.json", "w") as f:
            json.dump(results, f, indent=2, default=str)

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
    print(json.dumps({"utility": results["utility"], "security": results["security"]}, indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
