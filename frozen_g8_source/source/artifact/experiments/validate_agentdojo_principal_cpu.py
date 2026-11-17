#!/usr/bin/env python3
"""Authenticate and summarize the data-only AgentDojo principal CPU plan."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True

from sluice_v2.evaluation.agentdojo_live import (
    OfficialRegistryAttestation,
    OfficialSourceAttestation,
)
from sluice_v2.evaluation.agentdojo_principal_construction import (
    build_principal_plan_wire,
)
from sluice_v2.evaluation.agentdojo_principal_driver import (
    PrincipalExecutionPlan,
)
from validate_agentdojo_v122 import (
    IMPORT_DEPENDENCIES as BASE_IMPORT_DEPENDENCIES,
    _disable_unused_provider_initializers,
)


IMPORT_DEPENDENCIES = {
    **BASE_IMPORT_DEPENDENCIES,
    "idna": "3.10",
    "pygments": "2.19.1",
}


def _verify_dependencies() -> dict[str, str]:
    observed = {
        distribution: importlib.metadata.version(distribution)
        for distribution in IMPORT_DEPENDENCIES
    }
    mismatches = {
        distribution: {"expected": expected, "observed": observed[distribution]}
        for distribution, expected in IMPORT_DEPENDENCIES.items()
        if observed[distribution] != expected
    }
    if mismatches:
        raise SystemExit(f"suite import dependency mismatch: {mismatches}")
    return observed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", type=Path, required=True)
    args = parser.parse_args(argv)

    source = OfficialSourceAttestation.authenticate(args.checkout)
    disabled = _disable_unused_provider_initializers(source.root)
    sys.path.insert(0, str(source.root / "src"))
    from agentdojo.task_suite.load_suites import get_suites

    from sluice_v2.evaluation.agentdojo import BENCHMARK_VERSION

    registry = OfficialRegistryAttestation.verify(
        source=source,
        suites=get_suites(BENCHMARK_VERSION),
    )
    first_wire = build_principal_plan_wire(source=source, registry=registry)
    second_wire = build_principal_plan_wire(source=source, registry=registry)
    if first_wire != second_wire:
        raise SystemExit("principal plan construction is not deterministic")
    plan = PrincipalExecutionPlan.load(
        first_wire, expected_sha256=first_wire["sha256"]
    )
    balance = []
    for instance in plan.schedule_instances:
        first = [entry.condition for entry in instance.entries if entry.order == 1]
        left, right = instance.conditions
        balance.append(
            {
                "instance_id": instance.instance_id,
                "comparison_id": instance.comparison_id,
                "generation_seed": instance.generation_seed,
                "left_first": first.count(left),
                "right_first": first.count(right),
            }
        )
    observed_imports = _verify_dependencies()
    output = {
        "schema_version": "sluice-agentdojo-principal-cpu-attestation-v1",
        "source": source.to_wire(),
        "registry": registry.to_wire(),
        "plan": {
            "sha256": plan.sha256,
            "attacked_pair_count": plan.attacked_pair_count,
            "benign_task_count": plan.benign_task_count,
            "scenario_count": len(plan.scenarios),
            "schedule_instance_count": len(plan.schedule_instances),
            "planned_run_count": len(plan.entries),
            "seeds": list(plan.seeds),
            "repetitions_per_seed": plan.repetitions_per_seed,
            "policy_author_split_sha256": plan.policy_author_split_sha256,
            "development_task_count": len(
                plan.policy_author_split.development_task_ids
            ),
            "heldout_task_count": len(plan.policy_author_split.heldout_task_ids),
            "principal_outcomes_present": plan.principal_outcomes_present,
        },
        "counterbalance": balance,
        "runtime": {
            "python": sys.version.split()[0],
            "pydantic": importlib.metadata.version("pydantic"),
            "pyyaml": importlib.metadata.version("PyYAML"),
            "principal_dependency_match": False,
            "principal_eligible": False,
        },
        "import_dependencies_expected": IMPORT_DEPENDENCIES,
        "import_dependencies_observed": observed_imports,
        "provider_modules_disabled": list(disabled),
        "operations_performed": {
            "benchmark_evaluation": False,
            "endpoint_probe": False,
            "gpu": False,
            "model_call": False,
            "tool_call": False,
        },
        "result": "PASS_CPU_FOUNDATION_ONLY",
    }
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
