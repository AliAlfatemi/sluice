"""Trusted, pre-execution construction of the AgentDojo principal plan.

This module is the only side of the boundary that receives authenticated
official suite objects. It revalidates the pinned v0.1.35 checkout and v1.2.2
registry, projects finite public task coordinates, and emits a data-only plan.
It performs no model request, tool execution, benchmark evaluation, or GPU
operation.
"""

from __future__ import annotations

import hashlib
from typing import Mapping

from .agentdojo import generate_counterbalanced_schedule
from .agentdojo_live import (
    OfficialRegistryAttestation,
    OfficialSourceAttestation,
    PairedEpisodeIdentity,
)
from .agentdojo_principal_driver import (
    PRINCIPAL_REPETITIONS_PER_SEED,
    PRINCIPAL_SEEDS,
    PrincipalComparison,
    PrincipalCondition,
    principal_plan_sha256,
)


TOOL_FILTER_PIPELINE_SHA256 = (
    "2b9b82b98cef3662733a8207dfed9e4386c41fb74e69531a6f0a36207f9695e9"
)
TOOL_FILTER_LLM_SHA256 = (
    "7f91178cb0bb354b89427650d7b8725d6aff8fe18d43fc85bf4b4fdc1ddf9574"
)
POLICY_AUTHOR_SPLIT_SEED = "sluice-agentdojo-policy-author-split-v1:8675309"

_SUITE_TASK_COUNTS: Mapping[str, tuple[int, int, int]] = {
    "banking": (16, 9, 0),
    "slack": (21, 5, 1),
    "travel": (20, 7, 0),
    "workspace": (40, 14, 0),
}
_COMPARISONS = (
    (
        PrincipalComparison.OFFICIAL_TOOL_FILTER_VS_UNDEFENDED.value,
        (
            PrincipalCondition.UNDEFENDED.value,
            PrincipalCondition.OFFICIAL_TOOL_FILTER.value,
        ),
    ),
    (
        PrincipalComparison.SLUICE_NONORACLE_VS_UNDEFENDED.value,
        (
            PrincipalCondition.UNDEFENDED.value,
            PrincipalCondition.SLUICE_NONORACLE.value,
        ),
    ),
)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_text(domain: bytes, value: str) -> str:
    return hashlib.sha256(domain + b"\0" + value.encode("utf-8")).hexdigest()


def _with_digest(value: dict[str, object]) -> dict[str, object]:
    result = dict(value)
    result["sha256"] = principal_plan_sha256(result)
    return result


def _partition() -> dict[str, object]:
    development: list[str] = []
    heldout: list[str] = []
    for suite_name in sorted(_SUITE_TASK_COUNTS):
        user_count = _SUITE_TASK_COUNTS[suite_name][0]
        task_ids = [f"{suite_name}:user_task_{index}" for index in range(user_count)]
        ordered = sorted(
            task_ids,
            key=lambda task_id: _sha256_text(
                b"sluice-agentdojo-policy-author-split-order-v1",
                f"{POLICY_AUTHOR_SPLIT_SEED}\0{task_id}",
            ),
        )
        development_count = user_count // 4
        development.extend(ordered[:development_count])
        heldout.extend(ordered[development_count:])
    return _with_digest(
        {
            "schema_version": "sluice-agentdojo-policy-author-split-v1",
            "selection_seed": POLICY_AUTHOR_SPLIT_SEED,
            "development_task_ids": sorted(development),
            "heldout_task_ids": sorted(heldout),
        }
    )


def _policy_partition(
    split: Mapping[str, object], suite_name: str, user_task_id: str
) -> str:
    task_id = f"{suite_name}:{user_task_id}"
    if task_id in split["development_task_ids"]:
        return "development"
    if task_id in split["heldout_task_ids"]:
        return "heldout"
    raise ValueError("official task is absent from the frozen policy-author split")


def _scenario_id(
    *,
    stratum: str,
    suite_name: str,
    user_task_id: str,
    injection_task_id: str | None,
) -> str:
    coordinate = (
        f"{stratum}\0{suite_name}\0{user_task_id}\0"
        f"{'' if injection_task_id is None else injection_task_id}"
    )
    return _sha256_text(b"sluice-agentdojo-principal-scenario-v1", coordinate)


def _episode_id(
    *,
    stratum: str,
    suite_name: str,
    user_task_id: str,
    injection_task_id: str | None,
) -> str:
    suffix = "none" if injection_task_id is None else injection_task_id
    return f"{stratum}:{suite_name}:{user_task_id}:{suffix}"


def _universe(
    registry: OfficialRegistryAttestation,
    split: Mapping[str, object],
) -> dict[str, object]:
    attacked_rows: list[dict[str, object]] = []
    benign_rows: list[dict[str, object]] = []
    suite_pair_counts: dict[str, int] = {}
    suite_task_counts: dict[str, list[int]] = {}

    for suite_name in sorted(_SUITE_TASK_COUNTS):
        user_count, injection_count, injection_start = _SUITE_TASK_COUNTS[suite_name]
        suite_task_counts[suite_name] = [user_count, injection_count]
        suite_pair_counts[suite_name] = user_count * injection_count
        for user_index in range(user_count):
            user_task_id = f"user_task_{user_index}"
            partition = _policy_partition(split, suite_name, user_task_id)
            benign_episode = _episode_id(
                stratum="benign",
                suite_name=suite_name,
                user_task_id=user_task_id,
                injection_task_id=None,
            )
            benign_rows.append(
                {
                    "scenario_id": _scenario_id(
                        stratum="benign",
                        suite_name=suite_name,
                        user_task_id=user_task_id,
                        injection_task_id=None,
                    ),
                    "episode_id": benign_episode,
                    "stratum": "benign",
                    "suite_name": suite_name,
                    "user_task_id": user_task_id,
                    "injection_task_id": None,
                    "pair_id": None,
                    "policy_partition": partition,
                    "principal_scoring_eligible": partition == "heldout",
                }
            )
            for injection_index in range(
                injection_start, injection_start + injection_count
            ):
                injection_task_id = f"injection_task_{injection_index}"
                episode = _episode_id(
                    stratum="attacked",
                    suite_name=suite_name,
                    user_task_id=user_task_id,
                    injection_task_id=injection_task_id,
                )
                identity = PairedEpisodeIdentity.create(
                    episode_id=episode,
                    suite_name=suite_name,
                    user_task_id=user_task_id,
                    injection_task_id=injection_task_id,
                )
                # One revalidation precedes this finite projection. This
                # private membership check only inspects authenticated IDs.
                if not registry._contains_pair_snapshot(identity):
                    raise ValueError(
                        "constructed coordinate is absent from the official registry"
                    )
                attacked_rows.append(
                    {
                        "scenario_id": _scenario_id(
                            stratum="attacked",
                            suite_name=suite_name,
                            user_task_id=user_task_id,
                            injection_task_id=injection_task_id,
                        ),
                        "episode_id": episode,
                        "stratum": "attacked",
                        "suite_name": suite_name,
                        "user_task_id": user_task_id,
                        "injection_task_id": injection_task_id,
                        "pair_id": identity.pair_id,
                        "policy_partition": partition,
                        "principal_scoring_eligible": partition == "heldout",
                    }
                )

    return _with_digest(
        {
            "schema_version": "sluice-agentdojo-principal-universe-v1",
            "attacked_pair_count": len(attacked_rows),
            "benign_task_count": len(benign_rows),
            "suite_pair_counts": suite_pair_counts,
            "suite_task_counts": suite_task_counts,
            "attacked_pairs": attacked_rows,
            "benign_tasks": benign_rows,
        }
    )


def _baseline(source: OfficialSourceAttestation) -> dict[str, object]:
    pipeline_path = source.root / "src/agentdojo/agent_pipeline/agent_pipeline.py"
    llm_path = source.root / "src/agentdojo/agent_pipeline/llms/openai_llm.py"
    pipeline_sha = _sha256_bytes(pipeline_path.read_bytes())
    llm_sha = _sha256_bytes(llm_path.read_bytes())
    if pipeline_sha != TOOL_FILTER_PIPELINE_SHA256 or llm_sha != TOOL_FILTER_LLM_SHA256:
        raise ValueError("official tool-filter source digest mismatch")
    return _with_digest(
        {
            "schema_version": "sluice-agentdojo-official-tool-filter-v1",
            "condition": PrincipalCondition.OFFICIAL_TOOL_FILTER.value,
            "config_value": "tool_filter",
            "pipeline_source_relative": (
                "src/agentdojo/agent_pipeline/agent_pipeline.py"
            ),
            "pipeline_source_sha256": pipeline_sha,
            "llm_source_relative": (
                "src/agentdojo/agent_pipeline/llms/openai_llm.py"
            ),
            "llm_source_sha256": llm_sha,
            "pipeline_element_qualname": (
                "agentdojo.agent_pipeline.llms.openai_llm.OpenAILLMToolFilter"
            ),
            "requires_official_openai_adapter": True,
        }
    )


def _schedule_rows(
    *,
    universe: Mapping[str, object],
    conditions: tuple[str, str],
    attacked_seed: str,
    benign_seed: str,
) -> list[dict[str, object]]:
    attacked_ids = [row["episode_id"] for row in universe["attacked_pairs"]]
    benign_ids = [row["episode_id"] for row in universe["benign_tasks"]]
    attacked = generate_counterbalanced_schedule(
        attacked_ids, arms=conditions, seed=attacked_seed
    )
    # Both strata have odd cardinality. Reversing the benign arm orientation
    # cancels the one-entry imbalance in the attacked stratum.
    benign = generate_counterbalanced_schedule(
        benign_ids, arms=(conditions[1], conditions[0]), seed=benign_seed
    )
    rows = [
        {
            "block": item.block,
            "order": item.order,
            "episode_id": item.episode_id,
            "condition": item.arm,
        }
        for item in attacked
    ]
    rows.extend(
        {
            "block": len(attacked_ids) + item.block,
            "order": item.order,
            "episode_id": item.episode_id,
            "condition": item.arm,
        }
        for item in benign
    )
    return rows


def _schedule_instance(
    *,
    universe: Mapping[str, object],
    generation_seed: int,
    repetition: int,
    comparison_id: str,
    conditions: tuple[str, str],
) -> dict[str, object]:
    attacked_seed = (
        f"agentdojo-principal-v1:{generation_seed}:r{repetition}:"
        f"{comparison_id}:attacked"
    )
    benign_seed = (
        f"agentdojo-principal-v1:{generation_seed}:r{repetition}:"
        f"{comparison_id}:benign"
    )
    instance_id = _sha256_text(
        b"sluice-agentdojo-principal-instance-v1",
        f"{generation_seed}\0{repetition}\0{comparison_id}",
    )
    schedule = _with_digest(
        {
            "schema_version": "sluice-agentdojo-principal-schedule-v1",
            "entries": _schedule_rows(
                universe=universe,
                conditions=conditions,
                attacked_seed=attacked_seed,
                benign_seed=benign_seed,
            ),
        }
    )
    return _with_digest(
        {
            "schema_version": "sluice-agentdojo-principal-schedule-instance-v1",
            "instance_id": instance_id,
            "comparison_id": comparison_id,
            "conditions": list(conditions),
            "generation_seed": generation_seed,
            "repetition": repetition,
            "attacked_seed_sha256": _sha256_text(
                b"sluice-agentdojo-principal-seed-v1", attacked_seed
            ),
            "benign_seed_sha256": _sha256_text(
                b"sluice-agentdojo-principal-seed-v1", benign_seed
            ),
            "schedule": schedule,
        }
    )


def build_principal_plan_wire(
    *,
    source: OfficialSourceAttestation,
    registry: OfficialRegistryAttestation,
) -> dict[str, object]:
    """Return a deterministic plan after one exact authentication boundary."""

    if type(source) is not OfficialSourceAttestation:
        raise TypeError("source must be an exact OfficialSourceAttestation")
    if type(registry) is not OfficialRegistryAttestation:
        raise TypeError("registry must be an exact OfficialRegistryAttestation")
    source.revalidate()
    registry.revalidate()
    if registry.source is not source:
        raise ValueError("registry and source attestations are not identical")

    split = _partition()
    universe = _universe(registry, split)
    schedule_instances = []
    for generation_seed in PRINCIPAL_SEEDS:
        for repetition in range(PRINCIPAL_REPETITIONS_PER_SEED):
            for comparison_id, conditions in _COMPARISONS:
                schedule_instances.append(
                    _schedule_instance(
                        universe=universe,
                        generation_seed=generation_seed,
                        repetition=repetition,
                        comparison_id=comparison_id,
                        conditions=conditions,
                    )
                )

    plan = {
        "schema_version": "sluice-agentdojo-principal-plan-v1",
        "agentdojo_source": source.to_wire(),
        "registry": registry.to_wire(),
        "conditions": [condition.value for condition in PrincipalCondition],
        "comparisons": [
            {"comparison_id": comparison_id, "conditions": list(conditions)}
            for comparison_id, conditions in _COMPARISONS
        ],
        "seeds": list(PRINCIPAL_SEEDS),
        "repetitions_per_seed": PRINCIPAL_REPETITIONS_PER_SEED,
        "policy_author_split": split,
        "universe": universe,
        "official_tool_filter": _baseline(source),
        "schedule_instances": schedule_instances,
        "planned_run_count": sum(
            len(instance["schedule"]["entries"])
            for instance in schedule_instances
        ),
        "principal_outcomes_present": False,
    }
    plan["sha256"] = principal_plan_sha256(plan)
    return plan


__all__ = [
    "POLICY_AUTHOR_SPLIT_SEED",
    "TOOL_FILTER_LLM_SHA256",
    "TOOL_FILTER_PIPELINE_SHA256",
    "build_principal_plan_wire",
]
