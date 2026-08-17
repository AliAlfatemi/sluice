"""RQ2: exact transcript-distribution analysis for RELEASE gates.

For each configuration this experiment enumerates every secret under a
uniform prior.  A deterministic adaptive attacker partitions its current
candidate set into balanced buckets and selects an affordable arity using
dynamic programming.  The policy maximizes final Shannon information within
this declared balanced-partition policy class; posterior Bayes vulnerability
is computed separately from the resulting transcript classes.

The experiment imports ``monitor.gate_cost_units`` for every affordability
decision and uses ``gate_cost_bits`` only as a reporting view.  Consequently
a change to the monitor's complete charged observable support changes both
the policy and the report automatically without float round trips.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from collections import Counter
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Optional, Sequence

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "sluice_v2"))

from monitor import (  # noqa: E402
    Backend,
    Direction,
    Outcome,
    ReferenceMonitor,
    Symbol,
    gate_cost_bits,
    gate_cost_units,
)
from store import ACCOUNTING_SCALE, DurableStore, cap_bits_to_units, units_to_bits  # noqa: E402

POLICY_NAME = "balanced_dp_shannon_then_bayes_v1"
FLOAT_TOLERANCE = 1e-9


class RevealBucketBackend(Backend):
    """Trusted synthetic backend whose only secret-dependent output is a bucket."""

    def __init__(self, secret: int):
        self.secret = secret

    def decode(self, query_json: str, symbol_values: Sequence[str]) -> str:
        buckets = json.loads(query_json)
        for symbol in symbol_values:
            if self.secret in buckets[symbol]:
                return symbol
        raise ValueError("secret not covered by query partition")


@dataclass(frozen=True)
class Plan:
    first_arity: Optional[int]
    leaf_sizes: tuple[int, ...]
    mutual_information_bits: float

    @property
    def leaf_count(self) -> int:
        return len(self.leaf_sizes)


def balanced_sizes(n_candidates: int, arity: int) -> tuple[int, ...]:
    if not 2 <= arity <= n_candidates:
        raise ValueError("arity must be between 2 and the candidate count")
    quotient, remainder = divmod(n_candidates, arity)
    return tuple(quotient + (1 if index < remainder else 0) for index in range(arity))


def balanced_partition(candidates: Sequence[int], arity: int) -> dict[str, list[int]]:
    sizes = balanced_sizes(len(candidates), arity)
    buckets: dict[str, list[int]] = {}
    offset = 0
    for index, size in enumerate(sizes):
        buckets[f"b{index}"] = list(candidates[offset : offset + size])
        offset += size
    if offset != len(candidates):
        raise AssertionError("balanced partition did not cover every candidate")
    return buckets


def mutual_information_from_leaf_sizes(n_candidates: int, leaf_sizes: Sequence[int]) -> float:
    """Exact-enumeration Shannon MI for a deterministic uniform channel."""
    if sum(leaf_sizes) != n_candidates or any(size <= 0 for size in leaf_sizes):
        raise ValueError("leaf sizes must be a positive partition of the candidate set")
    conditional_entropy = math.fsum(
        (size / n_candidates) * math.log2(size) for size in leaf_sizes
    )
    return math.log2(n_candidates) - conditional_entropy


def make_balanced_policy(max_cardinality: int):
    """Return a memoized policy planner using production gate costs.

    The state is public: candidate-count and remaining authorized budget.
    Choices never inspect the secret.  Memoization and affordability use only
    exact integer microbit units.
    """

    @lru_cache(maxsize=None)
    def plan(n_candidates: int, remaining_units: int) -> Plan:
        best = Plan(None, (n_candidates,), 0.0)
        best_score = (0.0, 1, 0.0, 0)

        for arity in range(2, min(max_cardinality, n_candidates) + 1):
            cost_units = gate_cost_units(arity)
            if cost_units > remaining_units:
                continue
            next_units = remaining_units - cost_units
            child_plans = [plan(size, next_units) for size in balanced_sizes(n_candidates, arity)]
            leaf_sizes = tuple(
                leaf_size for child in child_plans for leaf_size in child.leaf_sizes
            )
            mi_bits = mutual_information_from_leaf_sizes(n_candidates, leaf_sizes)
            # Shannon MI is the primary objective.  Bayes vulnerability
            # (leaf count under a uniform deterministic channel) breaks ties,
            # followed by lower immediate cost and lower arity.
            score = (
                round(mi_bits, 12),
                len(leaf_sizes),
                -cost_units,
                -arity,
            )
            if score > best_score:
                best = Plan(arity, leaf_sizes, mi_bits)
                best_score = score
        return best

    def select(n_candidates: int, remaining_budget) -> Plan:
        if isinstance(remaining_budget, bool):
            raise ValueError("remaining budget must be an integer unit count or bit value")
        remaining_units = (
            remaining_budget
            if isinstance(remaining_budget, int)
            else cap_bits_to_units(float(remaining_budget))
        )
        return plan(n_candidates, max(0, remaining_units))

    return select


def transcript_key(transcript: Sequence[dict[str, Any]]) -> str:
    observable = [[step["outcome"], step["value"]] for step in transcript]
    return json.dumps(observable, ensure_ascii=False, separators=(",", ":"))


def _query_digest(query_json: str) -> str:
    return hashlib.sha256(query_json.encode("utf-8")).hexdigest()


def run_secret(
    n_secrets: int,
    secret: int,
    cap_bits: float,
    max_cardinality: int,
    db_path: Path,
    policy,
) -> dict[str, Any]:
    store = DurableStore(str(db_path))
    backend = RevealBucketBackend(secret)
    monitor = ReferenceMonitor(
        store,
        backend,
        default_cap_bits=cap_bits,
        max_cardinality=max(max_cardinality, 2),
        trusted_planner_identities=frozenset({"trusted_release_planner"}),
    )
    protected_object = "rq2-secret"
    candidates: tuple[int, ...] = tuple(range(n_secrets))
    transcript: list[dict[str, Any]] = []
    query_trace: list[dict[str, Any]] = []

    try:
        while len(candidates) > 1:
            spent_before_units = monitor.spent_units(protected_object, 0)
            cap_units = cap_bits_to_units(cap_bits)
            remaining_units = max(0, cap_units - spent_before_units)
            selected_plan = policy(len(candidates), remaining_units)
            arity = selected_plan.first_arity
            if arity is None:
                break

            cost_units = gate_cost_units(arity)
            cost = units_to_bits(cost_units)
            if spent_before_units + cost_units > cap_units:
                raise AssertionError("policy selected an unaffordable gate")

            buckets = balanced_partition(candidates, arity)
            symbols = [Symbol(name) for name in buckets]
            gate_id = f"g-{len(transcript)}"
            handle = monitor.author_gate(
                gate_id,
                "rq2-release-workflow",
                protected_object,
                Direction.RELEASE,
                symbols,
                "trusted_release_planner",
                frozenset({"attacker"}),
                cap_bits=cap_bits,
            )
            query_json = json.dumps(buckets, sort_keys=True, separators=(",", ":"))
            observation = monitor.invoke(handle, query_json, "attacker")
            transcript.append(
                {
                    "outcome": observation.outcome.value,
                    "value": observation.value,
                }
            )
            query_trace.append(
                {
                    "arity": arity,
                    "authorized_cost_bits": cost,
                    "authorized_cost_units": cost_units,
                    "candidate_count_before": len(candidates),
                    "query_sha256": _query_digest(query_json),
                }
            )
            if observation.outcome != Outcome.OK:
                raise RuntimeError(
                    f"budget-aware RQ2 policy produced {observation.outcome.value!r}"
                )
            candidates = tuple(buckets[observation.value])

        if secret not in candidates:
            raise AssertionError("true secret was removed from the posterior support")
        spent_units = monitor.spent_units(protected_object, 0)
        spent = units_to_bits(spent_units)
        audit_linkage_valid = store.verify_audit_chain()
    finally:
        store.close()

    return {
        "secret": secret,
        "transcript": transcript,
        "transcript_key": transcript_key(transcript),
        "query_trace": query_trace,
        "calls": len(transcript),
        "bits_spent": spent,
        "units_spent": spent_units,
        "remaining_candidates": list(candidates),
        "remaining_candidate_count": len(candidates),
        "secret_in_remaining": secret in candidates,
        "audit_linkage_valid": audit_linkage_valid,
    }


def _probability(numerator: int, denominator: int) -> dict[str, Any]:
    divisor = math.gcd(numerator, denominator)
    return {
        "numerator": numerator // divisor,
        "denominator": denominator // divisor,
        "decimal": numerator / denominator,
    }


def _bayes_bound(capacity_bits: float, n_secrets: int) -> float:
    return min(1.0, 2.0 ** min(capacity_bits, math.log2(n_secrets)) / n_secrets)


def summarize_config(
    n_secrets: int,
    cap_bits: float,
    max_cardinality: int,
    executions: list[dict[str, Any]],
    root_plan: Plan,
) -> dict[str, Any]:
    counts = Counter(execution["transcript_key"] for execution in executions)
    if sum(counts.values()) != n_secrets:
        raise AssertionError("transcript classes do not cover the prior")

    prior_entropy = math.log2(n_secrets)
    conditional_entropy = math.fsum(
        (count / n_secrets) * math.log2(count) for count in counts.values()
    )
    mutual_information = prior_entropy - conditional_entropy
    spent_values = [execution["bits_spent"] for execution in executions]
    spent_unit_values = [execution["units_spent"] for execution in executions]
    max_spent = max(spent_values, default=0.0)
    n_transcripts = len(counts)
    representative = {execution["transcript_key"]: execution for execution in executions}
    transcript_classes = [
        {
            "transcript": representative[key]["transcript"],
            "count": count,
            "posterior_max_probability": 1.0 / count,
        }
        for key, count in sorted(counts.items())
    ]

    cap_units = cap_bits_to_units(cap_bits)
    effective_cap_bits = units_to_bits(cap_units)
    configured_shannon_bound = min(prior_entropy, effective_cap_bits)
    path_shannon_bound = min(prior_entropy, max_spent)
    posterior_vulnerability = n_transcripts / n_secrets
    configured_bayes_bound = _bayes_bound(effective_cap_bits, n_secrets)
    path_bayes_bound = _bayes_bound(max_spent, n_secrets)

    return {
        "requested_cap_bits": cap_bits,
        "cap_bits": effective_cap_bits,
        "cap_units": cap_units,
        "max_cardinality": max_cardinality,
        "n_secrets_evaluated": len(executions),
        "enumeration_complete": len(executions) == n_secrets,
        "policy": {
            "name": POLICY_NAME,
            "root_arity": root_plan.first_arity,
            "predicted_leaf_count": root_plan.leaf_count,
            "predicted_mutual_information_bits": root_plan.mutual_information_bits,
            "prediction_matches_enumeration": (
                root_plan.leaf_count == n_transcripts
                and abs(root_plan.mutual_information_bits - mutual_information)
                <= FLOAT_TOLERANCE
            ),
        },
        "n_distinct_transcripts": n_transcripts,
        "transcript_class_counts": transcript_classes,
        "shannon": {
            "prior_entropy_bits": prior_entropy,
            "conditional_entropy_bits": conditional_entropy,
            "mutual_information_bits": mutual_information,
            "configured_cap_bound_bits": configured_shannon_bound,
            "max_path_spend_bound_bits": path_shannon_bound,
            "gap_to_configured_cap_bits": configured_shannon_bound - mutual_information,
            "gap_to_max_path_spend_bits": path_shannon_bound - mutual_information,
            "configured_cap_bound_holds": mutual_information
            <= configured_shannon_bound + FLOAT_TOLERANCE,
            "max_path_spend_bound_holds": mutual_information
            <= path_shannon_bound + FLOAT_TOLERANCE,
        },
        "bayes": {
            "prior_vulnerability": _probability(1, n_secrets),
            "posterior_vulnerability": _probability(n_transcripts, n_secrets),
            "min_entropy_leakage_bits": math.log2(n_transcripts),
            "configured_cap_bound": configured_bayes_bound,
            "max_path_spend_bound": path_bayes_bound,
            "configured_cap_bound_holds": posterior_vulnerability
            <= configured_bayes_bound + FLOAT_TOLERANCE,
            "max_path_spend_bound_holds": posterior_vulnerability
            <= path_bayes_bound + FLOAT_TOLERANCE,
        },
        "budget": {
            "minimum_spent_bits": min(spent_values, default=0.0),
            "mean_spent_bits": statistics.fmean(spent_values) if spent_values else 0.0,
            "maximum_spent_bits": max_spent,
            "minimum_spent_units": min(spent_unit_values, default=0),
            "maximum_spent_units": max(spent_unit_values, default=0),
            "budget_exhausted_outcomes": sum(
                step["outcome"] == Outcome.BUDGET_EXHAUSTED.value
                for execution in executions
                for step in execution["transcript"]
            ),
        },
        "all_audit_linkage_checks_passed": all(
            execution["audit_linkage_valid"] for execution in executions
        ),
        "raw_executions": executions,
    }


def run_config(
    n_secrets: int,
    cap_bits: float,
    max_cardinality: int,
    temp_dir: Path,
) -> dict[str, Any]:
    policy = make_balanced_policy(max_cardinality)
    root_plan = policy(n_secrets, cap_bits_to_units(cap_bits))
    executions = [
        run_secret(
            n_secrets,
            secret,
            cap_bits,
            max_cardinality,
            temp_dir / f"cap-{cap_bits:g}-card-{max_cardinality}-secret-{secret}.db",
            policy,
        )
        for secret in range(n_secrets)
    ]
    return summarize_config(
        n_secrets, cap_bits, max_cardinality, executions, root_plan
    )


def _git_provenance() -> dict[str, Any]:
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=HERE.parent,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        dirty = bool(
            subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=HERE.parent,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
        )
        return {"git_commit": commit, "git_dirty": dirty}
    except (OSError, subprocess.CalledProcessError):
        return {"git_commit": None, "git_dirty": None}


def run_experiment(
    n_secrets: int = 256,
    caps: Sequence[float] = (2.0, 4.0, 6.0, 8.0),
    cardinalities: Sequence[int] = (2, 4, 8),
    temp_root: Optional[str] = None,
) -> dict[str, Any]:
    if n_secrets < 2:
        raise ValueError("n_secrets must be at least 2")
    if any(cap < 0 or not math.isfinite(cap) for cap in caps):
        raise ValueError("caps must be finite and non-negative")
    if any(cardinality < 2 for cardinality in cardinalities):
        raise ValueError("cardinalities must be at least 2")

    started = time.time()
    with tempfile.TemporaryDirectory(prefix="sluice-rq2-", dir=temp_root) as temp:
        temp_dir = Path(temp)
        configs = []
        for config_index, (cap, cardinality) in enumerate(
            (cap, cardinality)
            for cap in caps
            for cardinality in cardinalities
        ):
            config_temp = temp_dir / f"config-{config_index}"
            config_temp.mkdir()
            configs.append(
                run_config(
                    n_secrets,
                    float(cap),
                    int(cardinality),
                    config_temp,
                )
            )
    finished = time.time()

    result = {
        "schema_version": "sluice.rq2.v2",
        "experiment_id": "rq2_exact_transcript_analysis",
        "prior": {"kind": "uniform", "n_secrets": n_secrets},
        "enumeration_complete": all(
            config["enumeration_complete"] for config in configs
        ),
        "policy": {
            "name": POLICY_NAME,
            "scope": "optimal within deterministic balanced partitions",
        },
        "cost_model_bits": {
            str(arity): gate_cost_bits(arity)
            for arity in range(2, max(cardinalities) + 1)
        },
        "cost_model_units": {
            str(arity): gate_cost_units(arity)
            for arity in range(2, max(cardinalities) + 1)
        },
        "accounting_scale_units_per_bit": ACCOUNTING_SCALE,
        "n_configs": len(configs),
        "elapsed_seconds": finished - started,
        "provenance": {
            **_git_provenance(),
            "hostname": platform.node(),
            "python": sys.version,
            "started_at_unix": started,
            "finished_at_unix": finished,
        },
        "configs": configs,
    }
    return result


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n-secrets", type=int, default=256)
    parser.add_argument("--caps", nargs="+", type=float, default=[2.0, 4.0, 6.0, 8.0])
    parser.add_argument("--cardinalities", nargs="+", type=int, default=[2, 4, 8])
    parser.add_argument("--temp-root")
    parser.add_argument(
        "--output",
        type=Path,
        default=HERE / "rq2_bound_tightness_results.json",
    )
    args = parser.parse_args(argv)

    result = run_experiment(
        n_secrets=args.n_secrets,
        caps=args.caps,
        cardinalities=args.cardinalities,
        temp_root=args.temp_root,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        f"enumerated {args.n_secrets} secrets for {result['n_configs']} configs "
        f"in {result['elapsed_seconds']:.2f}s"
    )
    for config in result["configs"]:
        print(
            f"cap={config['cap_bits']:g} card={config['max_cardinality']} "
            f"transcripts={config['n_distinct_transcripts']} "
            f"MI={config['shannon']['mutual_information_bits']:.6f}b "
            f"V={config['bayes']['posterior_vulnerability']['decimal']:.6f}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
