"""RQ2 extension: cross-object interleaved adaptive attacker.

The paper's introduction identifies the flaw that forced the redesign: "the
union bound over independent calls is not a valid argument for an adaptive,
interactive workflow, where which gate is invoked next, and its cost, can
depend on prior observations." RQ2 (``rq2_bound_tightness.py``) already
exercises within-object adaptivity: for a single protected object, the
attacker's next query depends on everything observed so far for that object.
It does not exercise CROSS-object adaptivity, where a single shared monitor
mediates two distinct protected objects in one trace and the attacker
chooses WHICH object to query next based on the full cross-object
transcript. This experiment targets exactly that gap.

Design does not claim, and this experiment does not test for, any bound on
a global cross-object trace quantity (Sec. "GateRecord and the observable
alphabet" scopes the charge to one protected object; budgets are tracked per
``(protected_object, epoch)``). What is tested: does each object's OWN
marginal transcript distribution -- and therefore its own Shannon MI and
Bayes vulnerability against its own configured cap -- stay invariant to (a)
interleaving with a second, simultaneously and adaptively queried object,
and (b) the specific cross-object interleaving strategy used? A violation
would mean shared monitor/store state lets one object's queries leak
information about, or be influenced by, another object's secret or query
history: a concrete instance of the composition failure the redesign set
out to close by keying accounting exactly to ``protected_object``.

Method: two protected objects A and B, each with a uniform secret over
``n_secrets`` candidates and its own copy of RQ2's exact balanced-DP policy
class, share ONE ``DurableStore``/``ReferenceMonitor``/backend instance (one
shared audit log, matching a real multi-object workflow). Object B's
candidate integers are disjoint from A's (offset), which lets one shared
synthetic backend disambiguate which object a given query targets purely
from the bucket contents -- no core ``sluice_v2`` code is touched or needs
to know about "objects" at all; this is entirely experiment-harness
machinery, exactly like RQ2's own ``RevealBucketBackend``.

Every (secret_a, secret_b) pair in the full n_secrets x n_secrets product is
enumerated (not sampled). Two interleaving strategies are compared:
``round_robin`` (object choice ignores all state -- a non-adaptive control)
and ``greedy_mi_per_unit_cost`` (object choice picks whichever object's next
DP-optimal query yields the best bits-per-unit-cost, given BOTH objects'
current state -- a self-interestedly adaptive, cross-object-informed
attacker). For each strategy, this experiment verifies structurally that
transcript_a is a function of secret_a alone (invariant across all 16 paired
secret_b values) before computing its Shannon MI/Bayes vulnerability, and
symmetrically for B; any non-singleton "distinct transcripts observed for a
fixed secret" would itself be the finding (cross-object contamination), not
a benign result to average over. A same-config isolated single-object
baseline (RQ2's own ``run_config``, no second object present at all) is
computed once for reference.
"""

from __future__ import annotations

import argparse
import json
import platform
import subprocess
import sys
import tempfile
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Optional, Sequence

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "sluice_v2"))

from monitor import Backend, Direction, Outcome, ReferenceMonitor, Symbol, gate_cost_units  # noqa: E402
from store import DurableStore, cap_bits_to_units, units_to_bits  # noqa: E402

from rq2_bound_tightness import (  # noqa: E402
    POLICY_NAME,
    _bayes_bound,
    _probability,
    balanced_partition,
    make_balanced_policy,
    run_config as run_isolated_single_object_config,
    transcript_key,
)

STRATEGIES = ("round_robin", "greedy_mi_per_unit_cost")
OBJECT_KEYS = ("A", "B")


class MultiObjectBucketBackend(Backend):
    """Trusted synthetic backend serving gates for two disjoint-domain objects.

    Disambiguates purely from which secret value (if any) appears in the
    query's bucket contents; A's and B's candidate integers never overlap,
    so this is unambiguous without any protected-object hint from the core
    monitor, and requires no change to ``sluice_v2``.
    """

    def __init__(self, secret_by_object: dict[str, int]):
        self.secret_by_object = secret_by_object

    def decode(self, query_json: str, symbol_values: Sequence[str]) -> str:
        buckets = json.loads(query_json)
        matches = set()
        for secret in self.secret_by_object.values():
            for symbol in symbol_values:
                if secret in buckets.get(symbol, ()):
                    matches.add(symbol)
        if len(matches) != 1:
            raise AssertionError(
                f"expected exactly one disambiguated bucket match, got {matches!r}"
            )
        return next(iter(matches))


def _select_round_robin(active_keys: list[str], query_counts: dict[str, int]) -> str:
    return min(active_keys, key=lambda key: (query_counts[key], key))


def _select_greedy_mi_per_unit_cost(
    active_keys: list[str],
    objects: dict[str, dict[str, Any]],
    monitor: ReferenceMonitor,
    policy,
    cap_units: int,
) -> str:
    best_key: Optional[str] = None
    best_score: Optional[tuple[float, int]] = None
    for key in active_keys:
        obj = objects[key]
        spent_units = monitor.spent_units(obj["protected_object"], 0)
        remaining_units = max(0, cap_units - spent_units)
        plan = policy(len(obj["candidates"]), remaining_units)
        if plan.first_arity is None:
            continue
        cost_units = gate_cost_units(plan.first_arity)
        score = (plan.mutual_information_bits / cost_units, -cost_units)
        if best_score is None or score > best_score:
            best_key, best_score = key, score
    if best_key is None:
        # Every active object is currently unaffordable; fall back to
        # round-robin so the caller still makes forward progress and the
        # policy's own `arity is None` handling marks it inactive.
        return min(active_keys, key=lambda key: key)
    return best_key


def run_joint_pair(
    secret_a: int,
    secret_b: int,
    n_secrets: int,
    cap_bits: float,
    max_cardinality: int,
    db_path: Path,
    policy,
    strategy: str,
    object_b_offset: int,
) -> dict[str, Any]:
    store = DurableStore(str(db_path))
    backend = MultiObjectBucketBackend(
        {"A": secret_a, "B": secret_b + object_b_offset}
    )
    monitor = ReferenceMonitor(
        store,
        backend,
        default_cap_bits=cap_bits,
        max_cardinality=max(max_cardinality, 2),
        trusted_planner_identities=frozenset({"trusted_release_planner"}),
    )
    cap_units = cap_bits_to_units(cap_bits)
    objects: dict[str, dict[str, Any]] = {
        "A": {
            "protected_object": "rq2mo-object-A",
            "candidates": tuple(range(n_secrets)),
            "transcript": [],
            "secret": secret_a,
            "active": True,
        },
        "B": {
            "protected_object": "rq2mo-object-B",
            "candidates": tuple(range(object_b_offset, object_b_offset + n_secrets)),
            "transcript": [],
            "secret": secret_b + object_b_offset,
            "active": True,
        },
    }
    interleave_order: list[str] = []
    step = 0
    try:
        while any(objects[key]["active"] for key in OBJECT_KEYS):
            active_keys = [
                key
                for key in OBJECT_KEYS
                if objects[key]["active"] and len(objects[key]["candidates"]) > 1
            ]
            if not active_keys:
                for key in OBJECT_KEYS:
                    objects[key]["active"] = False
                break
            if len(active_keys) == 1:
                chosen = active_keys[0]
            elif strategy == "round_robin":
                query_counts = {
                    key: len(objects[key]["transcript"]) for key in OBJECT_KEYS
                }
                chosen = _select_round_robin(active_keys, query_counts)
            elif strategy == "greedy_mi_per_unit_cost":
                chosen = _select_greedy_mi_per_unit_cost(
                    active_keys, objects, monitor, policy, cap_units
                )
            else:
                raise ValueError(f"unknown interleaving strategy {strategy!r}")

            obj = objects[chosen]
            protected_object = obj["protected_object"]
            spent_before_units = monitor.spent_units(protected_object, 0)
            remaining_units = max(0, cap_units - spent_before_units)
            selected_plan = policy(len(obj["candidates"]), remaining_units)
            arity = selected_plan.first_arity
            if arity is None:
                obj["active"] = False
                continue

            buckets = balanced_partition(obj["candidates"], arity)
            symbols = [Symbol(name) for name in buckets]
            gate_id = f"g-{chosen}-{step}"
            handle = monitor.author_gate(
                gate_id,
                "rq2mo-interleaved-workflow",
                protected_object,
                Direction.RELEASE,
                symbols,
                "trusted_release_planner",
                frozenset({"attacker"}),
                cap_bits=cap_bits,
            )
            query_json = json.dumps(buckets, sort_keys=True, separators=(",", ":"))
            observation = monitor.invoke(handle, query_json, "attacker")
            obj["transcript"].append(
                {"outcome": observation.outcome.value, "value": observation.value}
            )
            interleave_order.append(chosen)
            if observation.outcome != Outcome.OK:
                raise RuntimeError(
                    f"policy produced {observation.outcome.value!r} for object {chosen}"
                )
            obj["candidates"] = tuple(buckets[observation.value])
            if len(obj["candidates"]) <= 1:
                obj["active"] = False
            step += 1

        for key in OBJECT_KEYS:
            if objects[key]["secret"] not in objects[key]["candidates"]:
                raise AssertionError(
                    f"true secret removed from posterior support for object {key}"
                )
        audit_linkage_valid = store.verify_audit_chain()
        spent_a = monitor.spent_units(objects["A"]["protected_object"], 0)
        spent_b = monitor.spent_units(objects["B"]["protected_object"], 0)
    finally:
        store.close()

    return {
        "secret_a": secret_a,
        "secret_b": secret_b,
        "transcript_a": objects["A"]["transcript"],
        "transcript_a_key": transcript_key(objects["A"]["transcript"]),
        "transcript_b": objects["B"]["transcript"],
        "transcript_b_key": transcript_key(objects["B"]["transcript"]),
        "units_spent_a": spent_a,
        "units_spent_b": spent_b,
        "bits_spent_a": units_to_bits(spent_a),
        "bits_spent_b": units_to_bits(spent_b),
        "interleave_order": interleave_order,
        "audit_linkage_valid": audit_linkage_valid,
    }


def _marginal_summary(
    object_label: str,
    own_secret_field: str,
    other_secret_field: str,
    transcript_key_field: str,
    n_secrets: int,
    cap_bits: float,
    executions: list[dict[str, Any]],
) -> dict[str, Any]:
    by_own_secret: dict[int, set[str]] = defaultdict(set)
    for execution in executions:
        by_own_secret[execution[own_secret_field]].add(execution[transcript_key_field])

    contamination: list[dict[str, Any]] = []
    for own_secret, keys in by_own_secret.items():
        if len(keys) != 1:
            contamination.append(
                {
                    "secret": own_secret,
                    "distinct_transcripts_across_other_object_secret": sorted(keys),
                }
            )
    contamination_free = not contamination

    canonical_key_by_secret = {
        secret: next(iter(keys)) for secret, keys in by_own_secret.items()
    }
    if len(canonical_key_by_secret) != n_secrets:
        raise AssertionError(
            f"expected {n_secrets} distinct {object_label} secrets, "
            f"observed {len(canonical_key_by_secret)}"
        )

    counts = Counter(canonical_key_by_secret.values())
    prior_entropy = __import__("math").log2(n_secrets)
    conditional_entropy = __import__("math").fsum(
        (count / n_secrets) * __import__("math").log2(count) for count in counts.values()
    )
    mutual_information = prior_entropy - conditional_entropy
    n_transcripts = len(counts)
    posterior_vulnerability = n_transcripts / n_secrets

    cap_units = cap_bits_to_units(cap_bits)
    effective_cap_bits = units_to_bits(cap_units)
    configured_shannon_bound = min(prior_entropy, effective_cap_bits)
    configured_bayes_bound = _bayes_bound(effective_cap_bits, n_secrets)

    return {
        "object": object_label,
        "n_secrets": n_secrets,
        "cross_object_contamination_free": contamination_free,
        "cross_object_contamination_detail": contamination,
        "n_distinct_transcripts": n_transcripts,
        "shannon": {
            "prior_entropy_bits": prior_entropy,
            "conditional_entropy_bits": conditional_entropy,
            "mutual_information_bits": mutual_information,
            "configured_cap_bound_bits": configured_shannon_bound,
            "configured_cap_bound_holds": mutual_information
            <= configured_shannon_bound + 1e-9,
        },
        "bayes": {
            "posterior_vulnerability": _probability(n_transcripts, n_secrets),
            "configured_cap_bound": configured_bayes_bound,
            "configured_cap_bound_holds": posterior_vulnerability
            <= configured_bayes_bound + 1e-9,
        },
    }


def run_strategy(
    strategy: str,
    n_secrets: int,
    cap_bits: float,
    max_cardinality: int,
    temp_dir: Path,
) -> dict[str, Any]:
    policy = make_balanced_policy(max_cardinality)
    object_b_offset = n_secrets * 1000  # disjoint from A's [0, n_secrets) domain
    executions = []
    for secret_a in range(n_secrets):
        for secret_b in range(n_secrets):
            executions.append(
                run_joint_pair(
                    secret_a,
                    secret_b,
                    n_secrets,
                    cap_bits,
                    max_cardinality,
                    temp_dir
                    / f"{strategy}-a{secret_a}-b{secret_b}.db",
                    policy,
                    strategy,
                    object_b_offset,
                )
            )

    summary_a = _marginal_summary(
        "A", "secret_a", "secret_b", "transcript_a_key", n_secrets, cap_bits, executions
    )
    summary_b = _marginal_summary(
        "B", "secret_b", "secret_a", "transcript_b_key", n_secrets, cap_bits, executions
    )
    return {
        "strategy": strategy,
        "n_joint_pairs": len(executions),
        "all_audit_linkage_checks_passed": all(
            execution["audit_linkage_valid"] for execution in executions
        ),
        "object_a": summary_a,
        "object_b": summary_b,
        "raw_executions": executions,
    }


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
    n_secrets: int = 16,
    cap_bits: float = 6.0,
    max_cardinality: int = 4,
    temp_root: Optional[str] = None,
) -> dict[str, Any]:
    if n_secrets < 2:
        raise ValueError("n_secrets must be at least 2")

    started = time.time()
    with tempfile.TemporaryDirectory(prefix="sluice-rq2mo-", dir=temp_root) as temp:
        temp_dir = Path(temp)
        strategy_results = []
        for strategy in STRATEGIES:
            strategy_temp = temp_dir / strategy
            strategy_temp.mkdir()
            strategy_results.append(
                run_strategy(strategy, n_secrets, cap_bits, max_cardinality, strategy_temp)
            )

        isolated_temp = temp_dir / "isolated-baseline"
        isolated_temp.mkdir()
        isolated_baseline = run_isolated_single_object_config(
            n_secrets, cap_bits, max_cardinality, isolated_temp
        )
    finished = time.time()

    agreement = {
        "mutual_information_bits_match_across_strategies_and_baseline": len(
            {
                round(result["object_a"]["shannon"]["mutual_information_bits"], 9)
                for result in strategy_results
            }
            | {round(isolated_baseline["shannon"]["mutual_information_bits"], 9)}
        )
        == 1,
        "posterior_vulnerability_match_across_strategies_and_baseline": len(
            {
                round(result["object_a"]["bayes"]["posterior_vulnerability"]["decimal"], 12)
                for result in strategy_results
            }
            | {
                round(
                    isolated_baseline["bayes"]["posterior_vulnerability"]["decimal"], 12
                )
            }
        )
        == 1,
        "note": (
            "Object B is symmetric by construction (same n_secrets/cap/cardinality "
            "as object A); object_a numbers are compared against the isolated "
            "single-object baseline computed with no second object present at all."
        ),
    }

    return {
        "schema_version": "sluice.rq2_multiobject_interleaved.v1",
        "experiment_id": "rq2_multiobject_interleaved_adaptive_attacker",
        "motivation": (
            "Empirically test cross-object adaptive interleaving, the "
            "composition scenario the paper's introduction identifies as "
            "invalidating a union-bound argument; RQ2 alone only exercises "
            "within-object adaptivity."
        ),
        "config": {
            "n_secrets_per_object": n_secrets,
            "cap_bits": cap_bits,
            "max_cardinality": max_cardinality,
            "policy": POLICY_NAME,
            "strategies": list(STRATEGIES),
        },
        "elapsed_seconds": finished - started,
        "provenance": {
            **_git_provenance(),
            "hostname": platform.node(),
            "python": sys.version,
            "started_at_unix": started,
            "finished_at_unix": finished,
        },
        "cross_strategy_agreement": agreement,
        "isolated_single_object_baseline": isolated_baseline,
        "strategy_results": strategy_results,
    }


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n-secrets", type=int, default=16)
    parser.add_argument("--cap-bits", type=float, default=6.0)
    parser.add_argument("--max-cardinality", type=int, default=4)
    parser.add_argument("--temp-root")
    parser.add_argument(
        "--output",
        type=Path,
        default=HERE / "rq2_multiobject_interleaved_results.json",
    )
    args = parser.parse_args(argv)

    result = run_experiment(
        n_secrets=args.n_secrets,
        cap_bits=args.cap_bits,
        max_cardinality=args.max_cardinality,
        temp_root=args.temp_root,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(
        f"{result['config']['n_secrets_per_object']}x{result['config']['n_secrets_per_object']} "
        f"joint pairs, {len(STRATEGIES)} strategies, in {result['elapsed_seconds']:.2f}s"
    )
    for strategy_result in result["strategy_results"]:
        obj_a = strategy_result["object_a"]
        print(
            f"strategy={strategy_result['strategy']:<24} "
            f"MI_A={obj_a['shannon']['mutual_information_bits']:.6f}b "
            f"V_A={obj_a['bayes']['posterior_vulnerability']['decimal']:.6f} "
            f"contamination_free={obj_a['cross_object_contamination_free']} "
            f"cap_holds={obj_a['shannon']['configured_cap_bound_holds']}"
        )
    print(
        "isolated baseline: "
        f"MI={result['isolated_single_object_baseline']['shannon']['mutual_information_bits']:.6f}b "
        f"V={result['isolated_single_object_baseline']['bayes']['posterior_vulnerability']['decimal']:.6f}"
    )
    print(f"cross-strategy agreement: {result['cross_strategy_agreement']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
