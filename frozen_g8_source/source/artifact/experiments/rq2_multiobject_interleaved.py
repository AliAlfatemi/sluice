"""RQ2 extension: cross-object interleaved adaptive attacker, asymmetric.

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

Objects A and B are DELIBERATELY ASYMMETRIC: different candidate-set sizes
and maximum cardinalities (the earlier version of
this experiment used identical parameters for both objects and reported
that ``round_robin`` and its claimed-adaptive alternative produced the
byte-identical interleaving ``['A','B','A','B',...]`` on every secret pair
tested -- a real defect, since two schedules that never differ are not
evidence of two different strategies, regardless of what each is named).
With asymmetric objects, ``greedy_immediate_bits_per_cost`` -- pick
whichever object's *next single query* yields the best bits-per-microbit
right now, a genuine one-step-lookahead greedy, not the earlier version's
ratio of the whole remaining plan's total MI to only the first step's cost
-- front-loads queries to the object currently offering the better
immediate rate and visibly diverges from strict alternation. Both the
per-secret-pair interleave order and the full cross-run trace-order
distribution are reported so this is checkable directly, not asserted.

Method: two protected objects A and B, each with a uniform secret over its
own ``n_secrets`` candidates and its own copy of RQ2's exact balanced-DP
policy class (parameterized independently per object), share ONE
``DurableStore``/``ReferenceMonitor``/backend instance (one shared audit
log, matching a real multi-object workflow). Object B's candidate integers
are disjoint from A's (offset), which lets one shared synthetic backend
disambiguate which object a given query targets purely from the bucket
contents -- no core ``sluice_v2`` code is touched or needs to know about
"objects" at all; this is entirely experiment-harness machinery, exactly
like RQ2's own ``RevealBucketBackend``.

Every (secret_a, secret_b) pair in the full n_secrets_a x n_secrets_b
product is enumerated (not sampled). For each strategy, this experiment
verifies structurally that transcript_a is a function of secret_a alone
(invariant across all n_secrets_b paired secret_b values) before computing
its Shannon MI/Bayes vulnerability, and symmetrically for B; any
non-singleton "distinct transcripts observed for a fixed secret" would
itself be the finding (cross-object contamination), not a benign result to
average over. Isolated single-object baselines (RQ2's own ``run_config``,
no second object present at all) are computed once per object's own config
for reference.
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
sys.path.insert(0, str(HERE.parent))

from sluice_v2.monitor import (  # noqa: E402
    Backend,
    Direction,
    Outcome,
    ReferenceMonitor,
    Symbol,
    gate_cost_units,
)
from sluice_v2.store import (  # noqa: E402
    DurableStore,
    cap_bits_to_units,
    units_to_bits,
)

from rq2_bound_tightness import (  # noqa: E402
    POLICY_NAME,
    _bayes_bound,
    _probability,
    balanced_partition,
    balanced_sizes,
    make_balanced_policy,
    mutual_information_from_leaf_sizes,
    run_config as run_isolated_single_object_config,
    transcript_key,
)

STRATEGIES = ("round_robin", "greedy_immediate_bits_per_cost")
OBJECT_KEYS = ("A", "B")
REDACTED_PROVENANCE = "<redacted-for-anonymous-review>"

# The paper's revised configuration deliberately gives B an uneven
# three-way partition. Its observed bucket size can therefore change the
# greedy strategy's next public choice; unlike the historical divisible
# configuration, the default produces more than one greedy schedule.
DEFAULT_OBJECT_CONFIG = {
    "A": {"n_secrets": 16, "cap_bits": 6.0, "max_cardinality": 2},
    "B": {"n_secrets": 8, "cap_bits": 6.0, "max_cardinality": 3},
}


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


def _select_greedy_immediate_bits_per_cost(
    active_keys: list[str],
    objects: dict[str, dict[str, Any]],
    monitor: ReferenceMonitor,
    policies: dict[str, Any],
    cap_units_by_key: dict[str, int],
) -> str:
    """One-step lookahead: for each active object, look only at the single
    next query the policy would make (its own arity, its own immediate
    bits, its own immediate cost) and pick the best bits-per-microbit right
    now. This is deliberately not the whole remaining plan's total MI
    divided by only the first step's cost -- that ratio does not answer
    "which query is most efficient next," and produced identical
    schedules to round_robin under symmetric objects in an earlier version
    of this experiment."""
    best_key: Optional[str] = None
    best_score: Optional[tuple[float, int]] = None
    for key in active_keys:
        obj = objects[key]
        spent_units = monitor.spent_units(obj["protected_object"], 0)
        remaining_units = max(0, cap_units_by_key[key] - spent_units)
        plan = policies[key](len(obj["candidates"]), remaining_units)
        if plan.first_arity is None:
            continue
        sizes = balanced_sizes(len(obj["candidates"]), plan.first_arity)
        immediate_mi = mutual_information_from_leaf_sizes(len(obj["candidates"]), sizes)
        cost_units = gate_cost_units(plan.first_arity)
        score = (immediate_mi / cost_units, -cost_units)
        if best_score is None or score > best_score:
            best_key, best_score = key, score
    if best_key is None:
        return min(active_keys, key=lambda key: key)
    return best_key


def run_joint_pair(
    secret_a: int,
    secret_b: int,
    object_config: dict[str, dict[str, Any]],
    db_path: Path,
    policies: dict[str, Any],
    strategy: str,
    object_b_offset: int,
) -> dict[str, Any]:
    store = DurableStore(str(db_path))
    backend = MultiObjectBucketBackend(
        {"A": secret_a, "B": secret_b + object_b_offset}
    )
    max_cardinality_ceiling = max(
        object_config["A"]["max_cardinality"], object_config["B"]["max_cardinality"], 2
    )
    monitor = ReferenceMonitor(
        store,
        backend,
        default_cap_bits=max(object_config["A"]["cap_bits"], object_config["B"]["cap_bits"]),
        max_cardinality=max_cardinality_ceiling,
        trusted_planner_identities=frozenset({"trusted_release_planner"}),
    )
    cap_units_by_key = {
        key: cap_bits_to_units(object_config[key]["cap_bits"]) for key in OBJECT_KEYS
    }
    n_secrets_b = object_config["B"]["n_secrets"]
    objects: dict[str, dict[str, Any]] = {
        "A": {
            "protected_object": "rq2mo-object-A",
            "candidates": tuple(range(object_config["A"]["n_secrets"])),
            "transcript": [],
            "secret": secret_a,
            "active": True,
        },
        "B": {
            "protected_object": "rq2mo-object-B",
            "candidates": tuple(range(object_b_offset, object_b_offset + n_secrets_b)),
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
            elif strategy == "greedy_immediate_bits_per_cost":
                chosen = _select_greedy_immediate_bits_per_cost(
                    active_keys, objects, monitor, policies, cap_units_by_key
                )
            else:
                raise ValueError(f"unknown interleaving strategy {strategy!r}")

            obj = objects[chosen]
            protected_object = obj["protected_object"]
            spent_before_units = monitor.spent_units(protected_object, 0)
            remaining_units = max(0, cap_units_by_key[chosen] - spent_before_units)
            selected_plan = policies[chosen](len(obj["candidates"]), remaining_units)
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
                cap_bits=object_config[chosen]["cap_bits"],
                # UnsafeCompatibility experiment; excluded from complete-transcript claims.
                unsafe_allow_unauthenticated_caller=True,
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


def _trace_distribution(executions: list[dict[str, Any]]) -> dict[str, Any]:
    """Counts of the actual interleaving order observed (e.g. "AABB" vs
    "ABAB"), not just the final MI numbers -- the concrete, checkable
    evidence that a strategy's schedules differ from another's, rather
    than an assertion about them."""
    orders = Counter("".join(execution["interleave_order"]) for execution in executions)
    return {
        "n_distinct_orders": len(orders),
        "order_counts": dict(orders.most_common()),
    }


def run_strategy(
    strategy: str,
    object_config: dict[str, dict[str, Any]],
    temp_dir: Path,
) -> dict[str, Any]:
    policies = {
        key: make_balanced_policy(object_config[key]["max_cardinality"])
        for key in OBJECT_KEYS
    }
    n_secrets_a = object_config["A"]["n_secrets"]
    n_secrets_b = object_config["B"]["n_secrets"]
    object_b_offset = n_secrets_b * 1000
    executions = []
    for secret_a in range(n_secrets_a):
        for secret_b in range(n_secrets_b):
            executions.append(
                run_joint_pair(
                    secret_a,
                    secret_b,
                    object_config,
                    temp_dir / f"{strategy}-a{secret_a}-b{secret_b}.db",
                    policies,
                    strategy,
                    object_b_offset,
                )
            )

    summary_a = _marginal_summary(
        "A", "secret_a", "secret_b", "transcript_a_key",
        n_secrets_a, object_config["A"]["cap_bits"], executions,
    )
    summary_b = _marginal_summary(
        "B", "secret_b", "secret_a", "transcript_b_key",
        n_secrets_b, object_config["B"]["cap_bits"], executions,
    )
    return {
        "strategy": strategy,
        "n_joint_pairs": len(executions),
        "all_audit_linkage_checks_passed": all(
            execution["audit_linkage_valid"] for execution in executions
        ),
        "object_a": summary_a,
        "object_b": summary_b,
        "trace_distribution": _trace_distribution(executions),
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
    object_config: Optional[dict[str, dict[str, Any]]] = None,
    temp_root: Optional[str] = None,
    include_host_provenance: bool = False,
) -> dict[str, Any]:
    object_config = object_config or DEFAULT_OBJECT_CONFIG
    for key in OBJECT_KEYS:
        if object_config[key]["n_secrets"] < 2:
            raise ValueError(f"object {key}: n_secrets must be at least 2")
    if object_config["A"] == object_config["B"]:
        raise ValueError(
            "object_config['A'] == object_config['B']: this experiment exists "
            "specifically to test asymmetric objects; pass distinct configs "
            "(or use rq2_bound_tightness.py directly for a single-object study)"
        )

    started = time.time()
    with tempfile.TemporaryDirectory(prefix="sluice-rq2mo-", dir=temp_root) as temp:
        temp_dir = Path(temp)
        strategy_results = []
        for strategy in STRATEGIES:
            strategy_temp = temp_dir / strategy
            strategy_temp.mkdir()
            strategy_results.append(
                run_strategy(strategy, object_config, strategy_temp)
            )

        isolated_baselines = {}
        for key in OBJECT_KEYS:
            baseline_temp = temp_dir / f"isolated-baseline-{key}"
            baseline_temp.mkdir()
            cfg = object_config[key]
            isolated_baselines[key] = run_isolated_single_object_config(
                cfg["n_secrets"], cfg["cap_bits"], cfg["max_cardinality"], baseline_temp
            )
    finished = time.time()

    agreement = {}
    for key, obj_field in (("A", "object_a"), ("B", "object_b")):
        mi_values = {
            round(result[obj_field]["shannon"]["mutual_information_bits"], 9)
            for result in strategy_results
        }
        mi_values.add(round(isolated_baselines[key]["shannon"]["mutual_information_bits"], 9))
        v_values = {
            round(result[obj_field]["bayes"]["posterior_vulnerability"]["decimal"], 12)
            for result in strategy_results
        }
        v_values.add(
            round(isolated_baselines[key]["bayes"]["posterior_vulnerability"]["decimal"], 12)
        )
        agreement[key] = {
            "mutual_information_bits_match_across_strategies_and_baseline": len(mi_values) == 1,
            "posterior_vulnerability_match_across_strategies_and_baseline": len(v_values) == 1,
        }
    agreement["note"] = (
        "Objects A and B use different n_secrets/max_cardinality values "
        "(see config below); each object's own numbers are compared, "
        "per-object, against its own isolated single-object baseline "
        "computed with no second object present at all. Agreement here "
        "means marginal MI/vulnerability per object are invariant to "
        "interleaving strategy and to the second object's presence, not "
        "that the two objects' numbers match each other."
    )

    strategy_orders = {
        result["strategy"]: result["trace_distribution"] for result in strategy_results
    }
    schedules_identical_across_strategies = (
        len(STRATEGIES) > 1
        and len({frozenset(o["order_counts"].items()) for o in strategy_orders.values()}) == 1
    )

    return {
        "schema_version": "sluice.rq2_multiobject_interleaved.v3",
        "experiment_id": "rq2_multiobject_interleaved_adaptive_attacker",
        "motivation": (
            "Empirically test per-object accounting under two public "
            "interleavings. The uneven B partition makes the greedy schedule "
            "branch on a prior public B outcome; this does not test "
            "correlated-secret or joint-cap composition."
        ),
        "config": {"object_config": object_config, "policy": POLICY_NAME, "strategies": list(STRATEGIES)},
        "elapsed_seconds": finished - started,
        "provenance": {
            **_git_provenance(),
            "hostname": (
                platform.node() if include_host_provenance else REDACTED_PROVENANCE
            ),
            "python": sys.version,
            "started_at_unix": started,
            "finished_at_unix": finished,
        },
        "cross_strategy_agreement": agreement,
        "schedules_identical_across_strategies": schedules_identical_across_strategies,
        "isolated_single_object_baseline": isolated_baselines,
        "strategy_results": strategy_results,
    }


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n-secrets-a", type=int, default=DEFAULT_OBJECT_CONFIG["A"]["n_secrets"])
    parser.add_argument("--cap-bits-a", type=float, default=DEFAULT_OBJECT_CONFIG["A"]["cap_bits"])
    parser.add_argument("--max-cardinality-a", type=int, default=DEFAULT_OBJECT_CONFIG["A"]["max_cardinality"])
    parser.add_argument("--n-secrets-b", type=int, default=DEFAULT_OBJECT_CONFIG["B"]["n_secrets"])
    parser.add_argument("--cap-bits-b", type=float, default=DEFAULT_OBJECT_CONFIG["B"]["cap_bits"])
    parser.add_argument("--max-cardinality-b", type=int, default=DEFAULT_OBJECT_CONFIG["B"]["max_cardinality"])
    parser.add_argument("--temp-root")
    parser.add_argument(
        "--include-host-provenance",
        action="store_true",
        help="include the local hostname in output (off by default for anonymous review)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=HERE / "rq2_multiobject_interleaved_results.json",
    )
    args = parser.parse_args(argv)

    object_config = {
        "A": {
            "n_secrets": args.n_secrets_a,
            "cap_bits": args.cap_bits_a,
            "max_cardinality": args.max_cardinality_a,
        },
        "B": {
            "n_secrets": args.n_secrets_b,
            "cap_bits": args.cap_bits_b,
            "max_cardinality": args.max_cardinality_b,
        },
    }
    result = run_experiment(
        object_config=object_config,
        temp_root=args.temp_root,
        include_host_provenance=args.include_host_provenance,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    cfg = result["config"]["object_config"]
    print(
        f"A: {cfg['A']['n_secrets']} secrets, {cfg['A']['cap_bits']}b cap, "
        f"max_card={cfg['A']['max_cardinality']}  |  "
        f"B: {cfg['B']['n_secrets']} secrets, {cfg['B']['cap_bits']}b cap, "
        f"max_card={cfg['B']['max_cardinality']}"
    )
    print(
        f"{cfg['A']['n_secrets']}x{cfg['B']['n_secrets']} joint pairs, "
        f"{len(STRATEGIES)} strategies, in {result['elapsed_seconds']:.2f}s"
    )
    for strategy_result in result["strategy_results"]:
        obj_a = strategy_result["object_a"]
        obj_b = strategy_result["object_b"]
        print(
            f"strategy={strategy_result['strategy']:<28} "
            f"MI_A={obj_a['shannon']['mutual_information_bits']:.6f}b "
            f"MI_B={obj_b['shannon']['mutual_information_bits']:.6f}b "
            f"contamination_free={obj_a['cross_object_contamination_free'] and obj_b['cross_object_contamination_free']} "
            f"cap_holds={obj_a['shannon']['configured_cap_bound_holds'] and obj_b['shannon']['configured_cap_bound_holds']}"
        )
        print(f"  trace_distribution: {strategy_result['trace_distribution']['order_counts']}")
    print(f"schedules_identical_across_strategies: {result['schedules_identical_across_strategies']}")
    print(f"cross-strategy agreement: {result['cross_strategy_agreement']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
