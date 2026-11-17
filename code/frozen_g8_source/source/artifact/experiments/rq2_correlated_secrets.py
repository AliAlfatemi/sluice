"""RQ2 extension: asymmetric objects protecting a correlated (identical)
secret, and what pooling their transcripts reveals.

The paper's collusion corollary (Security Analysis, "Corollary: colluding
agents on one object") is careful to state what it does NOT cover: two
DIFFERENT protected objects whose secrets are statistically dependent.
Bounding I(S_A;T_A)<=B_A and I(S_B;T_B)<=B_B separately does not bound
I((S_A,S_B);(T_A,T_B)) when S_A and S_B are correlated, since mutual
information is not additive under correlation. RQ2's existing cross-object
experiment (``rq2_multiobject_interleaved.py``) only ever tests
INDEPENDENT secrets across A and B -- it cannot exhibit this gap because
there is nothing correlated to exploit. This experiment constructs the
gap directly and measures it, rather than only asserting it exists.

Design: two protected objects, A and B, asymmetric by construction --
different budgets (``cap_bits_a`` != ``cap_bits_b`` by default) and,
optionally, different cardinalities -- both bound to a single SHARED
secret M (S_A = S_B = M): the same underlying fact represented redundantly
across two objects, e.g. an account status mirrored into two different
protected records. Each object still only ever charges and enforces its
OWN cap on its OWN transcript (this experiment does not touch, and is not
testing, sluice_v2's mediation code -- only what an external observer who
pools two legitimately-authorized transcripts can compute). Two agents,
each individually authorized on exactly one object and therefore each
individually compliant with that object's own bound, are simulated as
colluding: their combined view is the PAIR (T_A, T_B).

For every M in range(n_secrets) (exhaustive, not sampled), this computes:
  - the MARGINAL Shannon MI and Bayes vulnerability of T_A alone and T_B
    alone against M (these must, and are checked to, respect each
    object's own configured cap -- confirming the ordinary per-object
    theorem still holds under this construction);
  - the JOINT Shannon MI and Bayes vulnerability of the PAIR (T_A, T_B)
    against M -- what a colluding pair of agents pooling their own
    individually-authorized observations actually learns about the
    shared secret.

What this is not: a claim that Sluice's mechanism is broken. Every
individual object's own bound holds throughout (verified below). What it
demonstrates is that "every object's own bound holds" does not imply "the
system's total exposure on a shared fact is bounded" when two objects are
about the same thing -- precisely the scope boundary Security Analysis and
Limitations already state in prose. This experiment turns that prose claim
into a checked number.
"""

from __future__ import annotations

import argparse
import json
import math
import platform
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path
from typing import Any, Sequence

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
    _bayes_bound,
    balanced_partition,
    make_balanced_policy,
    transcript_key,
)

OBJECT_KEYS = ("A", "B")


class MultiObjectBucketBackend(Backend):
    """Same disambiguation scheme as rq2_multiobject_interleaved.py's
    backend: A's and B's candidate integers are disjoint (B is offset), so
    which object a query targets is unambiguous from bucket contents alone
    -- no core sluice_v2 code is touched or needs to know about "objects."
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


def run_shared_secret_pair(
    shared_secret: int,
    n_secrets: int,
    cap_bits_a: float,
    cap_bits_b: float,
    max_cardinality: int,
    db_path: Path,
    policy,
    object_b_offset: int,
) -> dict[str, Any]:
    """Round-robin interleaving of two asymmetric-budget objects that both
    encode the same shared_secret. Round-robin (not the adaptive
    greedy-MI-per-unit-cost strategy) isolates the effect under study --
    asymmetric budgets on a correlated secret -- from a second, separate
    adaptive-choice effect RQ2's existing experiment already covers."""
    store = DurableStore(str(db_path))
    backend = MultiObjectBucketBackend(
        {"A": shared_secret, "B": shared_secret + object_b_offset}
    )
    monitor = ReferenceMonitor(
        store,
        backend,
        default_cap_bits=max(cap_bits_a, cap_bits_b),
        max_cardinality=max(max_cardinality, 2),
        trusted_planner_identities=frozenset({"trusted_release_planner"}),
    )
    cap_units_by_key = {
        "A": cap_bits_to_units(cap_bits_a),
        "B": cap_bits_to_units(cap_bits_b),
    }
    cap_bits_by_key = {"A": cap_bits_a, "B": cap_bits_b}
    objects: dict[str, dict[str, Any]] = {
        "A": {
            "protected_object": "rq2cs-object-A",
            "candidates": tuple(range(n_secrets)),
            "transcript": [],
            "secret": shared_secret,
            "active": True,
        },
        "B": {
            "protected_object": "rq2cs-object-B",
            "candidates": tuple(range(object_b_offset, object_b_offset + n_secrets)),
            "transcript": [],
            "secret": shared_secret + object_b_offset,
            "active": True,
        },
    }
    step = 0
    try:
        while any(objects[key]["active"] for key in OBJECT_KEYS):
            active_keys = [
                key
                for key in OBJECT_KEYS
                if objects[key]["active"] and len(objects[key]["candidates"]) > 1
            ]
            if not active_keys:
                break
            query_counts = {key: len(objects[key]["transcript"]) for key in OBJECT_KEYS}
            chosen = min(active_keys, key=lambda key: (query_counts[key], key))

            obj = objects[chosen]
            protected_object = obj["protected_object"]
            cap_units = cap_units_by_key[chosen]
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
                "rq2cs-workflow",
                protected_object,
                Direction.RELEASE,
                symbols,
                "trusted_release_planner",
                frozenset({"attacker"}),
                cap_bits=cap_bits_by_key[chosen],
                # UnsafeCompatibility experiment; excluded from complete-transcript claims.
                unsafe_allow_unauthenticated_caller=True,
            )
            query_json = json.dumps(buckets, sort_keys=True, separators=(",", ":"))
            observation = monitor.invoke(handle, query_json, "attacker")
            obj["transcript"].append(
                {"outcome": observation.outcome.value, "value": observation.value}
            )
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
        "shared_secret": shared_secret,
        "transcript_a": objects["A"]["transcript"],
        "transcript_a_key": transcript_key(objects["A"]["transcript"]),
        "transcript_b": objects["B"]["transcript"],
        "transcript_b_key": transcript_key(objects["B"]["transcript"]),
        "units_spent_a": spent_a,
        "units_spent_b": spent_b,
        "bits_spent_a": units_to_bits(spent_a),
        "bits_spent_b": units_to_bits(spent_b),
        "audit_linkage_valid": audit_linkage_valid,
    }


def _mi_and_vulnerability(
    n_secrets: int, keys_by_secret: dict[int, str]
) -> dict[str, float]:
    """Shannon MI and Bayes posterior vulnerability of a uniform n_secrets
    prior against an observable that partitions secrets into equivalence
    classes by transcript key -- shared by marginal and joint computations,
    the joint case simply using the PAIR (transcript_a_key, transcript_b_key)
    as one combined key."""
    counts = Counter(keys_by_secret.values())
    prior_entropy = math.log2(n_secrets)
    conditional_entropy = math.fsum(
        (count / n_secrets) * math.log2(count) for count in counts.values()
    )
    mutual_information = prior_entropy - conditional_entropy
    n_distinct = len(counts)
    return {
        "prior_entropy_bits": prior_entropy,
        "conditional_entropy_bits": conditional_entropy,
        "mutual_information_bits": mutual_information,
        "posterior_vulnerability": n_distinct / n_secrets,
        "n_distinct_observables": n_distinct,
    }


def run_config(
    n_secrets: int,
    cap_bits_a: float,
    cap_bits_b: float,
    max_cardinality: int,
    temp_dir: Path,
) -> dict[str, Any]:
    policy = make_balanced_policy(max_cardinality)
    object_b_offset = n_secrets * 1000
    executions = []
    for shared_secret in range(n_secrets):
        db_path = temp_dir / f"rq2cs-{shared_secret}.db"
        executions.append(
            run_shared_secret_pair(
                shared_secret,
                n_secrets,
                cap_bits_a,
                cap_bits_b,
                max_cardinality,
                db_path,
                policy,
                object_b_offset,
            )
        )
        db_path.unlink(missing_ok=True)

    if not all(execution["audit_linkage_valid"] for execution in executions):
        raise AssertionError("audit chain verification failed for at least one execution")

    keys_a = {execution["shared_secret"]: execution["transcript_a_key"] for execution in executions}
    keys_b = {execution["shared_secret"]: execution["transcript_b_key"] for execution in executions}
    keys_joint = {
        execution["shared_secret"]: (execution["transcript_a_key"], execution["transcript_b_key"])
        for execution in executions
    }

    marginal_a = _mi_and_vulnerability(n_secrets, keys_a)
    marginal_b = _mi_and_vulnerability(n_secrets, keys_b)
    joint = _mi_and_vulnerability(n_secrets, keys_joint)

    cap_units_a = cap_bits_to_units(cap_bits_a)
    cap_units_b = cap_bits_to_units(cap_bits_b)
    effective_cap_bits_a = units_to_bits(cap_units_a)
    effective_cap_bits_b = units_to_bits(cap_units_b)
    bound_a = min(marginal_a["prior_entropy_bits"], effective_cap_bits_a)
    bound_b = min(marginal_b["prior_entropy_bits"], effective_cap_bits_b)
    bayes_bound_a = _bayes_bound(effective_cap_bits_a, n_secrets)
    bayes_bound_b = _bayes_bound(effective_cap_bits_b, n_secrets)

    single_object_bound = max(bound_a, bound_b)
    additive_bound = bound_a + bound_b

    return {
        "n_secrets": n_secrets,
        "cap_bits_a": cap_bits_a,
        "cap_bits_b": cap_bits_b,
        "max_cardinality": max_cardinality,
        "marginal_a": {
            **marginal_a,
            "configured_cap_bound_bits": bound_a,
            "configured_cap_bound_holds": marginal_a["mutual_information_bits"]
            <= bound_a + 1e-9,
            "bayes_bound": bayes_bound_a,
            "bayes_bound_holds": marginal_a["posterior_vulnerability"]
            <= bayes_bound_a + 1e-9,
        },
        "marginal_b": {
            **marginal_b,
            "configured_cap_bound_bits": bound_b,
            "configured_cap_bound_holds": marginal_b["mutual_information_bits"]
            <= bound_b + 1e-9,
            "bayes_bound": bayes_bound_b,
            "bayes_bound_holds": marginal_b["posterior_vulnerability"]
            <= bayes_bound_b + 1e-9,
        },
        "joint_pooled": {
            **joint,
            "max_achieved_marginal_mi_bits": max(
                marginal_a["mutual_information_bits"],
                marginal_b["mutual_information_bits"],
            ),
            "collusion_gain_bits": joint["mutual_information_bits"]
            - max(
                marginal_a["mutual_information_bits"],
                marginal_b["mutual_information_bits"],
            ),
            "exceeds_larger_cap": joint["mutual_information_bits"]
            > single_object_bound + 1e-9,
            "exceeds_smaller_cap": joint["mutual_information_bits"]
            > min(bound_a, bound_b) + 1e-9,
            "smaller_cap_bits": min(bound_a, bound_b),
            "larger_cap_bits": single_object_bound,
            "within_additive_bound": joint["mutual_information_bits"]
            <= additive_bound + 1e-9,
            "additive_bound_bits": additive_bound,
        },
        "executions": executions,
    }


def _git_provenance(repo_root: Path) -> dict[str, Any]:
    def _run(*args: str) -> str:
        try:
            return subprocess.run(
                ["git", *args], cwd=repo_root, capture_output=True, text=True, check=False
            ).stdout.strip()
        except FileNotFoundError:
            return ""

    head = _run("rev-parse", "HEAD") or None
    status = _run("status", "--porcelain")
    return {"head": head, "dirty": bool(status) if head else None}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n-secrets", type=int, default=16)
    parser.add_argument("--cap-bits-a", type=float, default=4.0)
    parser.add_argument("--cap-bits-b", type=float, default=8.0)
    parser.add_argument("--max-cardinality", type=int, default=8)
    parser.add_argument("--out", type=str, required=True)
    args = parser.parse_args()

    repo_root = HERE.parent.parent.parent
    git = _git_provenance(repo_root)
    started = time.time()

    with tempfile.TemporaryDirectory(prefix="rq2cs-") as tmp:
        result = run_config(
            args.n_secrets,
            args.cap_bits_a,
            args.cap_bits_b,
            args.max_cardinality,
            Path(tmp),
        )

    elapsed = time.time() - started
    output = {
        "n_secrets": args.n_secrets,
        "cap_bits_a": args.cap_bits_a,
        "cap_bits_b": args.cap_bits_b,
        "max_cardinality": args.max_cardinality,
        "marginal_a": result["marginal_a"],
        "marginal_b": result["marginal_b"],
        "joint_pooled": result["joint_pooled"],
        "n_executions": len(result["executions"]),
        "elapsed_seconds": elapsed,
        "git": git,
        "python": platform.python_version(),
        "platform": platform.platform(),
    }
    Path(args.out).write_text(json.dumps(output, indent=2, sort_keys=True))
    print(json.dumps({k: v for k, v in output.items() if k != "executions"}, indent=2))


if __name__ == "__main__":
    main()
