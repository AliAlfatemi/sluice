#!/usr/bin/env python3
"""Run deterministic finite-distribution checks for the transcript theorem."""

from __future__ import annotations

from fractions import Fraction
import hashlib
import json
from pathlib import Path
import sys


ARTIFACT_ROOT = Path(__file__).resolve().parents[1]
if str(ARTIFACT_ROOT) not in sys.path:
    sys.path.insert(0, str(ARTIFACT_ROOT))

from sluice_v2 import qif_validation
from sluice_v2.qif_validation import (
    FiniteAdaptiveProcess,
    ProjectionCompletenessError,
    PublicEnvelope,
    UnderchargedEnvelopeError,
)


def _deterministic(event):
    return {event: Fraction(1, 1)}


def _models() -> dict[str, FiniteAdaptiveProcess]:
    binary = FiniteAdaptiveProcess(
        prior={0: Fraction(1, 2), 1: Fraction(1, 2)},
        max_steps=1,
        accounting_units_per_bit=1,
        envelopes={(): PublicEnvelope(("released:0", "released:1"), 1)},
        kernels={
            (0, ()): _deterministic("released:0"),
            (1, ()): _deterministic("released:1"),
        },
    )

    vector_secrets = ((0, 0), (0, 1), (1, 0), (1, 1))
    adaptive_envelopes = {
        (): PublicEnvelope(("route-a", "route-b"), 1),
        ("route-a",): PublicEnvelope(("a:0", "a:1"), 1),
        ("route-b",): PublicEnvelope(("b:0", "b:1"), 1),
    }
    adaptive_kernels = {}
    for first, second in vector_secrets:
        route = "route-a" if first == 0 else "route-b"
        adaptive_kernels[((first, second), ())] = _deterministic(route)
        adaptive_kernels[((first, second), (route,))] = _deterministic(
            f"{'a' if first == 0 else 'b'}:{second}"
        )
    adaptive = FiniteAdaptiveProcess(
        prior={secret: Fraction(1, 4) for secret in vector_secrets},
        max_steps=2,
        accounting_units_per_bit=1,
        envelopes=adaptive_envelopes,
        kernels=adaptive_kernels,
    )

    correlated_prior = {(0, 0): Fraction(1, 2), (1, 1): Fraction(1, 2)}
    correlated_envelopes = {
        (): PublicEnvelope(("object-a:0", "object-a:1"), 1),
        ("object-a:0",): PublicEnvelope(("object-b:0", "object-b:1"), 1),
        ("object-a:1",): PublicEnvelope(("object-b:0", "object-b:1"), 1),
    }
    correlated_kernels = {}
    for secret in correlated_prior:
        first = f"object-a:{secret[0]}"
        correlated_kernels[(secret, ())] = _deterministic(first)
        correlated_kernels[(secret, (first,))] = _deterministic(
            f"object-b:{secret[1]}"
        )
    correlated = FiniteAdaptiveProcess(
        prior=correlated_prior,
        max_steps=2,
        accounting_units_per_bit=1,
        envelopes=correlated_envelopes,
        kernels=correlated_kernels,
    )

    lifecycle_outcomes = (
        "auth_denied",
        "route_denied",
        "stopped",
        "reauthorized",
    )
    lifecycle_envelopes = {(): PublicEnvelope(lifecycle_outcomes, 2)}
    lifecycle_kernels = {}
    for secret, outcome in enumerate(lifecycle_outcomes):
        lifecycle_kernels[(secret, ())] = _deterministic(outcome)
        lifecycle_envelopes[(outcome,)] = PublicEnvelope(("domain_closed",), 0)
        lifecycle_kernels[(secret, (outcome,))] = _deterministic("domain_closed")
    lifecycle = FiniteAdaptiveProcess(
        prior={secret: Fraction(1, 4) for secret in range(4)},
        max_steps=2,
        accounting_units_per_bit=1,
        envelopes=lifecycle_envelopes,
        kernels=lifecycle_kernels,
    )

    randomized = FiniteAdaptiveProcess(
        prior={0: Fraction(1, 2), 1: Fraction(1, 2)},
        max_steps=1,
        accounting_units_per_bit=1,
        envelopes={(): PublicEnvelope(("x", "y"), 1)},
        kernels={
            (0, ()): {"x": Fraction(3, 4), "y": Fraction(1, 4)},
            (1, ()): {"x": Fraction(1, 4), "y": Fraction(3, 4)},
        },
    )
    return {
        "adaptive_public_history": adaptive,
        "correlated_secret_vector": correlated,
        "denial_stop_reauthorization": lifecycle,
        "randomized_channel": randomized,
        "tight_binary_release": binary,
    }


def _counterexamples() -> dict[str, str]:
    free_route = FiniteAdaptiveProcess(
        prior={0: Fraction(1, 2), 1: Fraction(1, 2)},
        max_steps=1,
        accounting_units_per_bit=1,
        envelopes={(): PublicEnvelope(("route-a", "route-b"), 0)},
        kernels={
            (0, ()): _deterministic("route-a"),
            (1, ()): _deterministic("route-b"),
        },
    )
    omitted_field = FiniteAdaptiveProcess(
        prior={0: Fraction(1, 2), 1: Fraction(1, 2)},
        max_steps=1,
        accounting_units_per_bit=1,
        envelopes={(): PublicEnvelope((("ok", "caller-a"),), 0)},
        kernels={
            (0, ()): _deterministic(("ok", "caller-a")),
            (1, ()): _deterministic(("ok", "caller-b")),
        },
    )
    rejected: dict[str, str] = {}
    for name, process, expected in (
        ("free_secret_route", free_route, UnderchargedEnvelopeError),
        ("omitted_observer_field", omitted_field, ProjectionCompletenessError),
    ):
        try:
            process.validate()
        except expected as exc:
            rejected[name] = type(exc).__name__
        else:
            raise AssertionError(f"legacy counterexample {name} was accepted")
    return rejected


def main() -> int:
    models = {}
    for name, process in _models().items():
        report = process.validate()
        models[name] = {
            "mutual_information_bits": report.mutual_information_bits,
            "chain_rule_sum_bits": report.chain_rule_sum_bits,
            "expected_declared_support_bits": (
                report.expected_declared_support_bits
            ),
            "expected_charge_bits": report.expected_charge_bits,
            "maximum_path_charge_bits": str(report.maximum_path_charge_bits),
            "step_mutual_information_bits": list(
                report.step_mutual_information_bits
            ),
            "reachable_histories_by_step": list(
                report.reachable_histories_by_step
            ),
            "bound_holds": (
                report.mutual_information_bits
                <= report.expected_charge_bits + 1e-10
            ),
        }
    module_path = Path(qif_validation.__file__).resolve()
    result = {
        "schema": "sluice.qif-finite-validation.v1",
        "module_sha256": hashlib.sha256(module_path.read_bytes()).hexdigest(),
        "models": models,
        "rejected_legacy_counterexamples": _counterexamples(),
        "all_bounds_hold": all(model["bound_holds"] for model in models.values()),
        "evidence_boundary": (
            "exact finite-probability enumeration; not a proof for arbitrary "
            "distributions and not evidence that an external deployment exposes "
            "only the declared observer projection"
        ),
    }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
