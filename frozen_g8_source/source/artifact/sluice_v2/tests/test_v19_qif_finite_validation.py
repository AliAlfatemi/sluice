"""Finite-distribution checks for the complete-transcript QIF theorem.

These tests enumerate exact rational joint distributions and then compare the
computed mutual information with the declared support and charged envelope.
They do not treat enumeration as a proof for arbitrary distributions.
"""

from __future__ import annotations

from fractions import Fraction
import math

import pytest

from sluice_v2.qif_validation import (
    FiniteAdaptiveProcess,
    ProjectionCompletenessError,
    PublicEnvelope,
    QIFValidationError,
    UnderchargedEnvelopeError,
    minimum_charge_units,
)


def _deterministic(event):
    return {event: Fraction(1, 1)}


def test_tight_binary_release_reaches_one_bit_bound():
    process = FiniteAdaptiveProcess(
        prior={0: Fraction(1, 2), 1: Fraction(1, 2)},
        max_steps=1,
        accounting_units_per_bit=1,
        envelopes={(): PublicEnvelope(("released:0", "released:1"), 1)},
        kernels={
            (0, ()): _deterministic("released:0"),
            (1, ()): _deterministic("released:1"),
        },
    )

    report = process.validate()

    assert report.mutual_information_bits == pytest.approx(1.0)
    assert report.chain_rule_sum_bits == pytest.approx(1.0)
    assert report.expected_declared_support_bits == pytest.approx(1.0)
    assert report.expected_charge_bits == pytest.approx(1.0)
    assert report.maximum_path_charge_bits == 1


def test_adaptive_public_history_scheduler_needs_no_independence_assumption():
    secrets = ((0, 0), (0, 1), (1, 0), (1, 1))
    prior = {secret: Fraction(1, 4) for secret in secrets}
    envelopes = {
        (): PublicEnvelope(("route-a", "route-b"), 1),
        ("route-a",): PublicEnvelope(("a:0", "a:1"), 1),
        ("route-b",): PublicEnvelope(("b:0", "b:1"), 1),
    }
    kernels = {}
    for first, second in secrets:
        route = "route-a" if first == 0 else "route-b"
        kernels[((first, second), ())] = _deterministic(route)
        value = f"{'a' if route == 'route-a' else 'b'}:{second}"
        kernels[((first, second), (route,))] = _deterministic(value)

    report = FiniteAdaptiveProcess(
        prior=prior,
        max_steps=2,
        accounting_units_per_bit=1,
        envelopes=envelopes,
        kernels=kernels,
    ).validate()

    assert report.step_mutual_information_bits == pytest.approx((1.0, 1.0))
    assert report.mutual_information_bits == pytest.approx(2.0)
    assert report.expected_charge_bits == pytest.approx(2.0)


def test_correlated_objects_are_bounded_once_by_the_shared_domain_transcript():
    # The second object is perfectly correlated with the first.  Two releases
    # cost two bits, but together reveal only one bit about the secret vector.
    prior = {(0, 0): Fraction(1, 2), (1, 1): Fraction(1, 2)}
    envelopes = {
        (): PublicEnvelope(("object-a:0", "object-a:1"), 1),
        ("object-a:0",): PublicEnvelope(("object-b:0", "object-b:1"), 1),
        ("object-a:1",): PublicEnvelope(("object-b:0", "object-b:1"), 1),
    }
    kernels = {}
    for secret in prior:
        first = f"object-a:{secret[0]}"
        second = f"object-b:{secret[1]}"
        kernels[(secret, ())] = _deterministic(first)
        kernels[(secret, (first,))] = _deterministic(second)

    report = FiniteAdaptiveProcess(
        prior=prior,
        max_steps=2,
        accounting_units_per_bit=1,
        envelopes=envelopes,
        kernels=kernels,
    ).validate()

    assert report.mutual_information_bits == pytest.approx(1.0)
    assert report.step_mutual_information_bits == pytest.approx((1.0, 0.0))
    assert report.expected_charge_bits == pytest.approx(2.0)


def test_colluding_observer_union_is_validated_as_one_transcript():
    secrets = ((0, 0), (0, 1), (1, 0), (1, 1))
    prior = {secret: Fraction(1, 4) for secret in secrets}
    envelopes = {(): PublicEnvelope(("agent-a:0", "agent-a:1"), 1)}
    kernels = {}
    for secret in secrets:
        first = f"agent-a:{secret[0]}"
        envelopes[(first,)] = PublicEnvelope(("agent-b:0", "agent-b:1"), 1)
        kernels[(secret, ())] = _deterministic(first)
        kernels[(secret, (first,))] = _deterministic(f"agent-b:{secret[1]}")

    report = FiniteAdaptiveProcess(
        prior=prior,
        max_steps=2,
        accounting_units_per_bit=1,
        envelopes=envelopes,
        kernels=kernels,
    ).validate()

    assert report.mutual_information_bits == pytest.approx(2.0)
    assert report.maximum_path_charge_bits == 2


def test_denial_stop_and_reauthorization_are_ordinary_charged_symbols():
    outcomes = ("auth_denied", "route_denied", "stopped", "reauthorized")
    prior = {index: Fraction(1, 4) for index in range(4)}
    envelopes = {(): PublicEnvelope(outcomes, 2)}
    kernels = {}
    for secret, outcome in enumerate(outcomes):
        kernels[(secret, ())] = _deterministic(outcome)
        envelopes[(outcome,)] = PublicEnvelope(("domain_closed",), 0)
        kernels[(secret, (outcome,))] = _deterministic("domain_closed")
        envelopes[(outcome, "domain_closed")] = PublicEnvelope(
            ("domain_closed",), 0
        )
        kernels[(secret, (outcome, "domain_closed"))] = _deterministic(
            "domain_closed"
        )

    report = FiniteAdaptiveProcess(
        prior=prior,
        max_steps=3,
        accounting_units_per_bit=1,
        envelopes=envelopes,
        kernels=kernels,
    ).validate()

    assert report.mutual_information_bits == pytest.approx(2.0)
    assert report.step_mutual_information_bits == pytest.approx((2.0, 0.0, 0.0))
    assert report.expected_charge_bits == pytest.approx(2.0)
    assert report.maximum_path_charge_bits == 2


def test_randomized_channel_reconciles_chain_rule_exact_probability_model():
    process = FiniteAdaptiveProcess(
        prior={0: Fraction(1, 2), 1: Fraction(1, 2)},
        max_steps=1,
        accounting_units_per_bit=1,
        envelopes={(): PublicEnvelope(("x", "y"), 1)},
        kernels={
            (0, ()): {"x": Fraction(3, 4), "y": Fraction(1, 4)},
            (1, ()): {"x": Fraction(1, 4), "y": Fraction(3, 4)},
        },
    )

    report = process.validate()

    expected = 1.0 - (-(0.75 * math.log2(0.75) + 0.25 * math.log2(0.25)))
    assert report.mutual_information_bits == pytest.approx(expected)
    assert report.chain_rule_sum_bits == pytest.approx(expected)
    assert report.mutual_information_bits < report.expected_charge_bits


def test_scaled_minimum_charge_is_exact_at_and_around_power_of_two():
    assert minimum_charge_units(1, 1_000_000) == 0
    assert minimum_charge_units(2, 1_000_000) == 1_000_000
    assert minimum_charge_units(3, 1_000_000) == 1_584_963
    assert minimum_charge_units(4, 1_000_000) == 2_000_000


def test_old_free_route_leak_is_rejected_as_undercharged():
    process = FiniteAdaptiveProcess(
        prior={0: Fraction(1, 2), 1: Fraction(1, 2)},
        max_steps=1,
        accounting_units_per_bit=1,
        envelopes={(): PublicEnvelope(("route-a", "route-b"), 0)},
        kernels={
            (0, ()): _deterministic("route-a"),
            (1, ()): _deterministic("route-b"),
        },
    )

    with pytest.raises(UnderchargedEnvelopeError, match="support|charge"):
        process.validate()


def test_omitted_caller_or_argument_field_fails_projection_completeness():
    # The declared result-only alphabet says there is one public symbol, but
    # the actual observer sees a secret-dependent caller/argument field.
    process = FiniteAdaptiveProcess(
        prior={0: Fraction(1, 2), 1: Fraction(1, 2)},
        max_steps=1,
        accounting_units_per_bit=1,
        envelopes={(): PublicEnvelope((("ok", "caller-a"),), 0)},
        kernels={
            (0, ()): _deterministic(("ok", "caller-a")),
            (1, ()): _deterministic(("ok", "caller-b")),
        },
    )

    with pytest.raises(ProjectionCompletenessError, match="outside|complete"):
        process.validate()


def test_free_secret_dependent_denial_is_rejected_on_first_probe():
    process = FiniteAdaptiveProcess(
        prior={0: Fraction(1, 2), 1: Fraction(1, 2)},
        max_steps=1,
        accounting_units_per_bit=1,
        envelopes={(): PublicEnvelope(("denied-a", "denied-b"), 0)},
        kernels={
            (0, ()): _deterministic("denied-a"),
            (1, ()): _deterministic("denied-b"),
        },
    )

    with pytest.raises(UnderchargedEnvelopeError):
        process.validate()


def test_missing_reachable_kernel_and_nonfinite_horizon_fail_closed():
    with pytest.raises(QIFValidationError, match="max_steps"):
        FiniteAdaptiveProcess(
            prior={0: 1},
            max_steps=0,
            accounting_units_per_bit=1,
            envelopes={(): PublicEnvelope(("x",), 0)},
            kernels={(0, ()): _deterministic("x")},
        )

    process = FiniteAdaptiveProcess(
        prior={0: Fraction(1, 2), 1: Fraction(1, 2)},
        max_steps=1,
        accounting_units_per_bit=1,
        envelopes={(): PublicEnvelope(("x",), 0)},
        kernels={(0, ()): _deterministic("x")},
    )
    with pytest.raises(QIFValidationError, match="missing kernel"):
        process.validate()


def test_constructor_snapshots_external_probability_mappings():
    prior = {0: Fraction(1, 2), 1: Fraction(1, 2)}
    distribution = {"x": Fraction(1, 1)}
    kernels = {(0, ()): distribution, (1, ()): distribution}
    process = FiniteAdaptiveProcess(
        prior=prior,
        max_steps=1,
        accounting_units_per_bit=1,
        envelopes={(): PublicEnvelope(("x",), 0)},
        kernels=kernels,
    )
    prior[0] = Fraction(1, 1)
    distribution["leak"] = Fraction(1, 1)

    report = process.validate()

    assert report.mutual_information_bits == pytest.approx(0.0)
    assert report.expected_charge_bits == pytest.approx(0.0)
