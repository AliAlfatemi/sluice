"""Independent post-repair edge coverage for finite mixed QIF validation."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from fractions import Fraction

import pytest

from sluice_v2.qif_validation import (
    FiniteAdaptiveProcess,
    FiniteMixedAdaptiveProcess,
    MixedPublicEnvelope,
    MixedStepAuthorization,
    ProjectionCompletenessError,
    PublicEnvelope,
    QIFValidationError,
)


CHARGED = MixedStepAuthorization.CHARGED_FINITE
POSTPROCESS = MixedStepAuthorization.PUBLIC_HISTORY_POSTPROCESSING


def _deterministic(observation):
    return {observation: Fraction(1, 1)}


def test_all_charged_rare_history_charge_is_accumulated_before_float_conversion():
    rare = Fraction(1, 2**1075)
    prior = {0: Fraction(1, 2), 1: Fraction(1, 2)}
    envelopes = {
        (): PublicEnvelope(("rare", "common"), 1),
        ("rare",): PublicEnvelope(("same",), 2**63),
        ("common",): PublicEnvelope(("same",), 0),
    }
    kernels = {}
    for secret in prior:
        kernels[(secret, ())] = {"rare": rare, "common": 1 - rare}
        kernels[(secret, ("rare",))] = _deterministic("same")
        kernels[(secret, ("common",))] = _deterministic("same")

    report = FiniteAdaptiveProcess(
        prior=prior,
        max_steps=2,
        accounting_units_per_bit=1,
        envelopes=envelopes,
        kernels=kernels,
    ).validate()
    expected_rare_charge = float(Fraction(2**63, 2**1075))

    assert report.step_expected_charge_bits[1] == pytest.approx(
        expected_rare_charge, rel=1e-12, abs=0.0
    )
    assert report.step_expected_charge_bits[1] > 0.0


def test_mixed_typed_projection_distinguishes_boolean_and_integer_observations():
    process = FiniteMixedAdaptiveProcess(
        prior={"secret": 1},
        chronology_slots=("MONITOR_RESPONSE",),
        accounting_units_per_bit=1,
        envelopes={
            (): MixedPublicEnvelope(
                observable_kind="MONITOR_RESPONSE",
                authorization=POSTPROCESS,
                alphabet=(False,),
                charge_units=0,
            )
        },
        kernels={("secret", ()): _deterministic(0)},
    )

    with pytest.raises(ProjectionCompletenessError):
        process.validate()


def test_postprocessing_kernel_comparison_uses_only_posterior_supported_secrets():
    prior = {0: Fraction(1, 2), 1: Fraction(1, 2)}
    process = FiniteMixedAdaptiveProcess(
        prior=prior,
        chronology_slots=("CHARGED_EVENT", "PUBLIC_DECODE"),
        accounting_units_per_bit=1,
        envelopes={
            (): MixedPublicEnvelope(
                "CHARGED_EVENT", CHARGED, ("event:0", "event:1"), 1
            ),
            ("event:0",): MixedPublicEnvelope(
                "PUBLIC_DECODE", POSTPROCESS, ("decoded:0",), 0
            ),
            ("event:1",): MixedPublicEnvelope(
                "PUBLIC_DECODE", POSTPROCESS, ("decoded:1",), 0
            ),
        },
        kernels={
            (0, ()): _deterministic("event:0"),
            (1, ()): _deterministic("event:1"),
            (0, ("event:0",)): _deterministic("decoded:0"),
            (1, ("event:1",)): _deterministic("decoded:1"),
        },
    )

    report = process.validate()

    assert report.mutual_information_bits == pytest.approx(1.0)
    assert report.step_mutual_information_bits == pytest.approx((1.0, 0.0))
    assert report.postprocessing_history_checks == 2


def test_mixed_process_snapshots_envelopes_and_probability_mappings():
    envelope = MixedPublicEnvelope(
        "CHARGED_EVENT", CHARGED, ("event:0", "event:1"), 1
    )
    prior = {0: Fraction(1, 2), 1: Fraction(1, 2)}
    zero_distribution = _deterministic("event:0")
    one_distribution = _deterministic("event:1")
    process = FiniteMixedAdaptiveProcess(
        prior=prior,
        chronology_slots=("CHARGED_EVENT",),
        accounting_units_per_bit=1,
        envelopes={(): envelope},
        kernels={
            (0, ()): zero_distribution,
            (1, ()): one_distribution,
        },
    )

    object.__setattr__(envelope, "alphabet", ("event:0",))
    object.__setattr__(envelope, "charge_units", 0)
    prior[0] = Fraction(1, 1)
    zero_distribution["mutation"] = Fraction(1, 1)

    report = process.validate()

    assert report.mutual_information_bits == pytest.approx(1.0)
    assert report.expected_charge_bits == pytest.approx(1.0)


def test_public_evidence_field_omission_is_projection_incomplete():
    process = FiniteMixedAdaptiveProcess(
        prior={0: Fraction(1, 2), 1: Fraction(1, 2)},
        chronology_slots=("PUBLIC_EVIDENCE",),
        accounting_units_per_bit=1,
        envelopes={
            (): MixedPublicEnvelope(
                "PUBLIC_EVIDENCE",
                CHARGED,
                (("status:ok", "length:2", "evidence:declared"),),
                0,
            )
        },
        kernels={
            (0, ()): _deterministic(
                ("status:ok", "length:2", "evidence:declared")
            ),
            (1, ()): _deterministic(
                ("status:ok", "length:2", "evidence:omitted")
            ),
        },
    )

    with pytest.raises(ProjectionCompletenessError):
        process.validate()


def test_duplicated_control_request_cannot_fill_monitor_reply_slot():
    request = ("MODEL_CONTROL_REQUEST", "request:7")
    reply = ("MONITOR_RESPONSE", "request:7", "DOMAIN_CLOSED")
    process = FiniteMixedAdaptiveProcess(
        prior={"secret": 1},
        chronology_slots=("MODEL_CONTROL_REQUEST", "MONITOR_RESPONSE"),
        accounting_units_per_bit=1,
        envelopes={
            (): MixedPublicEnvelope(
                "MODEL_CONTROL_REQUEST", POSTPROCESS, (request,), 0
            ),
            (request,): MixedPublicEnvelope(
                "MONITOR_RESPONSE", POSTPROCESS, (reply,), 0
            ),
        },
        kernels={
            ("secret", ()): _deterministic(request),
            # Replaying the request in the reply position is an exact extra /
            # duplicated control observation, not a valid monitor response.
            ("secret", (request,)): _deterministic(request),
        },
    )

    with pytest.raises(ProjectionCompletenessError):
        process.validate()


class _ReportedOversizedPrior(Mapping):
    def __getitem__(self, key):
        if key == "only":
            return 1
        raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        return iter(("only",))

    def __len__(self) -> int:
        return 1_000_001


def test_declared_oversized_mapping_fails_before_iteration():
    with pytest.raises(QIFValidationError, match="entry bound"):
        FiniteMixedAdaptiveProcess(
            prior=_ReportedOversizedPrior(),
            chronology_slots=("ONE",),
            accounting_units_per_bit=1,
            envelopes={
                (): MixedPublicEnvelope("ONE", POSTPROCESS, ("same",), 0)
            },
            kernels={("only", ()): _deterministic("same")},
        )


def test_oversized_exact_probability_component_fails_closed():
    tiny = Fraction(1, 2**4097)
    with pytest.raises(QIFValidationError, match="exact-rational.*bound"):
        FiniteMixedAdaptiveProcess(
            prior={0: tiny, 1: 1 - tiny},
            chronology_slots=("ONE",),
            accounting_units_per_bit=1,
            envelopes={
                (): MixedPublicEnvelope("ONE", POSTPROCESS, ("same",), 0)
            },
            kernels={
                (0, ()): _deterministic("same"),
                (1, ()): _deterministic("same"),
            },
        )
