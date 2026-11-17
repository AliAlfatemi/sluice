"""Independent fail-first probes for the mixed QIF finite validator.

These regressions were written against the frozen candidate hashes before the
repair.  They cover typed secret identity and exact rare-history accounting;
they do not assert any live-deployment premise.
"""

from __future__ import annotations

from fractions import Fraction

import pytest

from sluice_v2.qif_validation import (
    FiniteAdaptiveProcess,
    FiniteMixedAdaptiveProcess,
    MixedPublicEnvelope,
    MixedStepAuthorization,
    PublicEnvelope,
    QIFValidationError,
)


CHARGED = MixedStepAuthorization.CHARGED_FINITE
POSTPROCESS = MixedStepAuthorization.PUBLIC_HISTORY_POSTPROCESSING


def _deterministic(observation):
    return {observation: Fraction(1, 1)}


def test_all_charged_rejects_bool_integer_secret_key_alias():
    # False and integer zero are distinct typed JSON values.  A kernel keyed
    # by integer zero must not satisfy a prior whose typed support says False.
    with pytest.raises(QIFValidationError, match="secret|typed|prior"):
        FiniteAdaptiveProcess(
            prior={False: Fraction(1, 2), "other": Fraction(1, 2)},
            max_steps=1,
            accounting_units_per_bit=1,
            envelopes={(): PublicEnvelope(("false", "other"), 1)},
            kernels={
                (0, ()): _deterministic("false"),
                ("other", ()): _deterministic("other"),
            },
        )


def test_mixed_rejects_bool_integer_secret_key_alias():
    with pytest.raises(QIFValidationError, match="secret|typed|prior"):
        FiniteMixedAdaptiveProcess(
            prior={False: Fraction(1, 2), "other": Fraction(1, 2)},
            chronology_slots=("CHARGED_EVENT",),
            accounting_units_per_bit=1,
            envelopes={
                (): MixedPublicEnvelope(
                    observable_kind="CHARGED_EVENT",
                    authorization=CHARGED,
                    alphabet=("false", "other"),
                    charge_units=1,
                )
            },
            kernels={
                (0, ()): _deterministic("false"),
                ("other", ()): _deterministic("other"),
            },
        )


def _rare_history_process(charge_units: int) -> FiniteMixedAdaptiveProcess:
    rare = Fraction(1, 2**1075)
    prior = {0: Fraction(1, 2), 1: Fraction(1, 2)}
    envelopes = {
        (): MixedPublicEnvelope(
            observable_kind="PUBLIC_RANDOM_BRANCH",
            authorization=POSTPROCESS,
            alphabet=("rare", "common"),
            charge_units=0,
        ),
        ("rare",): MixedPublicEnvelope(
            observable_kind="CHARGED_EVENT",
            authorization=CHARGED,
            alphabet=("same",),
            charge_units=charge_units,
        ),
        ("common",): MixedPublicEnvelope(
            observable_kind="CHARGED_EVENT",
            authorization=CHARGED,
            alphabet=("same",),
            charge_units=0,
        ),
    }
    kernels = {}
    for secret in prior:
        kernels[(secret, ())] = {"rare": rare, "common": 1 - rare}
        kernels[(secret, ("rare",))] = _deterministic("same")
        kernels[(secret, ("common",))] = _deterministic("same")
    return FiniteMixedAdaptiveProcess(
        prior=prior,
        chronology_slots=("PUBLIC_RANDOM_BRANCH", "CHARGED_EVENT"),
        accounting_units_per_bit=1,
        envelopes=envelopes,
        kernels=kernels,
    )


def test_rare_history_expected_charge_retains_representable_subnormal_product():
    # float(2**-1075) is zero, but 2**-1075 * 2**63 = 2**-1012 is
    # representable.  Exact accumulation must occur before the final float.
    report = _rare_history_process(2**63).validate()
    expected = float(Fraction(2**63, 2**1075))

    assert expected > 0.0
    assert report.step_expected_charge_bits == pytest.approx(
        (0.0, expected), rel=1e-12, abs=0.0
    )
    assert report.expected_charge_bits == pytest.approx(
        expected, rel=1e-12, abs=0.0
    )


def test_unrepresentable_charge_fails_closed_as_qif_validation_error():
    # The public report uses bounded binary64 fields.  Inputs whose reachable
    # charge cannot be represented must fail in the validator's error domain,
    # not escape as an implementation OverflowError.
    with pytest.raises(QIFValidationError, match="charge|represent|bound"):
        _rare_history_process(2**1075).validate()
