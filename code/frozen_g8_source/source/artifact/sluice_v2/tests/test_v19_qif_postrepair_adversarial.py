"""Independent post-repair regressions for the finite QIF validator."""

from __future__ import annotations

from fractions import Fraction
import math

import pytest

from sluice_v2.qif_validation import (
    FiniteAdaptiveProcess,
    ProjectionCompletenessError,
    PublicEnvelope,
)


def _deterministic(event):
    return {event: Fraction(1, 1)}


def test_complete_projection_distinguishes_boolean_from_integer_symbol():
    # Boolean false and integer zero are different typed JSON values, but
    # Python set/dict equality aliases them.  An exact-symbol validator must
    # not accept an integer emitted under a Boolean-only public envelope.
    process = FiniteAdaptiveProcess(
        prior={"secret": Fraction(1, 1)},
        max_steps=1,
        accounting_units_per_bit=1,
        envelopes={(): PublicEnvelope((False,), 0)},
        kernels={("secret", ()): _deterministic(0)},
    )

    with pytest.raises(ProjectionCompletenessError):
        process.validate()


def test_subnormal_exact_prior_retains_representable_entropy_contribution():
    # float(2**-1075) rounds to zero, but 1075 * 2**-1075 is a positive,
    # representable subnormal.  Multiplying float(joint) by the log therefore
    # silently loses information that a scaled/log-domain calculation retains.
    tiny = Fraction(1, 2**1075)
    process = FiniteAdaptiveProcess(
        prior={0: tiny, 1: 1 - tiny},
        max_steps=1,
        accounting_units_per_bit=1,
        envelopes={(): PublicEnvelope(("released:0", "released:1"), 1)},
        kernels={
            (0, ()): _deterministic("released:0"),
            (1, ()): _deterministic("released:1"),
        },
    )

    report = process.validate()
    rare_entropy_term = float(tiny * 1075)

    assert rare_entropy_term > 0.0
    assert math.isfinite(report.mutual_information_bits)
    assert report.mutual_information_bits >= rare_entropy_term
    assert report.chain_rule_sum_bits >= rare_entropy_term
