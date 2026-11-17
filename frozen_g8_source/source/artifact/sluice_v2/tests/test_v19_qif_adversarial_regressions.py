"""Independent adversarial regressions for the finite QIF validator.

This file intentionally lives separately from the implementation-owned v19
suite.  Each test records a contract edge found by the independent audit.
"""

from __future__ import annotations

from fractions import Fraction
import json
import math
import os
from pathlib import Path
import subprocess
import sys

import pytest

from sluice_v2.qif_validation import (
    FiniteAdaptiveProcess,
    PublicEnvelope,
    QIFValidationError,
)


def _deterministic(event):
    return {event: Fraction(1, 1)}


def test_extreme_exact_prior_does_not_overflow_float_ratio():
    # Both the prior and the true entropy are representable inputs/results.
    # The likelihood ratio 2**1024 is just beyond binary64, so converting the
    # ratio to float before taking its logarithm raises OverflowError.
    tiny = Fraction(1, 2**1024)
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

    assert math.isfinite(report.mutual_information_bits)
    assert report.mutual_information_bits > 0.0
    assert report.chain_rule_sum_bits == pytest.approx(
        report.mutual_information_bits, rel=1e-12, abs=0.0
    )


def test_process_snapshots_caller_owned_public_envelope():
    envelope = PublicEnvelope(("released:0", "released:1"), 1)
    process = FiniteAdaptiveProcess(
        prior={0: Fraction(1, 2), 1: Fraction(1, 2)},
        max_steps=1,
        accounting_units_per_bit=1,
        envelopes={(): envelope},
        kernels={
            (0, ()): _deterministic("released:0"),
            (1, ()): _deterministic("released:1"),
        },
    )

    # frozen=True blocks ordinary assignment but does not make retaining a
    # caller-owned object a snapshot.  An immutable process must copy the
    # envelope just as it already copies priors and kernel distributions.
    object.__setattr__(envelope, "alphabet", ("released:0",))
    object.__setattr__(envelope, "charge_units", 0)

    report = process.validate()

    assert report.mutual_information_bits == pytest.approx(1.0)
    assert report.expected_charge_bits == pytest.approx(1.0)


def test_nonreflexive_nan_is_rejected_as_a_malformed_finite_symbol():
    # A mathematical alphabet needs stable equality.  Python NaN is hashable
    # but non-reflexive, making set cardinality depend on object reuse rather
    # than on a well-defined symbol equivalence relation.
    with pytest.raises((TypeError, QIFValidationError)):
        PublicEnvelope((float("nan"),), 0)


def test_documented_driver_resolves_the_adjacent_artifact_package():
    artifact_root = Path(__file__).resolve().parents[2]
    driver = artifact_root / "experiments" / "validate_qif_finite.py"
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)

    completed = subprocess.run(
        [sys.executable, "-S", str(driver)],
        cwd=artifact_root,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert result["schema"] == "sluice.qif-finite-validation.v1"
    assert result["all_bounds_hold"] is True
