"""Exact finite checks for the mixed chronological QIF corollary.

The validator works on one fixed public-state fiber.  These models exercise
charged finite events interleaved with authenticated public-history
post-processing.  They are finite-model evidence, not deployment evidence.
"""

from __future__ import annotations

from fractions import Fraction
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from sluice_v2.qif_validation import (
    ChronologyCompletenessError,
    FiniteAdaptiveProcess,
    FiniteMixedAdaptiveProcess,
    MixedPublicEnvelope,
    MixedStepAuthorization,
    PostprocessingIndependenceError,
    ProjectionCompletenessError,
    PublicEnvelope,
    UnderchargedEnvelopeError,
)


CHARGED = MixedStepAuthorization.CHARGED_FINITE
POSTPROCESS = MixedStepAuthorization.PUBLIC_HISTORY_POSTPROCESSING


def _deterministic(observation):
    return {observation: Fraction(1, 1)}


def _envelope(kind, authorization, alphabet, charge=0):
    return MixedPublicEnvelope(
        observable_kind=kind,
        authorization=authorization,
        alphabet=alphabet,
        charge_units=charge,
    )


def test_xor_counterexample_refutes_old_event_only_equality_but_meets_bound():
    # S and the fresh post-processing random bit R are independent.  The free
    # output is Z=R; the later charged event is E=S xor R.  E alone is
    # independent of S, but the complete chronological view (Z,E) reveals S.
    prior = {0: Fraction(1, 2), 1: Fraction(1, 2)}
    envelopes = {
        (): _envelope(
            "C1_PAYLOAD", POSTPROCESS, ("z:0", "z:1")
        )
    }
    kernels = {}
    for secret in prior:
        kernels[(secret, ())] = {
            "z:0": Fraction(1, 2),
            "z:1": Fraction(1, 2),
        }
        for random_bit in (0, 1):
            z = f"z:{random_bit}"
            envelopes[(z,)] = _envelope(
                "CHARGED_TRANSCRIPT_EVENT", CHARGED, ("e:0", "e:1"), 1
            )
            kernels[(secret, (z,))] = _deterministic(
                f"e:{secret ^ random_bit}"
            )

    report = FiniteMixedAdaptiveProcess(
        prior=prior,
        chronology_slots=("C1_PAYLOAD", "CHARGED_TRANSCRIPT_EVENT"),
        accounting_units_per_bit=1,
        envelopes=envelopes,
        kernels=kernels,
    ).validate()
    event_only = FiniteAdaptiveProcess(
        prior=prior,
        max_steps=1,
        accounting_units_per_bit=1,
        envelopes={(): PublicEnvelope(("e:0", "e:1"), 1)},
        kernels={
            (secret, ()): {"e:0": Fraction(1, 2), "e:1": Fraction(1, 2)}
            for secret in prior
        },
    ).validate()

    assert event_only.mutual_information_bits == pytest.approx(0.0)
    assert report.mutual_information_bits == pytest.approx(1.0)
    assert report.step_mutual_information_bits == pytest.approx((0.0, 1.0))
    assert report.expected_charge_bits == pytest.approx(1.0)
    assert report.maximum_path_charge_bits == 1


def test_adaptive_randomized_postprocessing_has_zero_incremental_information():
    # The post-processing distribution adapts to the prior charged group, but
    # is identical for both secrets remaining possible at that public prefix.
    prior = {secret: Fraction(1, 4) for secret in range(4)}
    envelopes = {
        (): _envelope(
            "CHARGED_TRANSCRIPT_EVENT", CHARGED, ("group:a", "group:b"), 1
        )
    }
    kernels = {}
    random_kernels = {
        "group:a": {"coin:a0": Fraction(1, 3), "coin:a1": Fraction(2, 3)},
        "group:b": {"coin:b0": Fraction(3, 4), "coin:b1": Fraction(1, 4)},
    }
    for secret in prior:
        group = "group:a" if secret < 2 else "group:b"
        kernels[(secret, ())] = _deterministic(group)
        envelopes[(group,)] = _envelope(
            "MODEL_CONTROL_REQUEST",
            POSTPROCESS,
            tuple(random_kernels[group]),
        )
        kernels[(secret, (group,))] = random_kernels[group]
        for coin in random_kernels[group]:
            history = (group, coin)
            envelopes[history] = _envelope(
                "CHARGED_TRANSCRIPT_EVENT", CHARGED, ("low:0", "low:1"), 1
            )
            kernels[(secret, history)] = _deterministic(f"low:{secret % 2}")

    report = FiniteMixedAdaptiveProcess(
        prior=prior,
        chronology_slots=(
            "CHARGED_TRANSCRIPT_EVENT",
            "MODEL_CONTROL_REQUEST",
            "CHARGED_TRANSCRIPT_EVENT",
        ),
        accounting_units_per_bit=1,
        envelopes=envelopes,
        kernels=kernels,
    ).validate()

    assert report.step_mutual_information_bits == pytest.approx((1.0, 0.0, 1.0))
    assert report.mutual_information_bits == pytest.approx(2.0)
    assert report.expected_charge_bits == pytest.approx(2.0)
    assert report.postprocessing_history_checks == 2


def test_deterministic_postprocessing_is_the_event_only_equality_special_case():
    prior = {0: Fraction(1, 2), 1: Fraction(1, 2)}
    envelopes = {
        (): _envelope(
            "CHARGED_TRANSCRIPT_EVENT", CHARGED, ("e:0", "e:1"), 1
        ),
        ("e:0",): _envelope("C2_PAYLOAD", POSTPROCESS, ("decoded:0",)),
        ("e:1",): _envelope("C2_PAYLOAD", POSTPROCESS, ("decoded:1",)),
    }
    kernels = {
        (0, ()): _deterministic("e:0"),
        (1, ()): _deterministic("e:1"),
        (0, ("e:0",)): _deterministic("decoded:0"),
        (1, ("e:1",)): _deterministic("decoded:1"),
    }

    report = FiniteMixedAdaptiveProcess(
        prior=prior,
        chronology_slots=("CHARGED_TRANSCRIPT_EVENT", "C2_PAYLOAD"),
        accounting_units_per_bit=1,
        envelopes=envelopes,
        kernels=kernels,
    ).validate()

    assert report.step_mutual_information_bits == pytest.approx((1.0, 0.0))
    assert report.mutual_information_bits == pytest.approx(1.0)
    assert report.expected_charge_bits == pytest.approx(1.0)


def test_secret_dependent_randomness_cannot_be_labeled_postprocessing():
    process = FiniteMixedAdaptiveProcess(
        prior={0: Fraction(1, 2), 1: Fraction(1, 2)},
        chronology_slots=("C3_PAYLOAD",),
        accounting_units_per_bit=1,
        envelopes={(): _envelope("C3_PAYLOAD", POSTPROCESS, ("z:0", "z:1"))},
        kernels={
            (0, ()): {"z:0": Fraction(3, 4), "z:1": Fraction(1, 4)},
            (1, ()): {"z:0": Fraction(1, 4), "z:1": Fraction(3, 4)},
        },
    )

    with pytest.raises(PostprocessingIndependenceError, match="secret|history"):
        process.validate()


def test_omitted_or_reordered_control_and_monitor_reply_fail_closed():
    omitted_reply = FiniteMixedAdaptiveProcess(
        prior={0: Fraction(1, 2), 1: Fraction(1, 2)},
        chronology_slots=("MODEL_CONTROL_REQUEST", "MONITOR_RESPONSE"),
        accounting_units_per_bit=1,
        envelopes={
            (): _envelope(
                "MODEL_CONTROL_REQUEST", POSTPROCESS, ("request:continue",)
            )
        },
        kernels={
            (0, ()): _deterministic("request:continue"),
            (1, ()): _deterministic("request:continue"),
        },
    )
    with pytest.raises(ChronologyCompletenessError, match="missing|slot"):
        omitted_reply.validate()

    with pytest.raises(ChronologyCompletenessError, match="kind|slot"):
        FiniteMixedAdaptiveProcess(
            prior={0: 1},
            chronology_slots=("MODEL_CONTROL_REQUEST",),
            accounting_units_per_bit=1,
            envelopes={
                (): _envelope(
                    "MONITOR_RESPONSE", POSTPROCESS, ("DOMAIN_CLOSED",)
                )
            },
            kernels={(0, ()): _deterministic("DOMAIN_CLOSED")},
        )


def test_response_status_length_outside_projection_is_rejected():
    process = FiniteMixedAdaptiveProcess(
        prior={0: 1},
        chronology_slots=("MONITOR_RESPONSE",),
        accounting_units_per_bit=1,
        envelopes={
            (): _envelope(
                "MONITOR_RESPONSE",
                POSTPROCESS,
                (("DOMAIN_CLOSED", "length:0"),),
            )
        },
        kernels={
            (0, ()): _deterministic(("DOMAIN_CLOSED", "length:17"))
        },
    )

    with pytest.raises(ProjectionCompletenessError, match="outside|chronology"):
        process.validate()


def test_cached_domain_closed_is_a_separate_captured_monitor_response():
    observations = (
        "request:continue",
        ("DOMAIN_CLOSED", "fresh", "length:0"),
        "request:retry",
        ("DOMAIN_CLOSED", "cached", "length:0"),
    )
    kinds = (
        "MODEL_CONTROL_REQUEST",
        "MONITOR_RESPONSE",
        "MODEL_CONTROL_REQUEST",
        "MONITOR_RESPONSE",
    )
    prior = {0: Fraction(1, 2), 1: Fraction(1, 2)}
    envelopes = {}
    kernels = {}
    for step, observation in enumerate(observations):
        history = observations[:step]
        envelopes[history] = _envelope(kinds[step], POSTPROCESS, (observation,))
        for secret in prior:
            kernels[(secret, history)] = _deterministic(observation)

    report = FiniteMixedAdaptiveProcess(
        prior=prior,
        chronology_slots=kinds,
        accounting_units_per_bit=1,
        envelopes=envelopes,
        kernels=kernels,
    ).validate()

    assert report.mutual_information_bits == pytest.approx(0.0)
    assert report.postprocessing_history_checks == 4
    assert report.reachable_histories_by_step == (1, 1, 1, 1, 1)


def test_charged_mixed_slot_rejects_undercharge():
    process = FiniteMixedAdaptiveProcess(
        prior={0: Fraction(1, 2), 1: Fraction(1, 2)},
        chronology_slots=("CHARGED_TRANSCRIPT_EVENT",),
        accounting_units_per_bit=1,
        envelopes={
            (): _envelope(
                "CHARGED_TRANSCRIPT_EVENT", CHARGED, ("e:0", "e:1"), 0
            )
        },
        kernels={
            (0, ()): _deterministic("e:0"),
            (1, ()): _deterministic("e:1"),
        },
    )

    with pytest.raises(UnderchargedEnvelopeError, match="support|charge"):
        process.validate()


def test_documented_mixed_driver_is_self_locating_and_hash_bound():
    artifact_root = Path(__file__).resolve().parents[2]
    driver = artifact_root / "experiments" / "validate_qif_mixed.py"
    module = artifact_root / "sluice_v2" / "qif_validation.py"
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
    assert result["schema"] == "sluice.qif-mixed-validation.v1"
    assert result["all_bounds_hold"] is True
    assert result["module_sha256"] == hashlib.sha256(module.read_bytes()).hexdigest()
    assert result["driver_sha256"] == hashlib.sha256(driver.read_bytes()).hexdigest()
    assert result["old_equality_counterexample"] == {
        "event_only_mutual_information_bits": pytest.approx(0.0),
        "complete_chronology_mutual_information_bits": pytest.approx(1.0),
    }
    assert result["rejected_counterexamples"] == {
        "omitted_monitor_reply": "ChronologyCompletenessError",
        "secret_dependent_postprocessing": "PostprocessingIndependenceError",
        "undercharged_event": "UnderchargedEnvelopeError",
    }
