#!/usr/bin/env python3
"""Validate finite mixed charged/post-processing chronologies.

This driver is deterministic and dependency-free.  It checks one-public-state
finite models; it is mathematical test evidence, not an isolation or trace-
completeness attestation for the live AgentLeak deployment.
"""

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
    ChronologyCompletenessError,
    FiniteAdaptiveProcess,
    FiniteMixedAdaptiveProcess,
    MixedPublicEnvelope,
    MixedStepAuthorization,
    PostprocessingIndependenceError,
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


def _xor_model():
    prior = {0: Fraction(1, 2), 1: Fraction(1, 2)}
    envelopes = {
        (): _envelope("C1_PAYLOAD", POSTPROCESS, ("z:0", "z:1"))
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
    return FiniteMixedAdaptiveProcess(
        prior=prior,
        chronology_slots=("C1_PAYLOAD", "CHARGED_TRANSCRIPT_EVENT"),
        accounting_units_per_bit=1,
        envelopes=envelopes,
        kernels=kernels,
    )


def _xor_event_only_model():
    prior = {0: Fraction(1, 2), 1: Fraction(1, 2)}
    return FiniteAdaptiveProcess(
        prior=prior,
        max_steps=1,
        accounting_units_per_bit=1,
        envelopes={(): PublicEnvelope(("e:0", "e:1"), 1)},
        kernels={
            (secret, ()): {"e:0": Fraction(1, 2), "e:1": Fraction(1, 2)}
            for secret in prior
        },
    )


def _adaptive_randomized_model():
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
            "MODEL_CONTROL_REQUEST", POSTPROCESS, tuple(random_kernels[group])
        )
        kernels[(secret, (group,))] = random_kernels[group]
        for coin in random_kernels[group]:
            history = (group, coin)
            envelopes[history] = _envelope(
                "CHARGED_TRANSCRIPT_EVENT", CHARGED, ("low:0", "low:1"), 1
            )
            kernels[(secret, history)] = _deterministic(f"low:{secret % 2}")
    return FiniteMixedAdaptiveProcess(
        prior=prior,
        chronology_slots=(
            "CHARGED_TRANSCRIPT_EVENT",
            "MODEL_CONTROL_REQUEST",
            "CHARGED_TRANSCRIPT_EVENT",
        ),
        accounting_units_per_bit=1,
        envelopes=envelopes,
        kernels=kernels,
    )


def _deterministic_decode_model():
    prior = {0: Fraction(1, 2), 1: Fraction(1, 2)}
    return FiniteMixedAdaptiveProcess(
        prior=prior,
        chronology_slots=("CHARGED_TRANSCRIPT_EVENT", "C2_PAYLOAD"),
        accounting_units_per_bit=1,
        envelopes={
            (): _envelope(
                "CHARGED_TRANSCRIPT_EVENT", CHARGED, ("e:0", "e:1"), 1
            ),
            ("e:0",): _envelope("C2_PAYLOAD", POSTPROCESS, ("decoded:0",)),
            ("e:1",): _envelope("C2_PAYLOAD", POSTPROCESS, ("decoded:1",)),
        },
        kernels={
            (0, ()): _deterministic("e:0"),
            (1, ()): _deterministic("e:1"),
            (0, ("e:0",)): _deterministic("decoded:0"),
            (1, ("e:1",)): _deterministic("decoded:1"),
        },
    )


def _cached_closed_model():
    prior = {0: Fraction(1, 2), 1: Fraction(1, 2)}
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
    envelopes = {}
    kernels = {}
    for step, observation in enumerate(observations):
        history = observations[:step]
        envelopes[history] = _envelope(
            kinds[step], POSTPROCESS, (observation,)
        )
        for secret in prior:
            kernels[(secret, history)] = _deterministic(observation)
    return FiniteMixedAdaptiveProcess(
        prior=prior,
        chronology_slots=kinds,
        accounting_units_per_bit=1,
        envelopes=envelopes,
        kernels=kernels,
    )


def _rejected_counterexamples():
    secret_dependent_postprocess = FiniteMixedAdaptiveProcess(
        prior={0: Fraction(1, 2), 1: Fraction(1, 2)},
        chronology_slots=("C3_PAYLOAD",),
        accounting_units_per_bit=1,
        envelopes={(): _envelope("C3_PAYLOAD", POSTPROCESS, ("z:0", "z:1"))},
        kernels={
            (0, ()): _deterministic("z:0"),
            (1, ()): _deterministic("z:1"),
        },
    )
    omitted_monitor_reply = FiniteMixedAdaptiveProcess(
        prior={0: 1},
        chronology_slots=("MODEL_CONTROL_REQUEST", "MONITOR_RESPONSE"),
        accounting_units_per_bit=1,
        envelopes={
            (): _envelope("MODEL_CONTROL_REQUEST", POSTPROCESS, ("request",))
        },
        kernels={(0, ()): _deterministic("request")},
    )
    undercharged_event = FiniteMixedAdaptiveProcess(
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
    rejected = {}
    for name, process, expected in (
        (
            "secret_dependent_postprocessing",
            secret_dependent_postprocess,
            PostprocessingIndependenceError,
        ),
        (
            "omitted_monitor_reply",
            omitted_monitor_reply,
            ChronologyCompletenessError,
        ),
        ("undercharged_event", undercharged_event, UnderchargedEnvelopeError),
    ):
        try:
            process.validate()
        except expected as exc:
            rejected[name] = type(exc).__name__
        else:
            raise AssertionError(f"mixed-process counterexample {name} was accepted")
    return rejected


def _report(process):
    result = process.validate()
    return {
        "mutual_information_bits": result.mutual_information_bits,
        "chain_rule_sum_bits": result.chain_rule_sum_bits,
        "expected_charged_support_bits": result.expected_charged_support_bits,
        "expected_charge_bits": result.expected_charge_bits,
        "maximum_path_charge_bits": str(result.maximum_path_charge_bits),
        "step_mutual_information_bits": list(result.step_mutual_information_bits),
        "charged_history_checks": result.charged_history_checks,
        "postprocessing_history_checks": result.postprocessing_history_checks,
        "bound_holds": (
            result.mutual_information_bits <= result.expected_charge_bits + 1e-10
        ),
    }


def main():
    models = {
        "adaptive_randomized_postprocessing": _report(
            _adaptive_randomized_model()
        ),
        "cached_domain_closed_chronology": _report(_cached_closed_model()),
        "deterministic_decode_special_case": _report(
            _deterministic_decode_model()
        ),
        "xor_later_charged_event": _report(_xor_model()),
    }
    event_only = _xor_event_only_model().validate()
    module_path = Path(qif_validation.__file__).resolve()
    driver_path = Path(__file__).resolve()
    result = {
        "schema": "sluice.qif-mixed-validation.v1",
        "module_sha256": hashlib.sha256(module_path.read_bytes()).hexdigest(),
        "driver_sha256": hashlib.sha256(driver_path.read_bytes()).hexdigest(),
        "models": models,
        "old_equality_counterexample": {
            "event_only_mutual_information_bits": (
                event_only.mutual_information_bits
            ),
            "complete_chronology_mutual_information_bits": (
                models["xor_later_charged_event"]["mutual_information_bits"]
            ),
        },
        "rejected_counterexamples": _rejected_counterexamples(),
        "all_bounds_hold": all(model["bound_holds"] for model in models.values()),
        "evidence_boundary": (
            "exact finite-probability validation for one fixed public-state "
            "fiber; not a general proof and not evidence that live process "
            "isolation, receipt provenance, or chronology completeness holds"
        ),
    }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
