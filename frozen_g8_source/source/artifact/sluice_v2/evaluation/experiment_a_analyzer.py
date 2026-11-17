"""Analytically exact finite-law analyzer for controlled Experiment A."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, localcontext, ROUND_FLOOR, ROUND_CEILING
from fractions import Fraction
import hashlib
import json
from pathlib import Path
from typing import Iterable, Mapping, Sequence

from . import experiment_a_freeze as freeze
from . import experiment_a_runner as runner


ANALYSIS_SCHEMA = "sluice.experiment-a.exact-analysis.v1"
PRECISION = 80
WORK_PRECISION = 120
TRANSCENDENTAL_GUARD = Decimal("1e-105")


class ExperimentAAnalysisError(ValueError):
    """The exact trace corpus or decision contract is invalid."""


def _fraction_text(value: Fraction) -> str:
    return f"{value.numerator}/{value.denominator}"


def _strict_fraction(numerator: object, denominator: object, *, name: str) -> Fraction:
    if type(numerator) is not int or type(denominator) is not int:
        raise ExperimentAAnalysisError(f"{name} must use strict integer components")
    if numerator < 0 or denominator <= 0:
        raise ExperimentAAnalysisError(f"{name} is outside the rational domain")
    return Fraction(numerator, denominator)


@dataclass(frozen=True)
class Log2Basis:
    constant: Fraction
    log2_3_coefficient: Fraction

    def __add__(self, other: "Log2Basis") -> "Log2Basis":
        return Log2Basis(
            self.constant + other.constant,
            self.log2_3_coefficient + other.log2_3_coefficient,
        )

    def scaled(self, factor: Fraction) -> "Log2Basis":
        return Log2Basis(
            self.constant * factor,
            self.log2_3_coefficient * factor,
        )


ZERO_BASIS = Log2Basis(Fraction(0, 1), Fraction(0, 1))


def _factor_power(value: int, prime: int) -> tuple[int, int]:
    exponent = 0
    while value > 1 and value % prime == 0:
        value //= prime
        exponent += 1
    return exponent, value


def _log2_rational_basis(value: Fraction) -> Log2Basis:
    if value <= 0:
        raise ExperimentAAnalysisError("logarithm ratio must be positive")
    num_twos, numerator = _factor_power(value.numerator, 2)
    num_threes, numerator = _factor_power(numerator, 3)
    den_twos, denominator = _factor_power(value.denominator, 2)
    den_threes, denominator = _factor_power(denominator, 3)
    if numerator != 1 or denominator != 1:
        raise ExperimentAAnalysisError(
            "finite law left the analytically exact {2,3} logarithm basis"
        )
    return Log2Basis(
        Fraction(num_twos - den_twos, 1),
        Fraction(num_threes - den_threes, 1),
    )


def _decimal_fraction(value: Fraction) -> Decimal:
    return Decimal(value.numerator) / Decimal(value.denominator)


def _log2_3_center() -> Decimal:
    with localcontext() as context:
        context.prec = WORK_PRECISION
        return Decimal(3).ln() / Decimal(2).ln()


def _directed_interval(basis: Log2Basis) -> tuple[Decimal, Decimal]:
    center_log = _log2_3_center()
    with localcontext() as context:
        context.prec = WORK_PRECISION
        center = _decimal_fraction(basis.constant) + _decimal_fraction(
            basis.log2_3_coefficient
        ) * center_log
        lower_work = center - TRANSCENDENTAL_GUARD
        upper_work = center + TRANSCENDENTAL_GUARD
    with localcontext() as context:
        context.prec = PRECISION
        context.rounding = ROUND_FLOOR
        lower = +lower_work
    with localcontext() as context:
        context.prec = PRECISION
        context.rounding = ROUND_CEILING
        upper = +upper_work
    return lower, upper


def _decimal_text(value: Decimal) -> str:
    return format(value, "f")


def _transcript(trace: Mapping[str, object], observer: str) -> tuple[tuple[object, ...], ...]:
    events = trace["events"]
    if type(events) is not list:
        raise ExperimentAAnalysisError("events must be a list")
    transcript = []
    for event in events:
        if type(event) is not dict:
            raise ExperimentAAnalysisError("event must be an object")
        projections = event.get("observer_projection")
        supports = event.get("observer_support")
        if type(projections) is not dict or type(supports) is not dict:
            raise ExperimentAAnalysisError("observer projection or support omitted")
        if observer not in projections or observer not in supports:
            raise ExperimentAAnalysisError("observer projection is incomplete")
        projection = projections[observer]
        support = supports[observer]
        if type(projection) is not str or type(support) is not list:
            raise ExperimentAAnalysisError("observer projection has wrong exact type")
        if projection not in support:
            raise ExperimentAAnalysisError("projection lies outside declared support")
        transcript.append(
            (
                event["kind"],
                projection,
                event["charge_units"],
                event["terminal"],
            )
        )
    return tuple(transcript)


def _validate_exact_corpus(traces: Sequence[Mapping[str, object]]) -> None:
    if type(traces) not in {list, tuple} or len(traces) != 656:
        raise ExperimentAAnalysisError("trace corpus must contain exactly 656 paths")
    expected_schedules = freeze.expected_schedule()
    seen_ids: set[str] = set()
    seen_paths: set[int] = set()
    for index, trace in enumerate(traces):
        if type(trace) is not dict:
            raise ExperimentAAnalysisError("trace must be an object")
        expected = runner.build_trace(expected_schedules[index])
        if not runner._typed_equal(trace, expected):
            raise ExperimentAAnalysisError(
                f"trace {index} differs from exact controlled reconstruction"
            )
        trace_id = trace["trace_id"]
        path_index = trace["path_index"]
        if type(trace_id) is not str or trace_id in seen_ids:
            raise ExperimentAAnalysisError("duplicate or malformed trace identity")
        if type(path_index) is not int or path_index in seen_paths:
            raise ExperimentAAnalysisError("duplicate or malformed path identity")
        seen_ids.add(trace_id)
        seen_paths.add(path_index)
        events = trace["events"]
        if type(events) is not list or len(events) != trace["public_outer_capture_hmax"]:
            raise ExperimentAAnalysisError("trace is truncated or exceeds public Hmax")
        last_lifetime = 0
        last_epoch = 0
        successful_reauthorizations = 0
        for slot, event in enumerate(events):
            if event["slot"] != slot:
                raise ExperimentAAnalysisError("trace slots are missing or reordered")
            before = event["lifetime_spend_before"]
            after = event["lifetime_spend_after"]
            charge = event["charge_units"]
            if any(type(value) is not int for value in (before, after, charge)):
                raise ExperimentAAnalysisError("spend and charge must be strict integers")
            if before != last_lifetime or after != before + charge:
                raise ExperimentAAnalysisError("lifetime spend reset or charge mismatch")
            if event["epoch_before"] != last_epoch:
                raise ExperimentAAnalysisError("epoch chronology is discontinuous")
            if event["epoch_after"] == last_epoch + 1:
                successful_reauthorizations += 1
                if event["grant_state"] != "USED" or event["epoch_spend_after"] != 0:
                    raise ExperimentAAnalysisError("reauthorization transition is malformed")
            elif event["epoch_after"] != last_epoch:
                raise ExperimentAAnalysisError("epoch skipped or moved backward")
            if event["grant_state"] == "USED_REPLAY_DENIED" and event["epoch_after"] != 1:
                raise ExperimentAAnalysisError("reauthorization replay created a new epoch")
            last_lifetime = after
            last_epoch = event["epoch_after"]
        if successful_reauthorizations > 1:
            raise ExperimentAAnalysisError("one-use reauthorization succeeded more than once")
        if trace["realized_charge_units"] != last_lifetime:
            raise ExperimentAAnalysisError("final lifetime spend differs")


def _conditional_mi_basis(
    traces: Sequence[Mapping[str, object]], observer: str
) -> Log2Basis:
    by_tape: dict[str, list[tuple[str, tuple[tuple[object, ...], ...], Fraction]]] = {}
    for trace in traces:
        weight = _strict_fraction(
            trace["path_weight_numerator"],
            trace["path_weight_denominator"],
            name="path weight",
        )
        by_tape.setdefault(str(trace["public_tape_id"]), []).append(
            (str(trace["secret_id"]), _transcript(trace, observer), weight)
        )
    if set(by_tape) != set(freeze.PUBLIC_TAPES):
        raise ExperimentAAnalysisError("public tape support is incomplete")
    total = ZERO_BASIS
    for tape in freeze.PUBLIC_TAPES:
        entries = by_tape[tape]
        tape_mass = sum((entry[2] for entry in entries), Fraction(0, 1))
        if tape_mass != Fraction(1, 4):
            raise ExperimentAAnalysisError("public tape mass differs from 1/4")
        transcript_mass: dict[tuple[tuple[object, ...], ...], Fraction] = {}
        for _secret, transcript, weight in entries:
            conditional = weight / tape_mass
            transcript_mass[transcript] = transcript_mass.get(
                transcript, Fraction(0, 1)
            ) + conditional
        for _secret, transcript, weight in entries:
            conditional = weight / tape_mass
            ratio = Fraction(1, 1) / transcript_mass[transcript]
            term = _log2_rational_basis(ratio).scaled(
                tape_mass * conditional
            )
            total = total + term
    return total


def _basis_wire(basis: Log2Basis) -> dict[str, str]:
    lower, upper = _directed_interval(basis)
    return {
        "analytic_expression": (
            f"({_fraction_text(basis.constant)})+"
            f"({_fraction_text(basis.log2_3_coefficient)})*log2(3)"
        ),
        "constant": _fraction_text(basis.constant),
        "interval_lower": _decimal_text(lower),
        "interval_upper": _decimal_text(upper),
        "log2_3_coefficient": _fraction_text(basis.log2_3_coefficient),
    }


def _bound_decision(basis: Log2Basis, bound: Fraction) -> tuple[str, Decimal, Decimal]:
    lower, upper = _directed_interval(basis)
    with localcontext() as context:
        context.prec = PRECISION
        tolerance = Decimal(freeze.DECISION_TOLERANCE)
        bound_decimal = _decimal_fraction(bound)
        if upper <= bound_decimal + tolerance:
            decision = "BOUND_HOLDS"
        elif lower > bound_decimal + tolerance:
            decision = "CERTIFIED_BOUND_OVERSHOOT"
        else:
            decision = "AMBIGUOUS_FAIL_CLOSED"
        overshoot_lower = max(Decimal(0), lower - bound_decimal)
        overshoot_upper = max(Decimal(0), upper - bound_decimal)
    return decision, overshoot_lower, overshoot_upper


def _weighted_endpoint(
    traces: Sequence[Mapping[str, object]], numerator_field: str, denominator_field: str
) -> Fraction:
    total = Fraction(0, 1)
    for trace in traces:
        weight = _strict_fraction(
            trace["path_weight_numerator"],
            trace["path_weight_denominator"],
            name="path weight",
        )
        value = _strict_fraction(
            trace[numerator_field], trace[denominator_field], name=numerator_field
        )
        total += weight * value
    return total


def _weighted_charge(traces: Sequence[Mapping[str, object]]) -> Fraction:
    total = Fraction(0, 1)
    for trace in traces:
        weight = _strict_fraction(
            trace["path_weight_numerator"],
            trace["path_weight_denominator"],
            name="path weight",
        )
        charge = trace["realized_charge_units"]
        if type(charge) is not int or charge < 0:
            raise ExperimentAAnalysisError("charge must be a strict nonnegative integer")
        total += weight * charge
    return total


def _condition_positive(condition_id: str) -> bool:
    for item in freeze.expected_conditions()["conditions"]:
        if item["condition_id"] == condition_id:
            return item["positive_assertion"] is True
    raise AssertionError(condition_id)


def analyze_traces(traces: Sequence[Mapping[str, object]]) -> dict[str, object]:
    _validate_exact_corpus(traces)
    rows = freeze.expected_rows()
    by_row: dict[str, list[Mapping[str, object]]] = {row["row_id"]: [] for row in rows}
    for trace in traces:
        by_row[str(trace["row_id"])].append(trace)
    reports = []
    all_positive_hold = True
    for row in rows:
        row_traces = by_row[row["row_id"]]
        if len(row_traces) != int(row["path_count"]):
            raise ExperimentAAnalysisError("row path count differs from matrix")
        mass = sum(
            (
                _strict_fraction(
                    trace["path_weight_numerator"],
                    trace["path_weight_denominator"],
                    name="path weight",
                )
                for trace in row_traces
            ),
            Fraction(0, 1),
        )
        if mass != 1:
            raise ExperimentAAnalysisError("row path mass does not sum exactly to one")
        certified = {trace["certified_bound_units"] for trace in row_traces}
        if len(certified) != 1 or any(type(value) is not int for value in certified):
            raise ExperimentAAnalysisError("row certified bound is not one strict integer")
        bound = Fraction(certified.pop(), freeze.ACCOUNTING_UNITS_PER_BIT)
        observer_reports = {}
        maximum_lower = Decimal(0)
        maximum_upper = Decimal(0)
        for observer in ("observer_A", "observer_B", "colluding_union"):
            basis = _conditional_mi_basis(row_traces, observer)
            decision, overshoot_lower, overshoot_upper = _bound_decision(basis, bound)
            maximum_lower = max(maximum_lower, overshoot_lower)
            maximum_upper = max(maximum_upper, overshoot_upper)
            observer_reports[observer] = {
                "bound_decision": decision,
                "certified_bound_bits": _fraction_text(bound),
                "mutual_information_bits": _basis_wire(basis),
                "overshoot_interval_lower": _decimal_text(overshoot_lower),
                "overshoot_interval_upper": _decimal_text(overshoot_upper),
            }
        positive = _condition_positive(row["condition_id"])
        if positive and observer_reports["colluding_union"]["bound_decision"] != "BOUND_HOLDS":
            all_positive_hold = False
        mechanism = next(
            item["mechanism"]
            for item in freeze.expected_conditions()["conditions"]
            if item["condition_id"] == row["condition_id"]
        )
        reports.append(
            {
                "condition_id": row["condition_id"],
                "epoch_attempt_horizon_h": int(row["epoch_attempt_horizon_h"]),
                "exact_expected_charge_units": _fraction_text(
                    _weighted_charge(row_traces)
                ),
                "exact_path_count": len(row_traces),
                "exact_path_mass": _fraction_text(mass),
                "exact_requested_field_utility": _fraction_text(
                    _weighted_endpoint(
                        row_traces,
                        "requested_fields_numerator",
                        "requested_fields_denominator",
                    )
                ),
                "maximum_certified_bound_overshoot_interval_lower": _decimal_text(
                    maximum_lower
                ),
                "maximum_certified_bound_overshoot_interval_upper": _decimal_text(
                    maximum_upper
                ),
                "maximum_path_charge_units": max(
                    int(trace["realized_charge_units"]) for trace in row_traces
                ),
                "mechanism_attempt_horizon_enforced": mechanism[
                    "attempt_horizon_enforced"
                ],
                "observers": observer_reports,
                "positive_assertion": positive,
                "principal_eligible": False,
                "prior_id": row["prior_id"],
                "public_outer_capture_hmax": int(row["public_outer_capture_hmax"]),
                "row_id": row["row_id"],
            }
        )
    trace_data = runner.trace_bytes(traces)
    return {
        "all_positive_assertion_bounds_hold": all_positive_hold,
        "analysis_schema": ANALYSIS_SCHEMA,
        "decision_tolerance_bits": freeze.DECISION_TOLERANCE,
        "directed_precision_digits": PRECISION,
        "evidence_boundary": (
            "exact finite controlled known-answer paths only; no model, tokenizer, "
            "endpoint, deployment, GPU, or principal outcome"
        ),
        "matrix_rows": len(reports),
        "principal_eligible": False,
        "rows": reports,
        "total_paths": len(traces),
        "trace_corpus_sha256": hashlib.sha256(trace_data).hexdigest(),
    }


def analyze_trace_bytes(data: bytes) -> dict[str, object]:
    if type(data) is not bytes:
        raise TypeError("trace corpus must be bytes")
    return analyze_traces(runner.parse_trace_bytes(data))


def main(argv: Sequence[str] | None = None) -> int:
    import argparse
    import sys

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace_file", type=Path)
    args = parser.parse_args(argv)
    result = analyze_trace_bytes(args.trace_file.read_bytes())
    sys.stdout.buffer.write(freeze.canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
