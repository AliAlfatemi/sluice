"""Exact finite controlled-path runner for Experiment A.

The runner transforms the prospective 656-path schedule into deterministic
finite traces.  It is a CPU-only known-answer foundation, not a live system
runner and not principal evidence.
"""

from __future__ import annotations

from fractions import Fraction
import hashlib
import json
import os
from pathlib import Path
from typing import Iterable, Mapping, Sequence

from . import experiment_a_freeze as freeze


TRACE_SCHEMA = "sluice.experiment-a.exact-trace.v1"
EVENT_SCHEMA = "sluice.experiment-a.controlled-event.v1"
ATTEMPT_SCHEMA = "sluice.experiment-a.attempt.v1"


class ExperimentARunnerError(ValueError):
    """A controlled path or append-only attempt violated the runner contract."""


def _typed_equal(left: object, right: object) -> bool:
    if type(left) is not type(right):
        return False
    if type(left) is dict:
        return set(left) == set(right) and all(
            _typed_equal(left[key], right[key]) for key in left
        )
    if type(left) is list:
        return len(left) == len(right) and all(
            _typed_equal(a, b) for a, b in zip(left, right)
        )
    return left == right


def _strict_int(name: str, value: object, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise ExperimentARunnerError(f"{name} must be an integer >= {minimum}")
    return value


def _condition_map() -> dict[str, Mapping[str, object]]:
    return {
        str(item["condition_id"]): item
        for item in freeze.expected_conditions()["conditions"]
    }


def _row_map() -> dict[str, Mapping[str, str]]:
    return {row["row_id"]: row for row in freeze.expected_rows()}


def _secret_value(prior_id: str, secret_id: str) -> int | tuple[int, int]:
    if prior_id == "A1":
        if (
            type(secret_id) is not str
            or len(secret_id) != 3
            or not secret_id.startswith("s")
            or not secret_id[1:].isdigit()
        ):
            raise ExperimentARunnerError("invalid A1 secret identity")
        value = int(secret_id[1:])
        if not 0 <= value < 16 or secret_id != f"s{value:02d}":
            raise ExperimentARunnerError("noncanonical A1 secret identity")
        return value
    if prior_id == "A2" and secret_id in {"00", "01", "10", "11"}:
        return (int(secret_id[0]), int(secret_id[1]))
    raise ExperimentARunnerError("secret identity is outside the frozen prior")


def _tape_index(tape_id: str) -> int:
    if tape_id not in freeze.PUBLIC_TAPES:
        raise ExperimentARunnerError("public tape is outside the frozen support")
    return freeze.PUBLIC_TAPES.index(tape_id)


def _event(
    *,
    slot: int,
    kind: str,
    outcome: str,
    value_code: str,
    projections: Mapping[str, str],
    supports: Mapping[str, Sequence[str]],
    charge_units: int,
    terminal: bool,
    epoch_before: int,
    epoch_after: int,
    epoch_spend_before: int,
    epoch_spend_after: int,
    lifetime_spend_before: int,
    lifetime_spend_after: int,
    grant_state: str,
) -> dict[str, object]:
    if set(projections) != {"observer_A", "observer_B", "colluding_union"}:
        raise ExperimentARunnerError("observer projection set is incomplete")
    if set(supports) != set(projections):
        raise ExperimentARunnerError("observer support set is incomplete")
    exact_supports: dict[str, list[str]] = {}
    for observer in sorted(supports):
        support = supports[observer]
        if type(support) not in {tuple, list} or not support:
            raise ExperimentARunnerError("observer support must be nonempty")
        values = list(support)
        if any(type(value) is not str for value in values):
            raise ExperimentARunnerError("observer support values must be strings")
        if len(values) != len(set(values)):
            raise ExperimentARunnerError("observer support contains duplicates")
        if projections[observer] not in values:
            raise ExperimentARunnerError("actual projection is outside support")
        exact_supports[observer] = values
    for name, value in (
        ("slot", slot),
        ("charge_units", charge_units),
        ("epoch_before", epoch_before),
        ("epoch_after", epoch_after),
        ("epoch_spend_before", epoch_spend_before),
        ("epoch_spend_after", epoch_spend_after),
        ("lifetime_spend_before", lifetime_spend_before),
        ("lifetime_spend_after", lifetime_spend_after),
    ):
        _strict_int(name, value)
    if type(terminal) is not bool:
        raise ExperimentARunnerError("terminal must be a boolean")
    return {
        "charge_units": charge_units,
        "epoch_after": epoch_after,
        "epoch_before": epoch_before,
        "epoch_spend_after": epoch_spend_after,
        "epoch_spend_before": epoch_spend_before,
        "event_schema": EVENT_SCHEMA,
        "grant_state": grant_state,
        "kind": kind,
        "lifetime_spend_after": lifetime_spend_after,
        "lifetime_spend_before": lifetime_spend_before,
        "observer_projection": dict(sorted(projections.items())),
        "observer_support": exact_supports,
        "outcome": outcome,
        "slot": slot,
        "terminal": terminal,
        "value_code": value_code,
    }


class _TraceState:
    def __init__(self) -> None:
        self.epoch = 0
        self.epoch_spend = 0
        self.lifetime_spend = 0
        self.grant_state = "UNUSED"
        self.events: list[dict[str, object]] = []

    def append(
        self,
        *,
        kind: str,
        outcome: str,
        value_code: str,
        projections: Mapping[str, str],
        supports: Mapping[str, Sequence[str]],
        charge_units: int,
        terminal: bool = False,
        transition: str = "NONE",
    ) -> None:
        before_epoch = self.epoch
        before_epoch_spend = self.epoch_spend
        before_lifetime = self.lifetime_spend
        after_epoch = self.epoch
        after_epoch_spend = self.epoch_spend + charge_units
        after_lifetime = self.lifetime_spend + charge_units
        grant_state = self.grant_state
        if transition == "REAUTHORIZE_SUCCESS":
            if self.grant_state != "UNUSED":
                raise ExperimentARunnerError("reauthorization grant reused as success")
            after_epoch = self.epoch + 1
            after_epoch_spend = 0
            grant_state = "USED"
        elif transition == "REAUTHORIZE_REPLAY_DENIED":
            if self.grant_state != "USED":
                raise ExperimentARunnerError("replay denial lacks prior success")
            grant_state = "USED_REPLAY_DENIED"
        elif transition != "NONE":
            raise ExperimentARunnerError("unknown lifecycle transition")
        self.events.append(
            _event(
                slot=len(self.events),
                kind=kind,
                outcome=outcome,
                value_code=value_code,
                projections=projections,
                supports=supports,
                charge_units=charge_units,
                terminal=terminal,
                epoch_before=before_epoch,
                epoch_after=after_epoch,
                epoch_spend_before=before_epoch_spend,
                epoch_spend_after=after_epoch_spend,
                lifetime_spend_before=before_lifetime,
                lifetime_spend_after=after_lifetime,
                grant_state=grant_state,
            )
        )
        self.epoch = after_epoch
        self.epoch_spend = after_epoch_spend
        self.lifetime_spend = after_lifetime
        self.grant_state = grant_state


def _constant_support(symbol: str) -> tuple[str, ...]:
    return (symbol,)


def _all_observers(symbol: str) -> dict[str, str]:
    return {
        "observer_A": symbol,
        "observer_B": symbol,
        "colluding_union": symbol,
    }


def _all_support(symbols: Sequence[str]) -> dict[str, Sequence[str]]:
    return {
        "observer_A": tuple(symbols),
        "observer_B": tuple(symbols),
        "colluding_union": tuple(symbols),
    }


def _append_lifecycle(state: _TraceState, tape_index: int) -> None:
    public = _all_observers("PUBLIC_LIFECYCLE")
    if tape_index in {2, 3}:
        reauth = "REAUTHORIZED"
        state.append(
            kind="REAUTHORIZATION",
            outcome=reauth,
            value_code=reauth,
            projections=public,
            supports=_all_support(("PUBLIC_LIFECYCLE", "PUBLIC_REAUTH_DENIED")),
            charge_units=1,
            transition="REAUTHORIZE_SUCCESS",
        )
    if tape_index == 3:
        replay = "REAUTH_DENIED_REPLAY"
        state.append(
            kind="REAUTHORIZATION",
            outcome=replay,
            value_code=replay,
            projections=public,
            supports=_all_support(("PUBLIC_LIFECYCLE", "PUBLIC_REAUTH_DENIED")),
            charge_units=1,
            transition="REAUTHORIZE_REPLAY_DENIED",
        )
    state.append(
        kind="LIFECYCLE",
        outcome="STOP",
        value_code="STOP",
        projections=public,
        supports=_all_support(("PUBLIC_LIFECYCLE", "PUBLIC_CONTINUE")),
        charge_units=1,
        terminal=True,
    )


def _append_external_padding(state: _TraceState, hmax: int, symbol: str) -> None:
    while len(state.events) < hmax:
        state.append(
            kind="PADDING",
            outcome=symbol,
            value_code=symbol,
            projections=_all_observers(symbol),
            supports=_all_support(_constant_support(symbol)),
            charge_units=0,
            terminal=True,
        )
    if len(state.events) != hmax:
        raise ExperimentARunnerError("active trace exceeds the public outer Hmax")


def _a1_trace(condition_id: str, secret: int, tape: int, hmax: int) -> tuple[_TraceState, int, int, int]:
    state = _TraceState()
    low = secret & 3
    high = (secret >> 2) & 3
    if condition_id == "unmediated":
        symbol = f"RAW:s{secret:02d}"
        support = tuple(f"RAW:s{item:02d}" for item in range(16))
        state.append(
            kind="UNMEDIATED_RAW",
            outcome="RAW_RELEASE",
            value_code=symbol,
            projections=_all_observers(symbol),
            supports=_all_support(support),
            charge_units=0,
        )
        _append_external_padding(state, hmax, "OUTER_NO_EVENT")
        return state, 0, 1, 1
    if condition_id == "sluice_result_only_accounting_old_design":
        a_result = f"RESULT:r{low}"
        state.append(
            kind="RESULT",
            outcome="RELEASED",
            value_code=a_result,
            projections={
                "observer_A": a_result,
                "observer_B": "RESULT_REDACTED",
                "colluding_union": a_result,
            },
            supports={
                "observer_A": tuple(f"RESULT:r{i}" for i in range(4)),
                "observer_B": ("RESULT_REDACTED",),
                "colluding_union": tuple(f"RESULT:r{i}" for i in range(4)),
            },
            charge_units=2,
        )
        route = f"ROUTE:q{high}"
        state.append(
            kind="OMITTED_ROUTE_METADATA",
            outcome="OBSERVED_OUTSIDE_RESULT_PROJECTION",
            value_code=route,
            projections={
                "observer_A": "METADATA_OMITTED",
                "observer_B": route,
                "colluding_union": route,
            },
            supports={
                "observer_A": ("METADATA_OMITTED",),
                "observer_B": tuple(f"ROUTE:q{i}" for i in range(4)),
                "colluding_union": tuple(f"ROUTE:q{i}" for i in range(4)),
            },
            charge_units=0,
        )
        _append_external_padding(state, hmax, "OUTER_NO_EVENT")
        return state, 2, 1, 1
    if condition_id == "sluice_complete_typed_transcript":
        state.append(
            kind="COMPLETE_TYPED_EVENT",
            outcome="RELEASED",
            value_code=f"FULL:s{secret:02d}",
            projections={
                "observer_A": f"LOW:r{low}",
                "observer_B": f"HIGH:q{high}",
                "colluding_union": f"FULL:s{secret:02d}",
            },
            supports={
                "observer_A": tuple(f"LOW:r{i}" for i in range(4)),
                "observer_B": tuple(f"HIGH:q{i}" for i in range(4)),
                "colluding_union": tuple(f"FULL:s{i:02d}" for i in range(16)),
            },
            charge_units=4,
        )
        _append_lifecycle(state, tape)
        _append_external_padding(state, hmax, "DOMAIN_CLOSED")
        return state, 7, 1, 1
    if condition_id == "sluice_without_attempt_horizon_enforcement":
        for slot in range(hmax):
            bit_index = (slot + tape) % 4
            bit = (secret >> bit_index) & 1
            target_a = slot % 2 == 0
            a_symbol = f"BIT:{bit_index}:{bit}" if target_a else "NO_OBSERVATION"
            b_symbol = f"BIT:{bit_index}:{bit}" if not target_a else "NO_OBSERVATION"
            state.append(
                kind="UNBOUNDED_ACTIVE_ATTEMPT",
                outcome="RELEASED",
                value_code=f"BIT:{bit_index}:{bit}",
                projections={
                    "observer_A": a_symbol,
                    "observer_B": b_symbol,
                    "colluding_union": f"BIT:{bit_index}:{bit}",
                },
                supports={
                    "observer_A": (
                        (f"BIT:{bit_index}:0", f"BIT:{bit_index}:1")
                        if target_a
                        else ("NO_OBSERVATION",)
                    ),
                    "observer_B": (
                        (f"BIT:{bit_index}:0", f"BIT:{bit_index}:1")
                        if not target_a
                        else ("NO_OBSERVATION",)
                    ),
                    "colluding_union": (
                        f"BIT:{bit_index}:0",
                        f"BIT:{bit_index}:1",
                    ),
                },
                charge_units=1,
            )
        return state, hmax, 1, 1
    if condition_id in {
        "sluice_with_success_only_route_charging",
        "sluice_with_route_denial_stopping_enforcement",
    }:
        lifecycle_values = (
            "ROUTE_RELEASE",
            "ROUTE_DENIED",
            "AUTH_DENIED",
            "STOP_SELECTED",
        )
        lifecycle = lifecycle_values[high]
        full = condition_id.endswith("route_denial_stopping_enforcement")
        state.append(
            kind="ROUTE_DENIAL_STOP",
            outcome=lifecycle,
            value_code=lifecycle,
            projections={
                "observer_A": "ROUTE_REDACTED",
                "observer_B": lifecycle,
                "colluding_union": lifecycle,
            },
            supports={
                "observer_A": ("ROUTE_REDACTED",),
                "observer_B": lifecycle_values,
                "colluding_union": lifecycle_values,
            },
            charge_units=2 if full else 0,
        )
        result = f"RESULT:r{low}"
        state.append(
            kind="RESULT",
            outcome="RELEASED",
            value_code=result,
            projections={
                "observer_A": result,
                "observer_B": "RESULT_REDACTED",
                "colluding_union": result,
            },
            supports={
                "observer_A": tuple(f"RESULT:r{i}" for i in range(4)),
                "observer_B": ("RESULT_REDACTED",),
                "colluding_union": tuple(f"RESULT:r{i}" for i in range(4)),
            },
            charge_units=2,
        )
        if full:
            _append_lifecycle(state, tape)
            _append_external_padding(state, hmax, "DOMAIN_CLOSED")
            return state, 7, 1, 1
        state.append(
            kind="LIFECYCLE",
            outcome="STOP",
            value_code="STOP",
            projections=_all_observers("PUBLIC_STOP"),
            supports=_all_support(("PUBLIC_STOP",)),
            charge_units=0,
            terminal=True,
        )
        _append_external_padding(state, hmax, "OUTER_NO_EVENT")
        return state, 2, 1, 1
    raise ExperimentARunnerError("A1 condition is not frozen")


def _a2_trace(condition_id: str, secret: tuple[int, int], tape: int, hmax: int) -> tuple[_TraceState, int, int, int]:
    state = _TraceState()
    left, right = secret
    if condition_id == "per_object_budgets":
        a = f"OBJECT_A:{left}"
        state.append(
            kind="OBJECT_A_RELEASE",
            outcome="RELEASED",
            value_code=a,
            projections={
                "observer_A": a,
                "observer_B": "OBJECT_A_HIDDEN",
                "colluding_union": a,
            },
            supports={
                "observer_A": ("OBJECT_A:0", "OBJECT_A:1"),
                "observer_B": ("OBJECT_A_HIDDEN",),
                "colluding_union": ("OBJECT_A:0", "OBJECT_A:1"),
            },
            charge_units=1,
        )
        b = f"OBJECT_B:{right}"
        state.append(
            kind="OBJECT_B_RELEASE",
            outcome="RELEASED",
            value_code=b,
            projections={
                "observer_A": "OBJECT_B_HIDDEN",
                "observer_B": b,
                "colluding_union": b,
            },
            supports={
                "observer_A": ("OBJECT_B_HIDDEN",),
                "observer_B": ("OBJECT_B:0", "OBJECT_B:1"),
                "colluding_union": ("OBJECT_B:0", "OBJECT_B:1"),
            },
            charge_units=1,
        )
        _append_lifecycle(state, tape)
        _append_external_padding(state, hmax, "DOMAIN_CLOSED")
        return state, 1, 2, 2
    if condition_id == "shared_correlated_secret_budget_domains":
        parity = left ^ right
        symbol = f"SHARED_PARITY:{parity}"
        target_a = tape % 2 == 0
        state.append(
            kind="SHARED_DOMAIN_RELEASE",
            outcome="RELEASED",
            value_code=symbol,
            projections={
                "observer_A": symbol if target_a else "SHARED_RELEASE_NOT_DELIVERED_A",
                "observer_B": symbol if not target_a else "SHARED_RELEASE_NOT_DELIVERED_B",
                "colluding_union": symbol,
            },
            supports={
                "observer_A": (
                    ("SHARED_PARITY:0", "SHARED_PARITY:1")
                    if target_a
                    else ("SHARED_RELEASE_NOT_DELIVERED_A",)
                ),
                "observer_B": (
                    ("SHARED_PARITY:0", "SHARED_PARITY:1")
                    if not target_a
                    else ("SHARED_RELEASE_NOT_DELIVERED_B",)
                ),
                "colluding_union": ("SHARED_PARITY:0", "SHARED_PARITY:1"),
            },
            charge_units=1,
        )
        _append_lifecycle(state, tape)
        _append_external_padding(state, hmax, "DOMAIN_CLOSED")
        return state, 4, 1, 2
    raise ExperimentARunnerError("A2 condition is not frozen")


def _condition_identity(condition: Mapping[str, object]) -> str:
    return hashlib.sha256(freeze.canonical_json(condition)).hexdigest()


def build_trace(schedule: Mapping[str, object]) -> dict[str, object]:
    if type(schedule) is not dict:
        raise TypeError("schedule must be a dict")
    row_id = schedule.get("row_id")
    rows = _row_map()
    if type(row_id) is not str or row_id not in rows:
        raise ExperimentARunnerError("schedule row identity is not frozen")
    row = rows[row_id]
    expected_schedule = freeze.expected_schedule()[
        _strict_int("path_index", schedule.get("path_index"))
    ]
    if not _typed_equal(schedule, expected_schedule):
        raise ExperimentARunnerError(
            "schedule path differs from exact outcome-free reconstruction"
        )
    condition_id = str(schedule["condition_id"])
    condition = _condition_map()[condition_id]
    secret = _secret_value(str(schedule["prior_id"]), str(schedule["secret_id"]))
    tape = _tape_index(str(schedule["public_tape_id"]))
    hmax = _strict_int(
        "public_outer_capture_hmax", schedule["public_outer_capture_hmax"], minimum=1
    )
    if str(schedule["prior_id"]) == "A1":
        assert type(secret) is int
        state, certified_bound, utility_num, utility_den = _a1_trace(
            condition_id, secret, tape, hmax
        )
    else:
        assert type(secret) is tuple
        state, certified_bound, utility_num, utility_den = _a2_trace(
            condition_id, secret, tape, hmax
        )
    if len(state.events) != hmax:
        raise ExperimentARunnerError("trace is not exactly padded to public Hmax")
    if state.lifetime_spend != sum(
        int(event["charge_units"]) for event in state.events
    ):
        raise ExperimentARunnerError("lifetime spend differs from event charges")
    schedule_bytes = freeze.canonical_json_line(schedule)
    trace_id_material = schedule_bytes + str(condition["policy_identity"]).encode("ascii")
    return {
        "attempt_number": schedule["attempt_number"],
        "certified_bound_units": certified_bound,
        "condition_id": condition_id,
        "condition_identity_sha256": _condition_identity(condition),
        "events": state.events,
        "path_index": schedule["path_index"],
        "path_weight_denominator": schedule["path_weight_denominator"],
        "path_weight_numerator": schedule["path_weight_numerator"],
        "principal_eligible": False,
        "prior_attempt_sha256": schedule["prior_attempt_sha256"],
        "prior_id": schedule["prior_id"],
        "public_outer_capture_hmax": hmax,
        "public_tape_id": schedule["public_tape_id"],
        "realized_charge_units": state.lifetime_spend,
        "requested_fields_denominator": utility_den,
        "requested_fields_numerator": utility_num,
        "row_id": row_id,
        "secret_id": schedule["secret_id"],
        "source_schedule_record_sha256": hashlib.sha256(schedule_bytes).hexdigest(),
        "trace_id": "trace-" + hashlib.sha256(trace_id_material).hexdigest()[:32],
        "trace_schema": TRACE_SCHEMA,
    }


def generate_trace_records(
    schedules: Iterable[Mapping[str, object]] | None = None,
) -> list[dict[str, object]]:
    records = freeze.expected_schedule() if schedules is None else list(schedules)
    if len(records) != 656:
        raise ExperimentARunnerError("exact runner requires all 656 scheduled paths")
    traces = [build_trace(record) for record in records]
    if len({trace["trace_id"] for trace in traces}) != 656:
        raise ExperimentARunnerError("trace identities are not unique")
    return traces


def trace_bytes(traces: Iterable[Mapping[str, object]]) -> bytes:
    return b"".join(freeze.canonical_json_line(trace) for trace in traces)


def parse_trace_bytes(data: bytes) -> list[dict[str, object]]:
    values = freeze.parse_strict_jsonl(data, label="Experiment A exact traces")
    records: list[dict[str, object]] = []
    for value in values:
        if type(value) is not dict:
            raise ExperimentARunnerError("trace record must be an object")
        records.append(value)
    return records


def retry_schedule(
    original: Sequence[Mapping[str, object]], *, prior_attempt_sha256: str
) -> list[dict[str, object]]:
    if (
        type(prior_attempt_sha256) is not str
        or len(prior_attempt_sha256) != 64
        or any(character not in "0123456789abcdef" for character in prior_attempt_sha256)
    ):
        raise ExperimentARunnerError("prior attempt digest must be lowercase SHA-256")
    if not _typed_equal(list(original), freeze.expected_schedule()):
        raise ExperimentARunnerError("retry source is not the exact initial schedule")
    result = []
    for record in original:
        copied = dict(record)
        copied["attempt_number"] = 2
        copied["prior_attempt_sha256"] = prior_attempt_sha256
        copied["run_state"] = "STRUCTURAL_RETRY_PATH_ONLY_PRINCIPAL_BLOCKED"
        result.append(copied)
    return result


def write_attempt_create_once(path: Path, data: bytes) -> str:
    if not isinstance(path, Path) or type(data) is not bytes:
        raise TypeError("path and data must be Path and bytes")
    if path.name not in {"attempt-0001.jsonl", "attempt-0002.jsonl"}:
        raise ExperimentARunnerError("attempt filename is outside the exact schema")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
    )
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise ExperimentARunnerError("short attempt write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return hashlib.sha256(data).hexdigest()


def validate_retry_attempt(
    initial_bytes: bytes, retry_records: Sequence[Mapping[str, object]]
) -> None:
    digest = hashlib.sha256(initial_bytes).hexdigest()
    if len(retry_records) != 656:
        raise ExperimentARunnerError("retry attempt is truncated")
    for initial, retry in zip(freeze.expected_schedule(), retry_records):
        if type(retry) is not dict:
            raise ExperimentARunnerError("retry record must be an object")
        expected = dict(initial)
        expected["attempt_number"] = 2
        expected["prior_attempt_sha256"] = digest
        expected["run_state"] = "STRUCTURAL_RETRY_PATH_ONLY_PRINCIPAL_BLOCKED"
        if not _typed_equal(retry, expected):
            raise ExperimentARunnerError("retry does not exactly bind prior attempt")


def exact_path_mass(traces: Iterable[Mapping[str, object]]) -> dict[str, Fraction]:
    totals: dict[str, Fraction] = {}
    for trace in traces:
        numerator = _strict_int("path_weight_numerator", trace["path_weight_numerator"], minimum=1)
        denominator = _strict_int("path_weight_denominator", trace["path_weight_denominator"], minimum=1)
        row_id = str(trace["row_id"])
        totals[row_id] = totals.get(row_id, Fraction(0, 1)) + Fraction(
            numerator, denominator
        )
    return totals


def main(argv: Sequence[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", type=Path, default=Path(__file__).resolve().parents[4])
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    freeze.validate_repository(args.repository_root)
    traces = generate_trace_records()
    data = trace_bytes(traces)
    if args.output is None:
        os.write(1, data)
    else:
        write_attempt_create_once(args.output, data)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
