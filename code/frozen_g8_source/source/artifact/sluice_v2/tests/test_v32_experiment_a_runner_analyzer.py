"""Known-answer and adversarial tests for the exact Experiment A pipeline."""

from __future__ import annotations

import copy
from fractions import Fraction
import hashlib
from pathlib import Path

import pytest

from sluice_v2.evaluation import experiment_a_analyzer as analyzer
from sluice_v2.evaluation import experiment_a_freeze as freeze
from sluice_v2.evaluation import experiment_a_runner as runner


def _traces():
    return runner.generate_trace_records()


def _report():
    return analyzer.analyze_traces(_traces())


def _row(report, prior, condition, horizon):
    matches = [
        row
        for row in report["rows"]
        if row["prior_id"] == prior
        and row["condition_id"] == condition
        and row["epoch_attempt_horizon_h"] == horizon
    ]
    assert len(matches) == 1
    return matches[0]


def _basis(row, observer):
    wire = row["observers"][observer]["mutual_information_bits"]
    return wire["constant"], wire["log2_3_coefficient"]


def test_runner_is_deterministic_complete_and_exactly_weighted() -> None:
    first = _traces()
    second = _traces()
    assert len(first) == 656
    assert runner._typed_equal(first, second)
    first_bytes = runner.trace_bytes(first)
    assert first_bytes == runner.trace_bytes(second)
    assert hashlib.sha256(first_bytes).hexdigest() == hashlib.sha256(
        runner.trace_bytes(runner.parse_trace_bytes(first_bytes))
    ).hexdigest()
    assert all(trace["principal_eligible"] is False for trace in first)
    assert all(
        len(trace["events"]) == trace["public_outer_capture_hmax"]
        for trace in first
    )
    assert set(runner.exact_path_mass(first).values()) == {Fraction(1, 1)}


def test_analyzer_known_answer_information_laws_and_decisions() -> None:
    report = _report()
    assert report["total_paths"] == 656
    assert report["matrix_rows"] == 14
    assert report["all_positive_assertion_bounds_hold"] is True
    assert report["principal_eligible"] is False

    expected_a1 = {
        "unmediated": ("4/1", "0/1", "CERTIFIED_BOUND_OVERSHOOT"),
        "sluice_result_only_accounting_old_design": (
            "4/1",
            "0/1",
            "CERTIFIED_BOUND_OVERSHOOT",
        ),
        "sluice_complete_typed_transcript": ("4/1", "0/1", "BOUND_HOLDS"),
        "sluice_without_attempt_horizon_enforcement": (
            "4/1",
            "0/1",
            "BOUND_HOLDS",
        ),
        "sluice_with_success_only_route_charging": (
            "4/1",
            "0/1",
            "CERTIFIED_BOUND_OVERSHOOT",
        ),
        "sluice_with_route_denial_stopping_enforcement": (
            "4/1",
            "0/1",
            "BOUND_HOLDS",
        ),
    }
    for condition, (constant, coefficient, decision) in expected_a1.items():
        row = _row(report, "A1", condition, 16)
        assert _basis(row, "colluding_union") == (constant, coefficient)
        assert row["observers"]["colluding_union"]["bound_decision"] == decision

    per_object = _row(report, "A2", "per_object_budgets", 16)
    assert _basis(per_object, "observer_A") == ("1/1", "0/1")
    assert _basis(per_object, "observer_B") == ("1/1", "0/1")
    assert _basis(per_object, "colluding_union") == ("3/1", "-3/4")
    assert (
        per_object["observers"]["colluding_union"]["bound_decision"]
        == "CERTIFIED_BOUND_OVERSHOOT"
    )

    shared = _row(report, "A2", "shared_correlated_secret_budget_domains", 16)
    assert _basis(shared, "observer_A") == ("1/1", "-3/8")
    assert _basis(shared, "observer_B") == ("1/1", "-3/8")
    assert _basis(shared, "colluding_union") == ("2/1", "-3/4")
    assert shared["observers"]["colluding_union"]["bound_decision"] == "BOUND_HOLDS"


def test_exact_charge_utility_count_and_horizon_sensitivity_endpoints() -> None:
    report = _report()
    expected_charge = {
        "unmediated": "0/1",
        "sluice_result_only_accounting_old_design": "2/1",
        "sluice_complete_typed_transcript": "23/4",
        "sluice_without_attempt_horizon_enforcement": "32/1",
        "sluice_with_success_only_route_charging": "2/1",
        "sluice_with_route_denial_stopping_enforcement": "23/4",
    }
    for condition, charge in expected_charge.items():
        row = _row(report, "A1", condition, 16)
        assert row["exact_expected_charge_units"] == charge
        assert row["exact_requested_field_utility"] == "1/1"
        assert row["exact_path_count"] == 64
        assert row["exact_path_mass"] == "1/1"
    per_object = _row(report, "A2", "per_object_budgets", 16)
    shared = _row(report, "A2", "shared_correlated_secret_budget_domains", 16)
    assert per_object["exact_expected_charge_units"] == "15/4"
    assert per_object["exact_requested_field_utility"] == "1/1"
    assert shared["exact_expected_charge_units"] == "11/4"
    assert shared["exact_requested_field_utility"] == "1/2"
    for prior, condition in (
        ("A1", "sluice_complete_typed_transcript"),
        ("A2", "shared_correlated_secret_budget_domains"),
    ):
        for horizon in (4, 8, 32):
            row = _row(report, prior, condition, horizon)
            assert row["public_outer_capture_hmax"] == 2 * horizon
            assert row["mechanism_attempt_horizon_enforced"] is True


def test_public_hmax_does_not_masquerade_as_mechanism_horizon() -> None:
    report = _report()
    row = _row(
        report,
        "A1",
        "sluice_without_attempt_horizon_enforcement",
        16,
    )
    assert row["public_outer_capture_hmax"] == 32
    assert row["mechanism_attempt_horizon_enforced"] is False
    traces = [
        trace
        for trace in _traces()
        if trace["row_id"] == row["row_id"]
    ]
    assert all(
        all(event["kind"] == "UNBOUNDED_ACTIVE_ATTEMPT" for event in trace["events"])
        for trace in traces
    )


def test_reauthorization_never_resets_lifetime_and_reuse_cannot_extend() -> None:
    traces = _traces()
    candidates = [
        trace
        for trace in traces
        if trace["condition_id"] == "sluice_complete_typed_transcript"
        and trace["public_tape_id"] == "tape-3"
        and trace["public_outer_capture_hmax"] == 32
    ]
    assert candidates
    for trace in candidates:
        events = trace["events"]
        reauth = [event for event in events if event["outcome"] == "REAUTHORIZED"]
        replay = [
            event for event in events if event["outcome"] == "REAUTH_DENIED_REPLAY"
        ]
        assert len(reauth) == len(replay) == 1
        assert reauth[0]["epoch_before"] == 0
        assert reauth[0]["epoch_after"] == 1
        assert replay[0]["epoch_before"] == replay[0]["epoch_after"] == 1
        lifetimes = [event["lifetime_spend_after"] for event in events]
        assert lifetimes == sorted(lifetimes)
        assert trace["realized_charge_units"] == lifetimes[-1]


def test_omitted_support_or_projection_fails_closed() -> None:
    traces = _traces()
    omitted_support = copy.deepcopy(traces)
    del omitted_support[0]["events"][0]["observer_support"]
    with pytest.raises(analyzer.ExperimentAAnalysisError, match="differs|support"):
        analyzer.analyze_traces(omitted_support)

    omitted_projection = copy.deepcopy(traces)
    del omitted_projection[0]["events"][0]["observer_projection"]["observer_B"]
    with pytest.raises(analyzer.ExperimentAAnalysisError, match="differs|projection"):
        analyzer.analyze_traces(omitted_projection)


def test_trace_truncation_duplicate_and_float_only_inputs_fail_closed() -> None:
    traces = _traces()
    with pytest.raises(analyzer.ExperimentAAnalysisError, match="656"):
        analyzer.analyze_traces(traces[:-1])

    duplicate = copy.deepcopy(traces)
    duplicate[1] = copy.deepcopy(duplicate[0])
    with pytest.raises(analyzer.ExperimentAAnalysisError, match="differs|duplicate"):
        analyzer.analyze_traces(duplicate)

    truncated = copy.deepcopy(traces)
    truncated[0]["events"].pop()
    with pytest.raises(analyzer.ExperimentAAnalysisError, match="differs|truncated"):
        analyzer.analyze_traces(truncated)

    float_weight = copy.deepcopy(traces)
    float_weight[0]["path_weight_numerator"] = 1.0
    with pytest.raises(analyzer.ExperimentAAnalysisError, match="differs|integer"):
        analyzer.analyze_traces(float_weight)

    bool_charge = copy.deepcopy(traces)
    bool_charge[0]["events"][0]["charge_units"] = False
    with pytest.raises(analyzer.ExperimentAAnalysisError, match="differs|integer"):
        analyzer.analyze_traces(bool_charge)


def test_reauthorization_reset_and_reuse_mutations_fail_closed() -> None:
    traces = _traces()
    target_index = next(
        index
        for index, trace in enumerate(traces)
        if trace["condition_id"] == "sluice_complete_typed_transcript"
        and trace["public_tape_id"] == "tape-3"
    )
    reset = copy.deepcopy(traces)
    reset[target_index]["events"][-1]["lifetime_spend_after"] = 0
    with pytest.raises(analyzer.ExperimentAAnalysisError):
        analyzer.analyze_traces(reset)

    reuse = copy.deepcopy(traces)
    replay = next(
        event
        for event in reuse[target_index]["events"]
        if event["outcome"] == "REAUTH_DENIED_REPLAY"
    )
    replay["epoch_after"] = 2
    with pytest.raises(analyzer.ExperimentAAnalysisError):
        analyzer.analyze_traces(reuse)


def test_retry_is_append_only_create_once_and_hash_linked(tmp_path: Path) -> None:
    initial_schedule = freeze.expected_schedule()
    initial_traces = _traces()
    initial_bytes = runner.trace_bytes(initial_traces)
    attempt1 = tmp_path / "attempt-0001.jsonl"
    digest = runner.write_attempt_create_once(attempt1, initial_bytes)
    assert digest == hashlib.sha256(initial_bytes).hexdigest()
    with pytest.raises(FileExistsError):
        runner.write_attempt_create_once(attempt1, initial_bytes)

    retries = runner.retry_schedule(
        initial_schedule, prior_attempt_sha256=digest
    )
    runner.validate_retry_attempt(initial_bytes, retries)
    corrupted = copy.deepcopy(retries)
    corrupted[0]["prior_attempt_sha256"] = "0" * 64
    with pytest.raises(runner.ExperimentARunnerError, match="bind"):
        runner.validate_retry_attempt(initial_bytes, corrupted)


def test_decision_interval_is_far_tighter_than_frozen_tolerance() -> None:
    report = _report()
    for row in report["rows"]:
        for observer in row["observers"].values():
            mi = observer["mutual_information_bits"]
            width = analyzer.Decimal(mi["interval_upper"]) - analyzer.Decimal(
                mi["interval_lower"]
            )
            assert width < analyzer.Decimal(freeze.DECISION_TOLERANCE) / 1000
            assert observer["bound_decision"] != "AMBIGUOUS_FAIL_CLOSED"
