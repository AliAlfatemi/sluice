"""Regression tests for non-poisoning budget-denial semantics."""

from __future__ import annotations

import pytest

from sluice_v2.monitor import (
    Direction,
    MockBackend,
    Outcome,
    ReferenceMonitor,
    Symbol,
    gate_cost_bits,
)
from sluice_v2.store import DurableStore


PLANNER_KEY = b"planner-agent-key-material-32bytes"
WORKER_KEY = b"worker-agent-key-material--32bytes"
CONTENT = "s0"
LOW_COST_BITS = gate_cost_bits(1)


def _monitor(tmp_path, name: str):
    store = DurableStore(str(tmp_path / f"{name}.db"))
    monitor = ReferenceMonitor(
        store,
        MockBackend(),
        default_cap_bits=LOW_COST_BITS,
        max_cardinality=8,
        trusted_planner_identities=frozenset({"planner-authority"}),
        agent_keys={"planner": PLANNER_KEY, "worker": WORKER_KEY},
    )
    return monitor, store


def _author(
    monitor: ReferenceMonitor,
    gate_id: str,
    protected_object: str,
    cardinality: int,
):
    return monitor.author_gate(
        gate_id=gate_id,
        workflow_id="wf-budget-availability",
        protected_object=protected_object,
        direction=Direction.RELEASE,
        symbols=[Symbol(f"s{i}") for i in range(cardinality)],
        author_identity="planner-authority",
        permitted_callers=frozenset({"planner"}),
        cap_bits=LOW_COST_BITS,
        unsafe_allow_unauthenticated_caller=False,
    )


def _credential(
    monitor: ReferenceMonitor,
    agent_id: str,
    key: bytes,
    gate_id: str,
):
    return monitor.issue_call_credential(
        agent_id,
        key,
        gate_id,
        "wf-budget-availability",
        0,
        CONTENT,
    )


def test_unaffordable_direct_attempt_does_not_mark_epoch_for_reauthorization(
    tmp_path,
):
    monitor, store = _monitor(tmp_path, "direct-flag")
    try:
        expensive = _author(monitor, "direct-expensive", "direct-flag-object", 8)
        credential = _credential(monitor, "planner", PLANNER_KEY, expensive.gate_id)

        denied = monitor.invoke(
            expensive,
            CONTENT,
            caller_id="planner",
            credential=credential,
        )

        assert denied.outcome == Outcome.BUDGET_EXHAUSTED
        assert store.spent("direct-flag-object", 0) == 0.0
        assert store.reauth_required("direct-flag-object", 0) is False
    finally:
        store.close()


def test_unaffordable_direct_attempt_leaves_exactly_affordable_gate_usable(
    tmp_path,
):
    monitor, store = _monitor(tmp_path, "direct-lower-gate")
    try:
        protected_object = "direct-lower-object"
        expensive = _author(monitor, "direct-high", protected_object, 8)
        affordable = _author(monitor, "direct-low", protected_object, 1)

        high_observation = monitor.invoke(
            expensive,
            CONTENT,
            caller_id="planner",
            credential=_credential(monitor, "planner", PLANNER_KEY, expensive.gate_id),
        )
        low_observation = monitor.invoke(
            affordable,
            CONTENT,
            caller_id="planner",
            credential=_credential(monitor, "planner", PLANNER_KEY, affordable.gate_id),
        )

        assert high_observation.outcome == Outcome.BUDGET_EXHAUSTED
        assert low_observation.outcome == Outcome.OK
        assert store.spent(protected_object, 0) == pytest.approx(LOW_COST_BITS)
    finally:
        store.close()


def test_gate_at_exact_budget_boundary_is_authorized(tmp_path):
    monitor, store = _monitor(tmp_path, "exact-boundary")
    try:
        protected_object = "exact-boundary-object"
        affordable = _author(monitor, "exact-boundary-gate", protected_object, 1)

        observation = monitor.invoke(
            affordable,
            CONTENT,
            caller_id="planner",
            credential=_credential(monitor, "planner", PLANNER_KEY, affordable.gate_id),
        )

        assert observation.outcome == Outcome.OK
        assert observation.charged_bits == pytest.approx(LOW_COST_BITS)
        assert store.spent(protected_object, 0) == pytest.approx(LOW_COST_BITS)
    finally:
        store.close()


def test_unaffordable_delegated_attempt_leaves_affordable_gate_usable(tmp_path):
    monitor, store = _monitor(tmp_path, "delegated-lower-gate")
    try:
        protected_object = "delegated-lower-object"
        expensive = _author(monitor, "delegated-high", protected_object, 8)
        affordable = _author(monitor, "delegated-low", protected_object, 1)

        high_grant = monitor.issue_delegation(
            "planner", PLANNER_KEY, "worker", expensive.gate_id
        )
        high_observation = monitor.invoke(
            expensive,
            CONTENT,
            caller_id="worker",
            credential=_credential(monitor, "worker", WORKER_KEY, expensive.gate_id),
            delegation=high_grant,
        )

        low_grant = monitor.issue_delegation(
            "planner", PLANNER_KEY, "worker", affordable.gate_id
        )
        low_observation = monitor.invoke(
            affordable,
            CONTENT,
            caller_id="worker",
            credential=_credential(monitor, "worker", WORKER_KEY, affordable.gate_id),
            delegation=low_grant,
        )

        assert high_observation.outcome == Outcome.BUDGET_EXHAUSTED
        assert low_observation.outcome == Outcome.OK
        assert store.spent(protected_object, 0) == pytest.approx(LOW_COST_BITS)
    finally:
        store.close()
