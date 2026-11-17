"""Regression specifications for successor namespace isolation.

Declaring a successor reserves a name only inside the predecessor's security
domain: protected object, workflow, and policy epoch.  A same-spelled gate in
an independent domain remains a valid entry gate.
"""

from __future__ import annotations

import pytest

from sluice_v2.monitor import (
    Direction,
    MockBackend,
    Outcome,
    ReferenceMonitor,
    Symbol,
)
from sluice_v2.store import DurableStore


AUTHORIZER_KEY = b"a" * 32


@pytest.fixture()
def monitor_and_store(tmp_path):
    store = DurableStore(str(tmp_path / "sluice.db"))
    monitor = ReferenceMonitor(
        store,
        MockBackend(),
        default_cap_bits=64.0,
        max_cardinality=8,
        trusted_planner_identities=frozenset({"planner"}),
        trusted_authorizer_keys={"approver": AUTHORIZER_KEY},
    )
    yield monitor, store
    store.close()


def _author(
    monitor,
    gate_id,
    protected_object,
    workflow_id,
    *,
    successors=frozenset(),
    epoch=0,
):
    return monitor.author_gate(
        gate_id=gate_id,
        workflow_id=workflow_id,
        protected_object=protected_object,
        direction=Direction.RELEASE,
        symbols=[Symbol("benign"), Symbol("escalate")],
        author_identity="planner",
        permitted_callers=frozenset({"caller"}),
        allowed_successor_gates=frozenset(successors),
        cap_bits=64.0,
        policy_epoch=epoch,
        # This suite isolates successor namespace behavior; the explicit
        # unsafe compatibility mode avoids conflating it with the separate
        # secure-authentication-default regression suite.
        unsafe_allow_unauthenticated_caller=True,
    )


def test_successor_name_isolated_by_protected_object(monitor_and_store):
    monitor, store = monitor_and_store
    _author(
        monitor,
        "object-scope-predecessor",
        "object-scope-a",
        "object-scope-workflow-a",
        successors={"object-scope-target"},
    )
    independent = _author(
        monitor,
        "object-scope-target",
        "object-scope-b",
        "object-scope-workflow-b",
    )

    observation = monitor.invoke(independent, "benign", caller_id="caller")
    assert observation.outcome == Outcome.OK, (
        "a successor declaration for another protected object captured this gate name"
    )


def test_successor_name_isolated_by_workflow(monitor_and_store):
    monitor, store = monitor_and_store
    _author(
        monitor,
        "workflow-scope-predecessor",
        "workflow-scope-object",
        "workflow-scope-a",
        successors={"workflow-scope-target"},
    )
    independent = _author(
        monitor,
        "workflow-scope-target",
        "workflow-scope-object",
        "workflow-scope-b",
    )

    observation = monitor.invoke(independent, "benign", caller_id="caller")
    assert observation.outcome == Outcome.OK, (
        "a successor declaration in another workflow captured this gate name"
    )


def test_successor_name_isolated_by_policy_epoch(monitor_and_store):
    monitor, store = monitor_and_store
    _author(
        monitor,
        "epoch-scope-predecessor",
        "epoch-scope-object",
        "epoch-scope-workflow",
        successors={"epoch-scope-target"},
        epoch=0,
    )
    grant = monitor.issue_reauthorization(
        "epoch-scope-object", 0, 1, 64.0, "approver", AUTHORIZER_KEY
    )
    monitor.redeem_reauthorization(grant)
    independent = _author(
        monitor,
        "epoch-scope-target",
        "epoch-scope-object",
        "epoch-scope-workflow",
        epoch=1,
    )

    observation = monitor.invoke(independent, "benign", caller_id="caller")
    assert observation.outcome == Outcome.OK, (
        "a successor declaration in an old epoch captured this gate name"
    )
