"""Regression specifications for atomic authentication-state redemption.

These tests intentionally fail on the frozen submission.  A valid caller
credential (and, for delegated calls, its one-shot grant) is part of the same
authorization transaction as the gate/capability claim: a rejected claim must
not burn authentication state that never authorized an operation.
"""

from __future__ import annotations

import threading

import pytest

from sluice_v2.actions import ActionTemplate, EffectClass
from sluice_v2.monitor import (
    Direction,
    MockBackend,
    Outcome,
    ReferenceMonitor,
    Symbol,
)
from sluice_v2.store import DurableStore, ReplayError


CONTENT = "benign content"
AGENT_KEYS = {
    "planner": b"p" * 32,
    "worker": b"w" * 32,
}
AUTHORIZER_KEY = b"a" * 32


@pytest.fixture()
def monitor_and_store(tmp_path):
    store = DurableStore(str(tmp_path / "sluice.db"))
    monitor = ReferenceMonitor(
        store,
        MockBackend(),
        default_cap_bits=64.0,
        max_cardinality=8,
        trusted_planner_identities=frozenset({"planner_authority"}),
        trusted_authorizer_keys={"approver": AUTHORIZER_KEY},
        agent_keys=AGENT_KEYS,
    )
    yield monitor, store
    store.close()


def _author(
    monitor,
    gate_id,
    protected_object,
    *,
    successors=frozenset(),
    cap_bits=64.0,
    epoch=0,
):
    return monitor.author_gate(
        gate_id=gate_id,
        workflow_id="wf",
        protected_object=protected_object,
        direction=Direction.RELEASE,
        symbols=[Symbol("benign"), Symbol("escalate")],
        author_identity="planner_authority",
        permitted_callers=frozenset({"planner"}),
        allowed_successor_gates=frozenset(successors),
        cap_bits=cap_bits,
        policy_epoch=epoch,
        unsafe_allow_unauthenticated_caller=False,
    )


def _delegated_attempt_material(monitor, gate_id, *, epoch=0):
    grant = monitor.issue_delegation(
        "planner", AGENT_KEYS["planner"], "worker", gate_id
    )
    credential = monitor.issue_call_credential(
        "worker", AGENT_KEYS["worker"], gate_id, "wf", epoch, CONTENT
    )
    return grant, credential


def _nonce_count(store, credential):
    with store._lock:
        return store._conn.execute(
            "SELECT COUNT(*) FROM consumed_call_nonces "
            "WHERE agent_id=? AND nonce=?",
            (credential.agent_id, credential.nonce),
        ).fetchone()[0]


def _grant_count(store, grant):
    with store._lock:
        return store._conn.execute(
            "SELECT COUNT(*) FROM delegation_grants WHERE grant_id=?",
            (grant.grant_id,),
        ).fetchone()[0]


def _assert_auth_material_unconsumed(store, credential, grant):
    state = (_nonce_count(store, credential), _grant_count(store, grant))
    assert state == (0, 0), (
        "a rejected gate claim consumed authentication state: "
        f"(nonce_rows, grant_rows)={state}"
    )


def test_unauthorized_successor_rolls_back_nonce_and_grant(monitor_and_store):
    monitor, store = monitor_and_store
    predecessor = _author(
        monitor,
        "atomic-predecessor",
        "atomic-successor-object",
        successors={"atomic-successor"},
    )
    successor = _author(monitor, "atomic-successor", "atomic-successor-object")
    grant, credential = _delegated_attempt_material(monitor, "atomic-successor")

    rejected = monitor.invoke(
        successor,
        CONTENT,
        caller_id="worker",
        credential=credential,
        delegation=grant,
    )
    assert rejected.outcome == Outcome.UNAUTHORIZED_SUCCESSOR
    _assert_auth_material_unconsumed(store, credential, grant)

    # Once the missing predecessor is legitimately claimed, the exact same
    # still-valid credential and grant must remain usable.
    predecessor_credential = monitor.issue_call_credential(
        "planner",
        AGENT_KEYS["planner"],
        "atomic-predecessor",
        "wf",
        0,
        CONTENT,
    )
    assert monitor.invoke(
        predecessor,
        CONTENT,
        caller_id="planner",
        credential=predecessor_credential,
    ).outcome == Outcome.OK
    assert monitor.invoke(
        successor,
        CONTENT,
        caller_id="worker",
        credential=credential,
        delegation=grant,
    ).outcome == Outcome.OK


def test_stale_epoch_rolls_back_nonce_and_grant(monitor_and_store):
    monitor, store = monitor_and_store
    handle = _author(monitor, "atomic-stale", "atomic-stale-object")
    grant, credential = _delegated_attempt_material(monitor, "atomic-stale")

    epoch_grant = monitor.issue_reauthorization(
        "atomic-stale-object", 0, 1, 64.0, "approver", AUTHORIZER_KEY
    )
    monitor.redeem_reauthorization(epoch_grant)

    rejected = monitor.invoke(
        handle,
        CONTENT,
        caller_id="worker",
        credential=credential,
        delegation=grant,
    )
    assert rejected.outcome == Outcome.STALE_EPOCH
    _assert_auth_material_unconsumed(store, credential, grant)


def test_budget_denial_rolls_back_nonce_and_grant(monitor_and_store):
    monitor, store = monitor_and_store
    handle = _author(
        monitor,
        "atomic-budget",
        "atomic-budget-object",
        cap_bits=0.0,
    )
    grant, credential = _delegated_attempt_material(monitor, "atomic-budget")

    rejected = monitor.invoke(
        handle,
        CONTENT,
        caller_id="worker",
        credential=credential,
        delegation=grant,
    )
    assert rejected.outcome == Outcome.BUDGET_EXHAUSTED
    _assert_auth_material_unconsumed(store, credential, grant)


def test_gate_replay_rolls_back_fresh_nonce_and_grant(monitor_and_store):
    monitor, store = monitor_and_store
    handle = _author(monitor, "atomic-replay", "atomic-replay-object")

    first_grant, first_credential = _delegated_attempt_material(
        monitor, "atomic-replay"
    )
    assert monitor.invoke(
        handle,
        CONTENT,
        caller_id="worker",
        credential=first_credential,
        delegation=first_grant,
    ).outcome == Outcome.OK

    retry_grant, retry_credential = _delegated_attempt_material(
        monitor, "atomic-replay"
    )
    rejected = monitor.invoke(
        handle,
        CONTENT,
        caller_id="worker",
        credential=retry_credential,
        delegation=retry_grant,
    )
    assert rejected.outcome == Outcome.REPLAYED
    _assert_auth_material_unconsumed(store, retry_credential, retry_grant)


def test_concurrent_failed_budget_claims_consume_no_auth_material(
    monitor_and_store,
):
    monitor, store = monitor_and_store
    handle = _author(
        monitor,
        "atomic-budget-race",
        "atomic-budget-race-object",
        cap_bits=0.0,
    )
    grant, credential = _delegated_attempt_material(monitor, "atomic-budget-race")
    barrier = threading.Barrier(2)
    outcomes = []
    errors = []

    def _attempt():
        try:
            barrier.wait(timeout=5)
            outcomes.append(
                monitor.invoke(
                    handle,
                    CONTENT,
                    caller_id="worker",
                    credential=credential,
                    delegation=grant,
                ).outcome
            )
        except BaseException as exc:  # noqa: BLE001 - asserted below
            errors.append(exc)

    threads = [threading.Thread(target=_attempt) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert not errors
    assert outcomes == [Outcome.BUDGET_EXHAUSTED, Outcome.BUDGET_EXHAUSTED]
    _assert_auth_material_unconsumed(store, credential, grant)


def test_failed_capability_replay_rolls_back_adjacent_credential_nonce(
    monitor_and_store,
):
    monitor, store = monitor_and_store
    action = ActionTemplate(
        name="send_message",
        tool="send_message",
        max_effect_class=EffectClass.REVERSIBLE,
    )
    handle = monitor.author_gate(
        gate_id="atomic-action",
        workflow_id="wf",
        protected_object="atomic-action-object",
        direction=Direction.ENDORSE,
        symbols=[Symbol("send", action=action)],
        author_identity="planner_authority",
        permitted_callers=frozenset({"planner"}),
        cap_bits=64.0,
        max_effect_class=EffectClass.REVERSIBLE,
        unsafe_allow_unauthenticated_caller=True,
    )
    observation = monitor.invoke(
        handle,
        "send",
        caller_id="planner",
        redeemer_agent_id="worker",
    )
    assert observation.outcome == Outcome.OK

    first_credential = monitor.issue_call_credential(
        "worker",
        AGENT_KEYS["worker"],
        "atomic-action",
        "",
        0,
        observation.capability_id,
        args=dict(observation.authorized_args),
    )
    monitor.consume_action_capability(observation, credential=first_credential)

    retry_credential = monitor.issue_call_credential(
        "worker",
        AGENT_KEYS["worker"],
        "atomic-action",
        "",
        0,
        observation.capability_id,
        args=dict(observation.authorized_args),
    )
    with pytest.raises(ReplayError):
        monitor.consume_action_capability(
            observation, credential=retry_credential
        )
    assert _nonce_count(store, retry_credential) == 0, (
        "a failed action-capability claim consumed its adjacent credential nonce"
    )
