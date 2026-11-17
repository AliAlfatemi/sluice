"""Independent regression audit for the v6 transactional core repair.

This file intentionally uses only public monitor operations except where it
must inspect durable rows or construct an exact v4 schema fixture.
"""

from __future__ import annotations

from collections import Counter
import math
import sqlite3
import threading
import time

import pytest

from sluice_v2.actions import ActionTemplate, EffectClass
from sluice_v2.monitor import (
    Direction,
    MockBackend,
    Outcome,
    ProvenanceViolation,
    ReferenceMonitor,
    Symbol,
    gate_cost_units,
)
from sluice_v2.store import (
    DurableStore,
    PreparedAuthorization,
    StoreInvariantError,
)


PLANNER_KEY = b"p" * 32
WORKER_KEY = b"w" * 32
CONTENT = "benign"


def _prepared(**overrides) -> PreparedAuthorization:
    values = {
        "agent_id": "worker",
        "nonce": "nonce",
        "gate_id": "not-even-looked-up",
        "workflow_id": "audit-workflow",
        "policy_epoch": 0,
        "expires_at": 10**20,
    }
    values.update(overrides)
    return PreparedAuthorization(**values)


def _monitor(store: DurableStore) -> ReferenceMonitor:
    return ReferenceMonitor(
        store,
        MockBackend(),
        default_cap_bits=128.0,
        max_cardinality=8,
        trusted_planner_identities=frozenset({"planner-authority"}),
        agent_keys={"planner": PLANNER_KEY, "worker": WORKER_KEY},
    )


def _author(
    monitor: ReferenceMonitor,
    gate_id: str,
    *,
    protected_object: str = "audit-object",
    workflow_id: str = "audit-workflow",
    successors=frozenset(),
    unsafe: bool = False,
):
    return monitor.author_gate(
        gate_id=gate_id,
        workflow_id=workflow_id,
        protected_object=protected_object,
        direction=Direction.RELEASE,
        symbols=[Symbol("benign"), Symbol("escalate")],
        author_identity="planner-authority",
        permitted_callers=frozenset({"planner"}),
        allowed_successor_gates=frozenset(successors),
        cap_bits=128.0,
        unsafe_allow_unauthenticated_caller=unsafe,
    )


def _delegated_material(monitor: ReferenceMonitor, gate_id: str):
    grant = monitor.issue_delegation(
        "planner", PLANNER_KEY, "worker", gate_id
    )
    credential = monitor.issue_call_credential(
        "worker",
        WORKER_KEY,
        gate_id,
        "audit-workflow",
        0,
        CONTENT,
    )
    return grant, credential


def _count(store: DurableStore, sql: str, parameters=()) -> int:
    with store._lock:
        return int(store._conn.execute(sql, parameters).fetchone()[0])


def test_invocation_audit_failure_rolls_back_entire_delegated_claim(
    tmp_path, monkeypatch
):
    store = DurableStore(str(tmp_path / "audit-rollback.db"))
    monitor = _monitor(store)
    handle = _author(monitor, "audit-rollback-gate")
    grant, credential = _delegated_material(monitor, handle.gate_id)
    original_append = store.append_audit

    def fail_invocation_start(gate_id, event, detail, conn=None):
        if event == "invocation_started":
            raise RuntimeError("injected audit append failure")
        return original_append(gate_id, event, detail, conn=conn)

    monkeypatch.setattr(store, "append_audit", fail_invocation_start)
    with pytest.raises(RuntimeError, match="injected audit append failure"):
        monitor.invoke(
            handle,
            CONTENT,
            caller_id="worker",
            credential=credential,
            delegation=grant,
        )

    assert _count(
        store, "SELECT consumed FROM gates WHERE gate_id=?", (handle.gate_id,)
    ) == 0
    assert store.spent_units("audit-object", 0) == 0
    assert _count(
        store,
        "SELECT COUNT(*) FROM consumed_call_nonces WHERE agent_id=? AND nonce=?",
        (credential.agent_id, credential.nonce),
    ) == 0
    assert _count(
        store,
        "SELECT COUNT(*) FROM delegation_grants WHERE grant_id=?",
        (grant.grant_id,),
    ) == 0
    assert _count(store, "SELECT COUNT(*) FROM object_sequence") == 0
    assert _count(
        store,
        "SELECT COUNT(*) FROM audit_log WHERE event IN "
        "('delegation_redeemed','invocation_started')",
    ) == 0

    # Rollback must make the exact same still-valid proof usable on retry.
    monkeypatch.setattr(store, "append_audit", original_append)
    assert monitor.invoke(
        handle,
        CONTENT,
        caller_id="worker",
        credential=credential,
        delegation=grant,
    ).outcome == Outcome.OK
    store.close()


def test_two_connections_redeeming_same_credential_commit_exactly_once(tmp_path):
    database = tmp_path / "two-connection-race.db"
    store_a = DurableStore(str(database))
    monitor_a = _monitor(store_a)
    handle = _author(monitor_a, "two-connection-gate")
    grant, credential = _delegated_material(monitor_a, handle.gate_id)

    # A second store gives the contenders independent SQLite connections and
    # locks; correctness therefore cannot come only from one Python RLock.
    store_b = DurableStore(str(database))
    monitor_b = _monitor(store_b)
    barrier = threading.Barrier(2)
    outcomes = []
    errors = []

    def attempt(monitor):
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

    threads = [
        threading.Thread(target=attempt, args=(monitor_a,)),
        threading.Thread(target=attempt, args=(monitor_b,)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=15)

    assert not any(thread.is_alive() for thread in threads)
    assert not errors
    assert Counter(outcomes) == Counter(
        {Outcome.OK: 1, Outcome.UNAUTHORIZED_DELEGATION: 1}
    )
    assert _count(
        store_a, "SELECT consumed FROM gates WHERE gate_id=?", (handle.gate_id,)
    ) == 1
    assert store_a.spent_units("audit-object", 0) == gate_cost_units(2)
    assert _count(
        store_a,
        "SELECT COUNT(*) FROM consumed_call_nonces WHERE agent_id=? AND nonce=?",
        (credential.agent_id, credential.nonce),
    ) == 1
    assert _count(
        store_a,
        "SELECT COUNT(*) FROM delegation_grants WHERE grant_id=?",
        (grant.grant_id,),
    ) == 1
    assert _count(
        store_a,
        "SELECT COUNT(*) FROM audit_log WHERE event='invocation_started'",
    ) == 1
    store_b.close()
    store_a.close()


def test_capability_audit_failure_rolls_back_capability_and_nonce(
    tmp_path, monkeypatch
):
    store = DurableStore(str(tmp_path / "capability-audit-rollback.db"))
    monitor = _monitor(store)
    action = ActionTemplate(
        name="send_message",
        tool="send_message",
        max_effect_class=EffectClass.REVERSIBLE,
    )
    handle = monitor.author_gate(
        gate_id="capability-audit-gate",
        workflow_id="audit-workflow",
        protected_object="capability-audit-object",
        direction=Direction.ENDORSE,
        symbols=[Symbol("benign", action=action)],
        author_identity="planner-authority",
        permitted_callers=frozenset({"planner"}),
        cap_bits=128.0,
        max_effect_class=EffectClass.REVERSIBLE,
        unsafe_allow_unauthenticated_caller=True,
    )
    observation = monitor.invoke(
        handle,
        CONTENT,
        caller_id="planner",
        redeemer_agent_id="worker",
    )
    assert observation.outcome == Outcome.OK
    credential = monitor.issue_call_credential(
        "worker",
        WORKER_KEY,
        observation.gate_id,
        "",
        observation.policy_epoch,
        observation.capability_id,
        args=dict(observation.authorized_args),
    )
    original_append = store.append_audit

    def fail_capability_audit(gate_id, event, detail, conn=None):
        if event == "action_capability_consumed":
            raise RuntimeError("injected capability audit failure")
        return original_append(gate_id, event, detail, conn=conn)

    monkeypatch.setattr(store, "append_audit", fail_capability_audit)
    with pytest.raises(RuntimeError, match="injected capability audit failure"):
        monitor.consume_action_capability(observation, credential=credential)

    assert _count(
        store,
        "SELECT consumed FROM action_capabilities WHERE capability_id=?",
        (observation.capability_id,),
    ) == 0
    assert _count(
        store,
        "SELECT COUNT(*) FROM consumed_call_nonces WHERE agent_id=? AND nonce=?",
        (credential.agent_id, credential.nonce),
    ) == 0
    assert _count(
        store,
        "SELECT COUNT(*) FROM audit_log WHERE event='action_capability_consumed'",
    ) == 0

    monkeypatch.setattr(store, "append_audit", original_append)
    redeemed_action, redeemed_args = monitor.consume_action_capability(
        observation, credential=credential
    )
    assert redeemed_action == action
    assert redeemed_args == dict(observation.authorized_args)
    store.close()


def test_v4_schema_migrates_scopes_and_repairs_poisoned_budget_flag(tmp_path):
    database = tmp_path / "v4-migration.db"
    store = DurableStore(str(database))
    monitor = _monitor(store)
    predecessor = _author(
        monitor,
        "migration-predecessor",
        protected_object="migration-object",
        workflow_id="migration-workflow",
        successors={"migration-successor"},
    )
    credential = monitor.issue_call_credential(
        "planner",
        PLANNER_KEY,
        predecessor.gate_id,
        "migration-workflow",
        0,
        CONTENT,
    )
    assert monitor.invoke(
        predecessor,
        CONTENT,
        caller_id="planner",
        credential=credential,
    ).outcome == Outcome.OK
    store.close()

    # Rebuild only the two tables whose v4 primary keys lacked security scope.
    # All other rows were produced by the public API and are authentic v4-
    # compatible data.
    conn = sqlite3.connect(str(database), isolation_level=None)
    conn.execute("BEGIN IMMEDIATE")
    conn.execute(
        "CREATE TABLE object_sequence_v4 ("
        "protected_object TEXT NOT NULL, policy_epoch INTEGER NOT NULL, "
        "last_gate_id TEXT NOT NULL, chain_opted_in INTEGER NOT NULL DEFAULT 0, "
        "PRIMARY KEY (protected_object, policy_epoch))"
    )
    conn.execute(
        "INSERT INTO object_sequence_v4 "
        "SELECT protected_object, policy_epoch, last_gate_id, chain_opted_in "
        "FROM object_sequence"
    )
    conn.execute("DROP TABLE object_sequence")
    conn.execute("ALTER TABLE object_sequence_v4 RENAME TO object_sequence")
    conn.execute(
        "CREATE TABLE declared_successors_v4 ("
        "successor_gate_id TEXT NOT NULL, predecessor_gate_id TEXT NOT NULL, "
        "PRIMARY KEY (successor_gate_id, predecessor_gate_id))"
    )
    conn.execute(
        "INSERT INTO declared_successors_v4 "
        "SELECT successor_gate_id, predecessor_gate_id FROM declared_successors"
    )
    conn.execute("DROP TABLE declared_successors")
    conn.execute("ALTER TABLE declared_successors_v4 RENAME TO declared_successors")
    conn.execute(
        "UPDATE budgets SET reauth_required=1 "
        "WHERE protected_object='migration-object'"
    )
    conn.execute("PRAGMA user_version=4")
    conn.execute("COMMIT")
    conn.close()

    migrated = DurableStore(str(database))
    try:
        assert migrated.effective_pragmas()["user_version"] == 5
        with migrated._lock:
            sequence_columns = {
                row[1]
                for row in migrated._conn.execute(
                    "PRAGMA table_info(object_sequence)"
                )
            }
            successor_columns = {
                row[1]
                for row in migrated._conn.execute(
                    "PRAGMA table_info(declared_successors)"
                )
            }
            sequence = migrated._conn.execute(
                "SELECT protected_object, workflow_id, policy_epoch, "
                "last_gate_id FROM object_sequence"
            ).fetchone()
            successor = migrated._conn.execute(
                "SELECT protected_object, workflow_id, policy_epoch, "
                "successor_gate_id, predecessor_gate_id FROM declared_successors"
            ).fetchone()
        assert "workflow_id" in sequence_columns
        assert {
            "protected_object", "workflow_id", "policy_epoch"
        }.issubset(successor_columns)
        assert sequence == (
            "migration-object", "migration-workflow", 0, "migration-predecessor"
        )
        assert successor == (
            "migration-object",
            "migration-workflow",
            0,
            "migration-successor",
            "migration-predecessor",
        )
        assert migrated.spent_units("migration-object", 0) < 128_000_000
        assert migrated.reauth_required("migration-object", 0) is False
    finally:
        migrated.close()


def test_v4_migration_rejects_same_scope_conflicting_predecessors_atomically(
    tmp_path,
):
    database = tmp_path / "v4-conflicting-predecessors.db"
    store = DurableStore(str(database))
    monitor = _monitor(store)
    scope = {
        "protected_object": "legacy-conflict-object",
        "workflow_id": "legacy-conflict-workflow",
        "unsafe": True,
    }
    _author(monitor, "legacy-first-predecessor", **scope)
    _author(monitor, "legacy-second-predecessor", **scope)
    store.close()

    conn = sqlite3.connect(str(database), isolation_level=None)
    conn.execute("BEGIN IMMEDIATE")
    conn.execute(
        "CREATE TABLE object_sequence_v4 ("
        "protected_object TEXT NOT NULL, policy_epoch INTEGER NOT NULL, "
        "last_gate_id TEXT NOT NULL, chain_opted_in INTEGER NOT NULL DEFAULT 0, "
        "PRIMARY KEY (protected_object, policy_epoch))"
    )
    conn.execute(
        "INSERT INTO object_sequence_v4 "
        "SELECT protected_object, policy_epoch, last_gate_id, chain_opted_in "
        "FROM object_sequence"
    )
    conn.execute("DROP TABLE object_sequence")
    conn.execute("ALTER TABLE object_sequence_v4 RENAME TO object_sequence")
    conn.execute("DROP TABLE declared_successors")
    conn.execute(
        "CREATE TABLE declared_successors ("
        "successor_gate_id TEXT NOT NULL, predecessor_gate_id TEXT NOT NULL, "
        "PRIMARY KEY (successor_gate_id, predecessor_gate_id))"
    )
    conn.executemany(
        "INSERT INTO declared_successors VALUES (?,?)",
        [
            ("legacy-shared-successor", "legacy-first-predecessor"),
            ("legacy-shared-successor", "legacy-second-predecessor"),
        ],
    )
    conn.execute("PRAGMA user_version=4")
    conn.execute("COMMIT")
    conn.close()

    with pytest.raises(StoreInvariantError, match="conflicting predecessors"):
        DurableStore(str(database))

    # Schema initialization is one EXCLUSIVE transaction: the failed v5
    # rebuild must not leave a half-migrated database behind.
    with sqlite3.connect(str(database)) as unchanged:
        assert unchanged.execute("PRAGMA user_version").fetchone()[0] == 4
        successor_columns = {
            row[1]
            for row in unchanged.execute("PRAGMA table_info(declared_successors)")
        }
        assert successor_columns == {"successor_gate_id", "predecessor_gate_id"}
        assert unchanged.execute(
            "SELECT COUNT(*) FROM declared_successors"
        ).fetchone()[0] == 2
        assert unchanged.execute(
            "SELECT COUNT(*) FROM sqlite_master "
            "WHERE type='table' AND name LIKE '%_v5'"
        ).fetchone()[0] == 0


@pytest.mark.parametrize(
    "authorization",
    [
        object(),
        {"agent_id": "worker", "nonce": "nonce"},
        _prepared(agent_id=""),
        _prepared(nonce=""),
        _prepared(agent_id=True),
        _prepared(gate_id="different-operation"),
        _prepared(workflow_id=True),
        _prepared(policy_epoch=True),
        _prepared(expires_at=True),
        _prepared(expires_at=math.inf),
        _prepared(grant_id="grant"),
        _prepared(
            grant_id="grant",
            delegator_agent_id="planner",
            delegate_agent_id="another-agent",
        ),
        _prepared(delegation_expires_at=10**20),
        _prepared(
            grant_id="grant",
            delegator_agent_id="planner",
            delegate_agent_id="worker",
            delegation_expires_at=math.inf,
        ),
    ],
)
def test_claim_rejects_malformed_prepared_authorization_before_state_change(
    tmp_path, authorization
):
    store = DurableStore(str(tmp_path / "malformed-prepared.db"))
    try:
        with pytest.raises(ValueError):
            store.claim_and_reserve_gate("not-even-looked-up", authorization=authorization)
        assert _count(store, "SELECT COUNT(*) FROM consumed_call_nonces") == 0
        assert _count(store, "SELECT COUNT(*) FROM delegation_grants") == 0
    finally:
        store.close()


def test_direct_credential_expired_at_atomic_commit_is_rejected(
    tmp_path, monkeypatch
):
    store = DurableStore(str(tmp_path / "direct-expiry-at-commit.db"))
    monitor = _monitor(store)
    handle = _author(monitor, "direct-expiry-at-commit")
    credential = monitor.issue_call_credential(
        "planner",
        PLANNER_KEY,
        handle.gate_id,
        "audit-workflow",
        0,
        CONTENT,
        ttl_seconds=300.0,
    )
    original_claim = store.claim_and_reserve_gate

    def expire_then_claim(*args, **kwargs):
        # invoke() has already completed cryptographic/freshness verification.
        # Advance the shared clock only at the store boundary to model time
        # spent waiting for the SQLite write lock.
        monkeypatch.setattr(
            "sluice_v2.store.time.time", lambda: credential.expires_at + 1.0
        )
        return original_claim(*args, **kwargs)

    monkeypatch.setattr(store, "claim_and_reserve_gate", expire_then_claim)
    rejected = monitor.invoke(
        handle,
        CONTENT,
        caller_id="planner",
        credential=credential,
    )

    assert rejected.outcome == Outcome.UNAUTHENTICATED_CALLER
    assert rejected.charged_bits == 0.0
    assert _count(
        store, "SELECT consumed FROM gates WHERE gate_id=?", (handle.gate_id,)
    ) == 0
    assert store.spent_units("audit-object", 0) == 0
    assert _count(
        store,
        "SELECT COUNT(*) FROM consumed_call_nonces WHERE agent_id=? AND nonce=?",
        (credential.agent_id, credential.nonce),
    ) == 0
    assert _count(store, "SELECT COUNT(*) FROM object_sequence") == 0
    store.close()


def test_delegation_expired_at_atomic_commit_is_rejected(tmp_path, monkeypatch):
    store = DurableStore(str(tmp_path / "delegation-expiry-at-commit.db"))
    monitor = _monitor(store)
    handle = _author(monitor, "delegation-expiry-at-commit")
    delegation = monitor.issue_delegation(
        "planner",
        PLANNER_KEY,
        "worker",
        handle.gate_id,
        expiration=time.time() + 100.0,
    )
    credential = monitor.issue_call_credential(
        "worker",
        WORKER_KEY,
        handle.gate_id,
        "audit-workflow",
        0,
        CONTENT,
        ttl_seconds=300.0,
    )
    assert delegation.expiration < credential.expires_at
    original_claim = store.claim_and_reserve_gate

    def expire_delegation_then_claim(*args, **kwargs):
        monkeypatch.setattr(
            "sluice_v2.store.time.time", lambda: delegation.expiration + 1.0
        )
        return original_claim(*args, **kwargs)

    monkeypatch.setattr(
        store, "claim_and_reserve_gate", expire_delegation_then_claim
    )
    rejected = monitor.invoke(
        handle,
        CONTENT,
        caller_id="worker",
        credential=credential,
        delegation=delegation,
    )

    assert rejected.outcome == Outcome.UNAUTHORIZED_DELEGATION
    assert rejected.charged_bits == 0.0
    assert _count(
        store, "SELECT consumed FROM gates WHERE gate_id=?", (handle.gate_id,)
    ) == 0
    assert store.spent_units("audit-object", 0) == 0
    assert _count(
        store,
        "SELECT COUNT(*) FROM consumed_call_nonces WHERE agent_id=? AND nonce=?",
        (credential.agent_id, credential.nonce),
    ) == 0
    assert _count(
        store,
        "SELECT COUNT(*) FROM delegation_grants WHERE grant_id=?",
        (delegation.grant_id,),
    ) == 0
    assert _count(store, "SELECT COUNT(*) FROM object_sequence") == 0
    store.close()


def test_declared_successor_cannot_skip_predecessor_after_untracked_gate(tmp_path):
    store = DurableStore(str(tmp_path / "successor-skip.db"))
    monitor = _monitor(store)
    scope = {
        "protected_object": "successor-skip-object",
        "workflow_id": "successor-skip-workflow",
        "unsafe": True,
    }
    unrelated = _author(monitor, "unrelated-entry", **scope)
    _author(
        monitor,
        "required-predecessor",
        successors={"reserved-successor"},
        **scope,
    )
    reserved = _author(monitor, "reserved-successor", **scope)

    assert monitor.invoke(
        unrelated, CONTENT, caller_id="planner"
    ).outcome == Outcome.OK
    rejected = monitor.invoke(reserved, CONTENT, caller_id="planner")

    assert rejected.outcome == Outcome.UNAUTHORIZED_SUCCESSOR
    assert rejected.charged_bits == 0.0
    assert _count(
        store,
        "SELECT consumed FROM gates WHERE gate_id='reserved-successor'",
    ) == 0
    store.close()


def test_same_scope_successor_cannot_have_two_declared_predecessors(tmp_path):
    store = DurableStore(str(tmp_path / "conflicting-predecessors.db"))
    monitor = _monitor(store)
    scope = {
        "protected_object": "conflict-object",
        "workflow_id": "conflict-workflow",
        "unsafe": True,
    }
    _author(
        monitor,
        "first-predecessor",
        successors={"same-successor"},
        **scope,
    )

    with pytest.raises(ProvenanceViolation, match="different predecessor"):
        _author(
            monitor,
            "second-predecessor",
            successors={"same-successor"},
            **scope,
        )

    assert store.get_gate("second-predecessor") is None
    assert _count(
        store,
        "SELECT COUNT(*) FROM declared_successors WHERE "
        "protected_object='conflict-object' AND workflow_id='conflict-workflow' "
        "AND policy_epoch=0 AND successor_gate_id='same-successor'",
    ) == 1
    store.close()
