"""Regressions for security failures found during the v3 monitor audit."""

from __future__ import annotations

import json
import math
import sqlite3
import threading
from dataclasses import replace
from decimal import Decimal, ROUND_CEILING, localcontext

import pytest

from actions import ActionTemplate, ArgConstraint, EffectClass
from monitor import (
    Direction,
    MockBackend,
    Outcome,
    ProvenanceViolation,
    ReferenceMonitor,
    SluiceV2Error,
    Symbol,
    TamperViolation,
    gate_cost_bits,
    gate_cost_units,
)
from store import (
    DurableStore,
    StoreInvariantError,
    cap_bits_to_units,
    charge_bits_to_units,
)


def test_singleton_valid_and_schema_failure_have_same_nonzero_charge(tmp_path):
    class InvalidBackend:
        def decode(self, content, values):
            return "outside-the-declared-schema"

    ok_store = DurableStore(str(tmp_path / "singleton-ok.db"))
    ok_monitor = ReferenceMonitor(ok_store, MockBackend())
    ok_handle = ok_monitor.author_gate(
        "singleton-ok",
        "wf",
        "singleton-object-ok",
        Direction.ENDORSE,
        [Symbol("only")],
        "planner",
        frozenset({"agent"}),
    )
    ok = ok_monitor.invoke(ok_handle, "anything", "agent")

    bad_store = DurableStore(str(tmp_path / "singleton-bad.db"))
    bad_monitor = ReferenceMonitor(bad_store, InvalidBackend())
    bad_handle = bad_monitor.author_gate(
        "singleton-bad",
        "wf",
        "singleton-object-bad",
        Direction.ENDORSE,
        [Symbol("only")],
        "planner",
        frozenset({"agent"}),
    )
    bad = bad_monitor.invoke(bad_handle, "anything", "agent")

    expected = gate_cost_bits(1)
    assert expected > 0
    assert ok.outcome == Outcome.OK
    assert bad.outcome == Outcome.SCHEMA_VIOLATION
    assert ok.charged_bits == bad.charged_bits == expected
    assert ok_monitor.spent("singleton-object-ok", 0) == expected
    assert bad_monitor.spent("singleton-object-bad", 0) == expected


def test_backend_exception_is_generic_charged_audited_and_consumes_gate(tmp_path):
    secret = "DO-NOT-LEAK-THIS-BACKEND-SECRET"

    class ExplodingBackend:
        def decode(self, content, values):
            raise RuntimeError(f"decoder failed while processing {secret}")

    store = DurableStore(str(tmp_path / "backend-error.db"))
    monitor = ReferenceMonitor(store, ExplodingBackend())
    handle = monitor.author_gate(
        "backend-error",
        "wf",
        "backend-object",
        Direction.RELEASE,
        [Symbol("a"), Symbol("b")],
        "planner",
        frozenset({"agent"}),
    )

    first = monitor.invoke(handle, "protected content", "agent")
    second = monitor.invoke(handle, "protected content", "agent")

    assert first.outcome == Outcome.BACKEND_ERROR
    assert first.value is None and first.action is None
    assert first.charged_bits == gate_cost_bits(2)
    assert secret not in repr(first)
    assert second.outcome == Outcome.REPLAYED
    assert second.charged_bits == 0.0
    assert monitor.spent("backend-object", 0) == gate_cost_bits(2)

    audit = store.audit_log()
    audit_text = json.dumps(audit, sort_keys=True)
    assert secret not in audit_text
    assert [entry["event"] for entry in audit].count("invocation_started") == 1
    assert [entry["event"] for entry in audit].count("outcome:backend_error") == 1
    assert [entry["event"] for entry in audit].count("outcome:replayed") == 1
    assert store.verify_audit_chain() is True


def test_none_args_cannot_skip_required_action_validation(tmp_path):
    send = ActionTemplate(
        name="send",
        tool="email",
        arg_constraints={
            "to": ArgConstraint(allowed_values=frozenset({"ops@example.edu"}))
        },
        max_effect_class=EffectClass.IRREVERSIBLE,
    )
    store = DurableStore(str(tmp_path / "required-args.db"))
    monitor = ReferenceMonitor(store, MockBackend())
    handle = monitor.author_gate(
        "required-args",
        "wf",
        "required-args-object",
        Direction.ENDORSE,
        [Symbol("send", send), Symbol("noop")],
        "planner",
        frozenset({"agent"}),
        max_effect_class=EffectClass.IRREVERSIBLE,
    )

    observation = monitor.invoke(handle, "please send", "agent", args=None)

    assert observation.outcome == Outcome.ARG_INVALID
    assert observation.value is None and observation.action is None
    assert observation.authorized_args == ()
    assert observation.capability_id is None and observation.capability_tag is None
    assert observation.charged_bits == gate_cost_bits(2)


def test_same_handle_claim_is_atomic_across_two_store_connections(tmp_path):
    class BlockingBackend:
        def __init__(self):
            self.entered = threading.Event()
            self.release = threading.Event()
            self.calls = 0
            self.lock = threading.Lock()

        def decode(self, content, values):
            with self.lock:
                self.calls += 1
            self.entered.set()
            if not self.release.wait(timeout=5):
                raise TimeoutError("test did not release blocking backend")
            return values[0]

    class MustNotDecode:
        def decode(self, content, values):
            raise AssertionError("the losing claimant reached the backend")

    db_path = str(tmp_path / "cross-store-claim.db")
    backend = BlockingBackend()
    store_one = DurableStore(db_path)
    monitor_one = ReferenceMonitor(store_one, backend)
    handle = monitor_one.author_gate(
        "one-shot",
        "wf",
        "claim-object",
        Direction.ENDORSE,
        [Symbol("a"), Symbol("b")],
        "planner",
        frozenset({"agent"}),
    )
    store_two = DurableStore(db_path)
    monitor_two = ReferenceMonitor(store_two, MustNotDecode())

    first_result = []
    first_errors = []

    def invoke_first():
        try:
            first_result.append(monitor_one.invoke(handle, "content", "agent"))
        except Exception as error:  # noqa: BLE001 - captured for assertion
            first_errors.append(error)

    thread = threading.Thread(target=invoke_first, daemon=True)
    thread.start()
    entered = backend.entered.wait(timeout=5)
    if not entered:
        backend.release.set()
        thread.join(timeout=5)
    assert entered, first_errors

    try:
        losing_result = monitor_two.invoke(handle, "content", "agent")
    finally:
        backend.release.set()
    thread.join(timeout=5)

    assert not thread.is_alive()
    assert first_errors == []
    assert len(first_result) == 1
    assert first_result[0].outcome == Outcome.OK
    assert losing_result.outcome == Outcome.REPLAYED
    assert losing_result.charged_bits == 0.0
    assert backend.calls == 1
    assert monitor_one.spent("claim-object", 0) == gate_cost_bits(2)


def test_reauthorization_rejects_forged_same_old_and_skipped_epochs(tmp_path):
    real_key = b"trusted-reauthorizer-key-012345"
    attacker_key = b"attacker-reauthorizer-key-xxxx"
    store = DurableStore(str(tmp_path / "reauthorization.db"))
    monitor = ReferenceMonitor(
        store,
        MockBackend(),
        trusted_authorizer_keys={"approver": real_key},
    )
    old_handle = monitor.author_gate(
        "epoch-zero-gate",
        "wf",
        "reauth-object",
        Direction.ENDORSE,
        [Symbol("a"), Symbol("b")],
        "planner",
        frozenset({"agent"}),
        cap_bits=10.0,
    )

    forged = monitor.issue_reauthorization(
        "reauth-object", 0, 1, 10.0, "approver", attacker_key
    )
    with pytest.raises(TamperViolation):
        monitor.redeem_reauthorization(forged)
    assert store.current_epoch("reauth-object") == 0

    unknown_authority = monitor.issue_reauthorization(
        "reauth-object", 0, 1, 10.0, "attacker", attacker_key
    )
    with pytest.raises(ProvenanceViolation):
        monitor.redeem_reauthorization(unknown_authority)

    template = monitor.issue_reauthorization(
        "reauth-object", 0, 1, 10.0, "approver", real_key
    )
    same_epoch = replace(template, grant_id="same-epoch", new_epoch=0)
    skipped_epoch = replace(template, grant_id="skipped-epoch", new_epoch=2)
    with pytest.raises(SluiceV2Error, match="advance.*by one"):
        monitor.redeem_reauthorization(same_epoch)
    with pytest.raises(SluiceV2Error, match="advance.*by one"):
        monitor.redeem_reauthorization(skipped_epoch)

    valid = monitor.issue_reauthorization(
        "reauth-object", 0, 1, 10.0, "approver", real_key
    )
    monitor.redeem_reauthorization(valid)
    assert store.current_epoch("reauth-object") == 1

    old_grant = monitor.issue_reauthorization(
        "reauth-object", 0, 1, 10.0, "approver", real_key
    )
    with pytest.raises(ValueError, match="current epoch"):
        monitor.redeem_reauthorization(old_grant)
    assert store.current_epoch("reauth-object") == 1

    stale = monitor.invoke(old_handle, "content says a", "agent")
    assert stale.outcome == Outcome.STALE_EPOCH
    assert stale.charged_bits == 0.0
    assert monitor.spent("reauth-object", 0) == 0.0

    epoch_one = monitor.author_gate(
        "epoch-one-gate",
        "wf",
        "reauth-object",
        Direction.ENDORSE,
        [Symbol("a"), Symbol("b")],
        "planner",
        frozenset({"agent"}),
        policy_epoch=1,
        cap_bits=10.0,
    )
    assert monitor.invoke(epoch_one, "content says a", "agent").outcome == Outcome.OK


def test_unicode_alias_mutation_of_stored_policy_fails_digest_check(tmp_path):
    precomposed = "é"
    decomposed = "é"
    store = DurableStore(str(tmp_path / "unicode-tamper.db"))
    monitor = ReferenceMonitor(store, MockBackend())
    handle = monitor.author_gate(
        "unicode-gate",
        "wf",
        "unicode-object",
        Direction.ENDORSE,
        [Symbol(precomposed)],
        "planner",
        frozenset({"agent"}),
    )

    with store.transaction() as connection:
        stored_json = connection.execute(
            "SELECT record_json FROM gates WHERE gate_id=?", (handle.gate_id,)
        ).fetchone()[0]
        record = json.loads(stored_json)
        record["symbols"][0]["value"] = decomposed
        connection.execute(
            "UPDATE gates SET record_json=? WHERE gate_id=?",
            (json.dumps(record, sort_keys=True), handle.gate_id),
        )

    with pytest.raises(TamperViolation, match="digest verification failed"):
        monitor.invoke(handle, "content", "agent")


def test_conflicting_cap_rejection_leaves_no_orphan_gate(tmp_path):
    store = DurableStore(str(tmp_path / "cap-conflict.db"))
    monitor = ReferenceMonitor(store, MockBackend())
    original = monitor.author_gate(
        "original-gate",
        "wf",
        "cap-object",
        Direction.ENDORSE,
        [Symbol("a")],
        "planner",
        frozenset({"agent"}),
        cap_bits=10.0,
    )

    with pytest.raises(ProvenanceViolation, match="conflicting cap"):
        monitor.author_gate(
            "orphan-candidate",
            "wf",
            "cap-object",
            Direction.ENDORSE,
            [Symbol("a")],
            "planner",
            frozenset({"agent"}),
            cap_bits=11.0,
        )

    assert store.get_gate("orphan-candidate") is None
    assert store.current_epoch("cap-object") == 0
    assert not any(
        entry["gate_id"] == "orphan-candidate" for entry in store.audit_log()
    )
    assert monitor.invoke(original, "content", "agent").outcome == Outcome.OK


def test_store_claim_uses_only_authoritative_gate_binding(tmp_path):
    store = DurableStore(str(tmp_path / "authoritative-claim.db"))
    monitor = ReferenceMonitor(store, MockBackend())
    handle = monitor.author_gate(
        "bound-gate",
        "wf",
        "bound-object",
        Direction.RELEASE,
        [Symbol("a"), Symbol("b")],
        "planner",
        frozenset({"agent"}),
        cap_bits=10.0,
    )
    import inspect

    # `selection_units` (successor-selection charge, see monitor.py's
    # sequencing mechanism) is the one intentional addition to this
    # signature: it is never a raw caller-supplied value -- the monitor
    # computes it server-side from the already-authenticated, digest-bound
    # predecessor gate's `allowed_successor_gates` or this gate's own
    # `entry_fanout`, both fixed at author_gate() time -- and it is
    # independently bounds-checked below. Any OTHER parameter appearing
    # here would be a real regression and should fail this canary.
    assert set(inspect.signature(store.claim_and_reserve_gate).parameters) == {
        "gate_id", "selection_units"
    }
    claim = store.claim_and_reserve_gate(handle.gate_id)
    assert claim.protected_object == "bound-object"
    assert claim.policy_epoch == 0
    assert claim.authorized_cost_units > 0
    assert claim.spent_after_units == claim.authorized_cost_units
    with pytest.raises(TypeError):
        store.claim_and_reserve_gate(handle.gate_id, -100_000_000, "extra")
    with pytest.raises(ValueError):
        store.claim_and_reserve_gate(handle.gate_id, -100_000_000)


def test_legacy_fractional_budget_migration_fails_closed(tmp_path):
    database = str(tmp_path / "legacy.db")
    connection = sqlite3.connect(database)
    connection.executescript(
        """
        CREATE TABLE budgets (
          protected_object TEXT NOT NULL,
          policy_epoch INTEGER NOT NULL,
          spent_bits REAL NOT NULL DEFAULT 0,
          cap_bits REAL NOT NULL,
          reauth_required INTEGER NOT NULL DEFAULT 0,
          PRIMARY KEY (protected_object, policy_epoch)
        );
        CREATE TABLE gates (
          gate_id TEXT PRIMARY KEY,
          record_json TEXT NOT NULL,
          digest TEXT NOT NULL,
          consumed INTEGER NOT NULL DEFAULT 0,
          created_at REAL NOT NULL
        );
        CREATE TABLE reauth_grants (
          grant_id TEXT PRIMARY KEY,
          protected_object TEXT NOT NULL,
          new_epoch INTEGER NOT NULL,
          new_cap_bits REAL NOT NULL,
          authorizer_identity TEXT NOT NULL,
          signature TEXT NOT NULL,
          issued_at REAL NOT NULL,
          consumed INTEGER NOT NULL DEFAULT 0
        );
        """
    )
    fractional = 1.584962500721156
    connection.execute(
        "INSERT INTO budgets VALUES (?,?,?,?,0)",
        ("legacy-object", 0, fractional, fractional),
    )
    connection.commit()
    connection.close()

    with pytest.raises(StoreInvariantError, match="rounded spend exceeds rounded cap"):
        DurableStore(database)


def test_hostile_mapping_exception_is_generic_arg_invalid(tmp_path):
    secret = "SECRET-FROM-MAPPING-ITERATOR"

    from collections.abc import Mapping

    class HostileMapping(Mapping):
        def __iter__(self):
            raise RuntimeError(secret)

        def __len__(self):
            return 1

        def __getitem__(self, key):
            return "ops@example.edu"

    action = ActionTemplate(
        name="send",
        tool="email",
        arg_constraints={"to": ArgConstraint(max_length=100)},
        max_effect_class=EffectClass.REVERSIBLE,
    )
    store = DurableStore(str(tmp_path / "hostile-mapping.db"))
    monitor = ReferenceMonitor(store, MockBackend())
    handle = monitor.author_gate(
        "hostile-mapping",
        "wf",
        "hostile-object",
        Direction.ENDORSE,
        [Symbol("send", action)],
        "planner",
        frozenset({"agent"}),
        max_effect_class=EffectClass.REVERSIBLE,
    )
    observation = monitor.invoke(
        handle, "send", "agent", args=HostileMapping()
    )
    assert observation.outcome == Outcome.ARG_INVALID
    assert observation.value is None and observation.action is None
    assert secret not in repr(observation)
    assert secret not in json.dumps(store.audit_log())


def test_float_to_exact_units_is_conservative_at_microbit_boundaries():
    assert cap_bits_to_units(1e-6) == 0
    assert charge_bits_to_units(1e-6) == 1
    assert cap_bits_to_units(3e-6) == 3
    assert charge_bits_to_units(3e-6) == 4
    assert cap_bits_to_units(1.000001) <= 1_000_001
    assert charge_bits_to_units(1.000001) >= 1_000_001


def test_precomputed_gate_cost_table_matches_high_precision_definition():
    with localcontext() as context:
        context.prec = 100
        for cardinality in range(1, 33):
            support = cardinality + 4
            if support & (support - 1) == 0:
                expected = (support.bit_length() - 1) * 1_000_000
            else:
                expected = int(
                    (
                        Decimal(support).ln()
                        / Decimal(2).ln()
                        * Decimal(1_000_000)
                    ).to_integral_value(rounding=ROUND_CEILING)
                )
            assert gate_cost_units(cardinality) == expected


def test_reauthorization_keeps_exact_units_authoritative_across_float_display(tmp_path):
    """A display float must never be converted back into security state.

    The nearest float above one microbit conservatively maps to one unit, while
    the human-readable ``1e-6`` mirror is just below one microbit in binary and
    maps back to zero.  A monitor-issued grant must nevertheless redeem using
    its signed integer unit field.
    """
    key = b"trusted-reauthorizer-key-012345"
    store = DurableStore(str(tmp_path / "unit-roundtrip.db"))
    monitor = ReferenceMonitor(
        store,
        MockBackend(),
        trusted_authorizer_keys={"approver": key},
    )
    monitor.author_gate(
        "unit-roundtrip-gate",
        "wf",
        "unit-roundtrip-object",
        Direction.RELEASE,
        [Symbol("only")],
        "planner",
        frozenset({"agent"}),
        cap_bits=10.0,
    )

    one_unit_cap = math.nextafter(1e-6, math.inf)
    grant = monitor.issue_reauthorization(
        "unit-roundtrip-object", 0, 1, one_unit_cap, "approver", key
    )
    assert grant.new_cap_units == 1
    assert cap_bits_to_units(grant.new_cap_bits) == 0

    monitor.redeem_reauthorization(grant)
    assert store.current_epoch("unit-roundtrip-object") == 1
    with sqlite3.connect(str(tmp_path / "unit-roundtrip.db")) as connection:
        stored_cap_units = connection.execute(
            "SELECT cap_units FROM budgets WHERE protected_object=? AND policy_epoch=?",
            ("unit-roundtrip-object", 1),
        ).fetchone()[0]
    assert stored_cap_units == 1


def test_default_cap_keeps_units_authoritative_when_authoring(tmp_path):
    database = str(tmp_path / "default-unit-roundtrip.db")
    one_unit_cap = math.nextafter(1e-6, math.inf)
    store = DurableStore(database)
    monitor = ReferenceMonitor(store, MockBackend(), default_cap_bits=one_unit_cap)
    monitor.author_gate(
        "default-unit-roundtrip-gate",
        "wf",
        "default-unit-roundtrip-object",
        Direction.RELEASE,
        [Symbol("only")],
        "planner",
        frozenset({"agent"}),
    )
    with sqlite3.connect(database) as connection:
        stored_cap_units = connection.execute(
            "SELECT cap_units FROM budgets WHERE protected_object=? AND policy_epoch=0",
            ("default-unit-roundtrip-object",),
        ).fetchone()[0]
    assert stored_cap_units == 1


def test_action_scope_must_bind_to_a_declared_argument(tmp_path):
    unbound = ActionTemplate(
        name="send",
        tool="email",
        arg_constraints={"to": ArgConstraint(max_length=100)},
        recipient_scope=frozenset({"ops@example.edu"}),
        max_effect_class=EffectClass.REVERSIBLE,
    )
    monitor = ReferenceMonitor(
        DurableStore(str(tmp_path / "unbound-scope.db")), MockBackend()
    )
    with pytest.raises(SluiceV2Error, match="invalid action policy"):
        monitor.author_gate(
            "unbound",
            "wf",
            "scope-object",
            Direction.ENDORSE,
            [Symbol("send", unbound)],
            "planner",
            frozenset({"agent"}),
            max_effect_class=EffectClass.REVERSIBLE,
        )

    bound = replace(unbound, recipient_arg="to")
    handle = monitor.author_gate(
        "bound",
        "wf",
        "scope-object",
        Direction.ENDORSE,
        [Symbol("send", bound)],
        "planner",
        frozenset({"agent"}),
        max_effect_class=EffectClass.REVERSIBLE,
    )
    observation = monitor.invoke(
        handle, "send", "agent", args={"to": "attacker@evil.example"}
    )
    assert observation.outcome == Outcome.ARG_INVALID


def test_action_capability_is_revoked_when_epoch_advances(tmp_path):
    key = b"trusted-reauthorizer-key-012345"
    action = ActionTemplate(
        name="sink", tool="sink", max_effect_class=EffectClass.REVERSIBLE
    )
    store = DurableStore(str(tmp_path / "capability-epoch.db"))
    monitor = ReferenceMonitor(
        store, MockBackend(), trusted_authorizer_keys={"approver": key}
    )
    handle = monitor.author_gate(
        "epoch-capability",
        "wf",
        "capability-object",
        Direction.ENDORSE,
        [Symbol("sink", action)],
        "planner",
        frozenset({"agent"}),
        max_effect_class=EffectClass.REVERSIBLE,
        cap_bits=10.0,
    )
    observation = monitor.invoke(handle, "sink", "agent")
    grant = monitor.issue_reauthorization(
        "capability-object", 0, 1, 10.0, "approver", key
    )
    monitor.redeem_reauthorization(grant)
    from store import ReplayError

    with pytest.raises(ReplayError):
        monitor.consume_action_capability(observation)


def test_audit_hash_encoding_has_no_delimiter_collision(tmp_path):
    store = DurableStore(str(tmp_path / "audit-encoding.db"))
    store.append_audit("a|b", "c", {})
    with store.transaction() as connection:
        connection.execute(
            "UPDATE audit_log SET gate_id=?, event=? WHERE seq=1", ("a", "b|c")
        )
    assert store.verify_audit_chain() is False


def test_sqlite_real_values_cannot_coerce_into_integer_security_state(tmp_path):
    database = str(tmp_path / "dynamic-types.db")
    store = DurableStore(database)
    monitor = ReferenceMonitor(store, MockBackend())
    handle = monitor.author_gate(
        "dynamic-types-gate",
        "wf",
        "dynamic-types-object",
        Direction.RELEASE,
        [Symbol("only")],
        "planner",
        frozenset({"agent"}),
    )

    # Simulate post-initialization corruption by a separate database writer.
    # Fresh schemas reject this through CHECK(typeof(...)); ignoring CHECKs
    # exercises the mandatory runtime fail-closed validation as well.
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA ignore_check_constraints=ON")
        connection.execute(
            "UPDATE budgets SET spent_units=0.9 WHERE protected_object=?",
            ("dynamic-types-object",),
        )
        connection.commit()
    with pytest.raises((ValueError, StoreInvariantError), match="integer"):
        store.claim_and_reserve_gate(handle.gate_id)

    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA ignore_check_constraints=ON")
        connection.execute(
            "UPDATE budgets SET spent_units=0 WHERE protected_object=?",
            ("dynamic-types-object",),
        )
        connection.execute(
            "UPDATE object_epochs SET current_epoch=0.9 WHERE protected_object=?",
            ("dynamic-types-object",),
        )
        connection.commit()
    with pytest.raises(StoreInvariantError, match="integer"):
        store.claim_and_reserve_gate(handle.gate_id)


def test_transaction_rolls_back_control_flow_exceptions(tmp_path):
    store = DurableStore(str(tmp_path / "control-flow-rollback.db"))
    with pytest.raises(KeyboardInterrupt):
        with store.transaction() as connection:
            connection.execute(
                "INSERT INTO monitor_meta(key, value) VALUES (?, ?)",
                ("must_rollback", "value"),
            )
            raise KeyboardInterrupt

    assert store._conn.in_transaction is False
    assert store._conn.execute(
        "SELECT value FROM monitor_meta WHERE key='must_rollback'"
    ).fetchone() is None
    store.append_audit(None, "after_control_flow_rollback", {})


def test_gate_authorship_and_audit_entry_commit_atomically(tmp_path, monkeypatch):
    store = DurableStore(str(tmp_path / "atomic-author-audit.db"))
    monitor = ReferenceMonitor(store, MockBackend())
    original_append = store.append_audit

    def failing_gate_audit(gate_id, event, detail, conn=None):
        if event == "gate_authored":
            raise OSError("simulated audit write failure")
        return original_append(gate_id, event, detail, conn=conn)

    monkeypatch.setattr(store, "append_audit", failing_gate_audit)
    with pytest.raises(OSError, match="simulated audit write failure"):
        monitor.author_gate(
            "atomic-author-audit-gate",
            "wf",
            "atomic-author-audit-object",
            Direction.RELEASE,
            [Symbol("only")],
            "planner",
            frozenset({"agent"}),
        )
    assert store.get_gate("atomic-author-audit-gate") is None
    assert store.current_epoch("atomic-author-audit-object") is None


@pytest.mark.parametrize("bad_key", [b"", b"short", b"x" * 31, bytearray(b"x" * 32)])
def test_monitor_rejects_invalid_central_hmac_keys(tmp_path, bad_key):
    store = DurableStore(str(tmp_path / f"bad-hmac-{len(bad_key)}.db"))
    with pytest.raises(SluiceV2Error, match="hmac_key"):
        ReferenceMonitor(store, MockBackend(), hmac_key=bad_key)
