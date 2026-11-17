"""Fail-first production correspondence tests for the durable v2 monitor.

These tests never hand-author an abstract transition.  They invoke the real
``DurableSecureDomain`` API, inspect its committed SQLite state through the
emitter, and feed the emitter's exact canonical JSONL bytes to the independent
``FormalTraceChecker``.
"""

from __future__ import annotations

import json
from pathlib import Path
import random
import sqlite3

import pytest

from sluice_v2.durable_secure import (
    AttemptCredential,
    DomainConfig,
    DurableSecureDomain,
    EffectRequest,
    EffectResult,
    IdempotentEffectHandler,
    ObserverSpec,
    ReauthorizationGrant,
    ReauthorizationPolicy,
    RouteCodebook,
)
from sluice_v2.formal_emitter import (
    DurableFormalBinding,
    DurableFormalEmitter,
    FormalEmitterError,
    UnsupportedCorrespondence,
)
from sluice_v2.formal_trace import FormalManifest, check_trace
from sluice_v2.observer import OutcomeCode


CALLER_KEY = b"formal-emitter-caller-key-32bytes"
REAUTH_KEY = b"formal-emitter-reauth-key-32bytes"
TRACE_ID = "durableTrace_20260820_AA"


def _direct(_payload):
    return 0


def _effect_execute(request: EffectRequest) -> EffectResult:
    return EffectResult.for_request(request, 1)


def _effect_reconcile(_request: EffectRequest) -> EffectResult | None:
    return None


HANDLERS = {
    "direct": _direct,
    "effect": IdempotentEffectHandler(_effect_execute, _effect_reconcile),
    "stale": _direct,
    "epoch-one": _direct,
}


def _manifest_line() -> bytes:
    path = Path(__file__).resolve().parents[2] / "formal" / "SluiceDurableTraceManifest.json"
    return path.read_bytes()


def _create(path, *, fault_hook=None):
    domain = DurableSecureDomain.create(
        path,
        config=DomainConfig(
            domain_id="durable-formal-domain",
            protected_objects=frozenset(
                {"direct-object", "effect-object", "stale-object", "epoch-one-object"}
            ),
            lifetime_budget_units=56,
            attempt_horizon=7,
            event_charge_units=8,
        ),
        observer_spec=ObserverSpec(
            frozenset({0, 1}),
            observer_spec_id="durable-formal-public-codebook-v1",
            route_codebooks=(
                RouteCodebook("direct", frozenset({0, 1})),
                RouteCodebook("effect", frozenset({0, 1}), True),
                RouteCodebook("stale", frozenset({0, 1})),
                RouteCodebook("epoch-one", frozenset({0, 1})),
            ),
        ),
        reauthorization_policy=ReauthorizationPolicy(16, 2),
        agent_keys={"worker": CALLER_KEY},
        reauthorization_keys={"security-admin": REAUTH_KEY},
        handler_registry=HANDLERS,
        fault_hook=fault_hook,
    )
    routes = {
        "direct": domain.register_route(
            name="direct",
            protected_object="direct-object",
            handler_key="direct",
            public_values=frozenset({0, 1}),
        ),
        "effect": domain.register_route(
            name="effect",
            protected_object="effect-object",
            handler_key="effect",
            public_values=frozenset({0, 1}),
            requires_capability=True,
        ),
        "stale": domain.register_route(
            name="stale",
            protected_object="stale-object",
            handler_key="stale",
            public_values=frozenset({0, 1}),
        ),
        "epoch-one": domain.register_route(
            name="epoch-one",
            protected_object="epoch-one-object",
            handler_key="epoch-one",
            public_values=frozenset({0, 1}),
        ),
    }
    effect_payload = {"effect": "private"}
    capability = domain.issue_capability(
        routes["effect"],
        payload=effect_payload,
        redeemer_id="broker",
        expires_at_lifetime_attempt=9,
    )
    domain.seal()
    domain.activate()
    binding = DurableFormalBinding.from_maps(
        _manifest_line(),
        domain_slot=0,
        object_slots={
            "direct-object": 0,
            "effect-object": 1,
            "stale-object": 2,
            "epoch-one-object": 3,
        },
        route_gate_slots={
            routes["direct"].to_wire(): 0,
            routes["effect"].to_wire(): 1,
            routes["stale"].to_wire(): 2,
            routes["epoch-one"].to_wire(): 3,
        },
        agent_slots={"worker": 0},
        credential_nonce_slots={
            ("worker", "direct-nonce"): 0,
            ("worker", "effect-nonce"): 1,
            ("worker", "stale-nonce"): 2,
            ("worker", "epoch-one-nonce"): 3,
            ("worker", "second-direct-nonce"): 4,
        },
        grant_slots={("security-admin", "grant-nonce"): 0},
        capability_slots={capability.to_wire(): 0},
        redeemer_slots={"broker": 0, "wrong-broker": 1},
    )
    return domain, routes, capability, effect_payload, binding


def _reopen(path, *, fault_hook=None):
    return DurableSecureDomain.reopen(
        path,
        agent_keys={"worker": CALLER_KEY},
        reauthorization_keys={"security-admin": REAUTH_KEY},
        handler_registry=HANDLERS,
        fault_hook=fault_hook,
    )


def _credential(domain, route, payload, nonce):
    return AttemptCredential.sign(
        agent_id="worker",
        signing_key=CALLER_KEY,
        domain_context=domain.credential_context,
        expected_epoch=domain.current_epoch,
        route=route,
        payload=payload,
        nonce=nonce,
        expires_at_lifetime_attempt=domain.attempt_horizon,
    )


def _grant(domain):
    return ReauthorizationGrant.sign(
        authorizer_id="security-admin",
        signing_key=REAUTH_KEY,
        domain_context=domain.reauthorization_context,
        expected_epoch=domain.current_epoch,
        budget_increment_units=16,
        attempt_increment=2,
        nonce="grant-nonce",
        expires_at_lifetime_attempt=9,
    )


def _records(emitter):
    return [json.loads(line) for line in emitter.trace_bytes.splitlines()]


def test_real_operations_emit_exact_checker_accepted_private_jsonl(tmp_path):
    path = tmp_path / "complete.sqlite3"
    domain, routes, capability, effect_payload, binding = _create(path)
    emitter = DurableFormalEmitter(domain, binding, trace_id=TRACE_ID)

    stale_payload = {"stale": "private"}
    stale_credential = _credential(
        domain, routes["stale"], stale_payload, "stale-nonce"
    )
    direct_payload = {"direct": "private"}
    direct = emitter.attempt(
        routes["direct"],
        direct_payload,
        credential=_credential(
            domain, routes["direct"], direct_payload, "direct-nonce"
        ),
    )
    effect_credential = _credential(
        domain, routes["effect"], effect_payload, "effect-nonce"
    )
    denied = emitter.attempt(
        routes["effect"],
        effect_payload,
        credential=effect_credential,
        capability=capability,
        redeemer_id="wrong-broker",
    )
    effect = emitter.attempt(
        routes["effect"],
        effect_payload,
        credential=effect_credential,
        capability=capability,
        redeemer_id="broker",
    )
    continued = emitter.continue_work()
    grant = _grant(domain)
    accepted_grant = emitter.reauthorize(grant)
    stale = emitter.attempt(
        routes["stale"], stale_payload, credential=stale_credential
    )
    replay = emitter.reauthorize(grant)
    stopped = emitter.stop()
    closed = emitter.continue_work()

    assert [
        direct.outcome,
        denied.outcome,
        effect.outcome,
        continued.outcome,
        accepted_grant.outcome,
        stale.outcome,
        replay.outcome,
        stopped.outcome,
        closed.outcome,
    ] == [
        OutcomeCode.RELEASED,
        OutcomeCode.CAPABILITY_DENIED,
        OutcomeCode.RELEASED,
        OutcomeCode.CONTINUED,
        OutcomeCode.REAUTHORIZED,
        OutcomeCode.AUTH_DENIED,
        OutcomeCode.REAUTH_DENIED,
        OutcomeCode.STOPPED,
        OutcomeCode.DOMAIN_CLOSED,
    ]

    actions = [record["action"] for record in _records(emitter)]
    assert actions == [
        "commit_direct",
        "finalize",
        "reject_capability_binding",
        "commit_effect",
        "finalize",
        "continue",
        "reauthorize",
        "reject_stale_epoch",
        "reject_reauthorization",
        "stop_and_pad",
        "closed_reply_stutter",
    ]
    parsed = check_trace(_manifest_line(), emitter.trace_bytes)
    assert emitter.verify() == parsed
    assert parsed.transitions == len(actions)
    assert parsed.final_attempts == (9,)
    assert parsed.final_visible_events == (9,)

    raw = emitter.trace_bytes
    for private_value in (
        routes["direct"].to_wire(),
        capability.to_wire(),
        "worker",
        "direct-nonce",
        "broker",
        "private",
    ):
        assert private_value.encode() not in raw
    for record in _records(emitter):
        for field in (
            "domain_slot",
            "scope_slot",
            "gate_slot",
            "agent_slot",
            "nonce_slot",
            "reauth_grant_slot",
            "capability_slot",
            "redeemer_slot",
        ):
            assert record[field] is None or type(record[field]) is int

    connection = sqlite3.connect(path)
    try:
        starts = connection.execute(
            "SELECT COUNT(*) FROM audit_log WHERE phase='START'"
        ).fetchone()[0]
        finals = connection.execute(
            "SELECT COUNT(*) FROM audit_log WHERE phase='FINAL'"
        ).fetchone()[0]
        credentials = connection.execute("SELECT COUNT(*) FROM used_credentials").fetchone()[0]
        grants = connection.execute("SELECT COUNT(*) FROM used_grants").fetchone()[0]
        capabilities = connection.execute(
            "SELECT COUNT(*) FROM capabilities WHERE consumed_attempt IS NOT NULL"
        ).fetchone()[0]
    finally:
        connection.close()
    assert (starts, finals, credentials, grants, capabilities) == (9, 9, 2, 1, 1)
    # Formal auditStarts is the successful-claim join, not the database's
    # broader one-START-per-reservation journal.  Both quantities are checked.
    assert sum(record["audit_start_delta"] for record in _records(emitter)) == 2


class _CrashAfterCommit(BaseException):
    pass


def test_committed_real_reservation_then_reopen_emits_recovery_finalize(tmp_path):
    path = tmp_path / "recovery.sqlite3"

    def crash(stage):
        if stage == "after_reservation_commit":
            raise _CrashAfterCommit()

    domain, routes, _capability, _effect_payload, binding = _create(
        path, fault_hook=crash
    )
    emitter = DurableFormalEmitter(domain, binding, trace_id=TRACE_ID)
    payload = {"crash": "private"}
    with pytest.raises(_CrashAfterCommit):
        emitter.attempt(
            routes["direct"],
            payload,
            credential=_credential(
                domain, routes["direct"], payload, "direct-nonce"
            ),
        )
    assert emitter.evidence_status == "recovery_required"
    with pytest.raises(FormalEmitterError, match="recovery prefix"):
        _ = emitter.trace_bytes
    recovery_prefix = emitter.recovery_prefix_bytes
    assert [json.loads(line)["action"] for line in recovery_prefix.splitlines()] == [
        "commit_direct"
    ]
    assert check_trace(_manifest_line(), recovery_prefix).transitions == 1

    recovered = emitter.recover(lambda: _reopen(path))
    assert recovered.transcript[0].outcome is OutcomeCode.INTERNAL_DENIED
    assert emitter.evidence_status == "exportable"
    with pytest.raises(FormalEmitterError, match="no recovery prefix"):
        _ = emitter.recovery_prefix_bytes
    assert [record["action"] for record in _records(emitter)] == [
        "commit_direct",
        "finalize",
    ]
    emitter.stop()
    assert emitter.verify().final_attempts == (7,)


def test_unmodeled_route_reuse_fails_before_the_durable_call(tmp_path):
    path = tmp_path / "reuse.sqlite3"
    domain, routes, _capability, _effect_payload, binding = _create(path)
    emitter = DurableFormalEmitter(domain, binding, trace_id=TRACE_ID)
    payload = {"direct": 1}
    emitter.attempt(
        routes["direct"],
        payload,
        credential=_credential(domain, routes["direct"], payload, "direct-nonce"),
    )
    before = (domain.attempts_used, emitter.trace_bytes)
    with pytest.raises(UnsupportedCorrespondence, match="one-use gate"):
        emitter.attempt(
            routes["direct"],
            payload,
            credential=_credential(
                domain, routes["direct"], payload, "second-direct-nonce"
            ),
        )
    assert (domain.attempts_used, emitter.trace_bytes) == before


def test_unmapped_bad_credential_fails_before_the_durable_call(tmp_path):
    path = tmp_path / "unmapped.sqlite3"
    domain, routes, _capability, _effect_payload, binding = _create(path)
    emitter = DurableFormalEmitter(domain, binding, trace_id=TRACE_ID)
    payload = {"direct": 1}
    unknown = _credential(domain, routes["direct"], payload, "not-in-slot-manifest")
    with pytest.raises(UnsupportedCorrespondence, match="credential slot"):
        emitter.attempt(routes["direct"], payload, credential=unknown)
    assert domain.attempts_used == 0
    assert emitter.trace_bytes == b""


def test_late_unbound_capability_inventory_is_detected_before_next_call(tmp_path):
    path = tmp_path / "late-capability.sqlite3"
    domain, routes, _capability, effect_payload, binding = _create(path)
    emitter = DurableFormalEmitter(domain, binding, trace_id=TRACE_ID)
    domain.issue_capability(
        routes["effect"],
        payload=effect_payload,
        redeemer_id="broker",
        expires_at_lifetime_attempt=7,
    )
    with pytest.raises(UnsupportedCorrespondence, match="capability inventory"):
        emitter.continue_work()
    assert domain.attempts_used == 0
    assert emitter.trace_bytes == b""


@pytest.mark.parametrize("seed", range(12))
def test_randomized_real_lifecycle_sequences_are_checked(seed, tmp_path):
    rng = random.Random(0xD04AB1E + seed)
    path = tmp_path / f"random-{seed}.sqlite3"
    domain, routes, capability, effect_payload, binding = _create(path)
    emitter = DurableFormalEmitter(
        domain, binding, trace_id=f"durableRandom_{seed:02d}_20260820"
    )

    pre_epoch = ["direct", "effect"]
    rng.shuffle(pre_epoch)
    for action in pre_epoch:
        if rng.random() < 0.75 and domain.state.value == "active":
            if action == "direct":
                payload = {"seed": seed, "route": "direct"}
                emitter.attempt(
                    routes["direct"],
                    payload,
                    credential=_credential(
                        domain, routes["direct"], payload, "direct-nonce"
                    ),
                )
            else:
                emitter.attempt(
                    routes["effect"],
                    effect_payload,
                    credential=_credential(
                        domain,
                        routes["effect"],
                        effect_payload,
                        "effect-nonce",
                    ),
                    capability=capability,
                    redeemer_id="broker",
                )
        elif domain.state.value == "active" and rng.random() < 0.5:
            emitter.continue_work()

    if domain.state.value == "active" and rng.random() < 0.7:
        grant = _grant(domain)
        emitter.reauthorize(grant)
        if domain.state.value == "active" and rng.random() < 0.7:
            payload = {"seed": seed, "route": "epoch-one"}
            emitter.attempt(
                routes["epoch-one"],
                payload,
                credential=_credential(
                    domain,
                    routes["epoch-one"],
                    payload,
                    "epoch-one-nonce",
                ),
            )

    while domain.state.value == "active":
        if rng.random() < 0.35:
            emitter.stop()
        else:
            emitter.continue_work()
    emitter.continue_work()
    report = check_trace(_manifest_line(), emitter.trace_bytes)
    assert report == emitter.verify()
    assert report.final_attempts[0] in (7, 9)
    assert report.final_attempts == report.final_visible_events


def test_binding_rejects_manifest_route_scope_drift(tmp_path):
    path = tmp_path / "drift.sqlite3"
    domain, routes, capability, _effect_payload, _binding = _create(path)
    with pytest.raises(ValueError, match="object slot"):
        DurableFormalBinding.from_maps(
            _manifest_line(),
            domain_slot=0,
            object_slots={
                "direct-object": 1,
                "effect-object": 0,
                "stale-object": 2,
                "epoch-one-object": 3,
            },
            route_gate_slots={
                routes["direct"].to_wire(): 0,
                routes["effect"].to_wire(): 1,
                routes["stale"].to_wire(): 2,
                routes["epoch-one"].to_wire(): 3,
            },
            agent_slots={"worker": 0},
            credential_nonce_slots={
                ("worker", "direct-nonce"): 0,
                ("worker", "effect-nonce"): 1,
                ("worker", "stale-nonce"): 2,
                ("worker", "epoch-one-nonce"): 3,
                ("worker", "second-direct-nonce"): 4,
            },
            grant_slots={("security-admin", "grant-nonce"): 0},
            capability_slots={capability.to_wire(): 0},
            redeemer_slots={"broker": 0, "wrong-broker": 1},
        ).validate_database(domain)


def test_postcheck_failure_discards_single_transition_and_permanently_poisoned(
    tmp_path, monkeypatch
):
    path = tmp_path / "postcheck-single.sqlite3"
    domain, _routes, _capability, _effect_payload, binding = _create(path)
    emitter = DurableFormalEmitter(domain, binding, trace_id=TRACE_ID)

    def reject_after(_snapshot, _expected):
        raise FormalEmitterError("injected post-operation projection failure")

    monkeypatch.setattr(emitter, "_assert_after", reject_after)
    with pytest.raises(FormalEmitterError, match="injected post-operation"):
        emitter.continue_work()

    assert emitter.evidence_status == "poisoned"
    assert emitter.transition_count == 0
    with pytest.raises(FormalEmitterError, match="permanently poisoned"):
        _ = emitter.trace_bytes
    with pytest.raises(FormalEmitterError, match="permanently poisoned"):
        emitter.verify()
    with pytest.raises(FormalEmitterError, match="permanently poisoned"):
        emitter.continue_work()


def test_postcheck_failure_discards_two_transition_attempt_and_blocks_export(
    tmp_path, monkeypatch
):
    path = tmp_path / "postcheck-two.sqlite3"
    domain, routes, _capability, _effect_payload, binding = _create(path)
    emitter = DurableFormalEmitter(domain, binding, trace_id=TRACE_ID)
    payload = {"direct": "private"}

    def reject_after(_snapshot, _expected):
        raise FormalEmitterError("injected post-operation inventory failure")

    monkeypatch.setattr(emitter, "_assert_after", reject_after)
    with pytest.raises(FormalEmitterError, match="injected post-operation"):
        emitter.attempt(
            routes["direct"],
            payload,
            credential=_credential(
                domain, routes["direct"], payload, "direct-nonce"
            ),
        )

    assert emitter.evidence_status == "poisoned"
    assert emitter.transition_count == 0
    with pytest.raises(FormalEmitterError, match="permanently poisoned"):
        _ = emitter.trace_bytes


def test_postoperation_inventory_read_failure_permanently_blocks_export(
    tmp_path, monkeypatch
):
    path = tmp_path / "postcheck-inventory.sqlite3"
    domain, _routes, _capability, _effect_payload, binding = _create(path)
    emitter = DurableFormalEmitter(domain, binding, trace_id=TRACE_ID)
    original_snapshot = emitter._snapshot
    calls = 0

    def fail_second_snapshot():
        nonlocal calls
        calls += 1
        if calls == 2:
            raise FormalEmitterError("injected post-operation inventory failure")
        return original_snapshot()

    monkeypatch.setattr(emitter, "_snapshot", fail_second_snapshot)
    with pytest.raises(FormalEmitterError, match="injected post-operation inventory"):
        emitter.continue_work()

    assert domain.attempts_used == 1
    assert emitter.evidence_status == "poisoned"
    assert emitter.transition_count == 0
    with pytest.raises(FormalEmitterError, match="permanently poisoned"):
        _ = emitter.trace_bytes
