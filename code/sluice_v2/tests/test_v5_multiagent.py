"""Regression tests for agent-identity call authentication and single-hop
delegation (CallerCredential / DelegationGrant, \\S\\ref{sec:multiagent}).

Before this mechanism, ``caller_id`` was a bare, unauthenticated string:
``invoke()`` only ever checked membership in ``permitted_callers``, never
proof of possession. An earlier revision of ``CallerCredential`` closed
that gap but signed only ``(agent_id, gate_id)`` -- a value fixed for the
credential's entire lifetime, with no nonce, no expiry, and no binding to
the content or arguments actually being submitted. That meant a captured
credential could be replayed to win a gate claim ahead of its legitimate
holder, and, more seriously, could be paired with *different* content or
arguments than the agent actually signed. This version signs the full
request -- gate, workflow, epoch, content digest, args digest, a fresh
nonce, and an expiry -- and consumes the nonce transactionally, so this
file's tests are organized around the specific failure modes that matters
for: impersonation, capability forwarding, delegation laundering, and now
stolen-token replay, delayed replay, cross-session (cross-epoch) reuse,
relay/content-tampering, and concurrent duplicate presentation.
"""

from __future__ import annotations

import secrets
import threading

import pytest

from sluice_v2.actions import ActionTemplate, EffectClass
from sluice_v2.monitor import (
    CallerCredential,
    DelegationGrant,
    Direction,
    MockBackend,
    Outcome,
    ProvenanceViolation,
    ReferenceMonitor,
    Symbol,
)
from sluice_v2.store import DurableStore


@pytest.fixture()
def agents():
    return {
        "planner": secrets.token_bytes(32),
        "worker": secrets.token_bytes(32),
        "eavesdropper": secrets.token_bytes(32),
    }


@pytest.fixture()
def monitor_and_store(tmp_path, agents):
    db_path = str(tmp_path / "sluice.db")
    store = DurableStore(db_path)
    backend = MockBackend()
    monitor = ReferenceMonitor(
        store,
        backend,
        default_cap_bits=64.0,
        max_cardinality=8,
        trusted_planner_identities=frozenset({"planner_authority"}),
        agent_keys=agents,
    )
    yield monitor, store
    store.close()


def _author(monitor, gate_id, protected_object, *, callers, require_auth=False, workflow_id="wf"):
    return monitor.author_gate(
        gate_id=gate_id,
        workflow_id=workflow_id,
        protected_object=protected_object,
        direction=Direction.RELEASE,
        symbols=[Symbol("benign"), Symbol("escalate")],
        author_identity="planner_authority",
        permitted_callers=frozenset(callers),
        cap_bits=64.0,
        require_authenticated_caller=require_auth,
    )


CONTENT = "benign content"


def _cred(monitor, agent_id, key, gate_id, *, workflow_id="wf", epoch=0, content=CONTENT, args=None, ttl=300.0):
    return monitor.issue_call_credential(
        agent_id, key, gate_id, workflow_id, epoch, content, args=args, ttl_seconds=ttl
    )


def test_unauthenticated_gate_is_backward_compatible(monitor_and_store):
    """A gate that never opts into require_authenticated_caller behaves
    exactly as before this mechanism existed: bare caller_id membership is
    sufficient, no credential required. Every RQ1-RQ6 gate in this paper
    exercises only this dormant path."""
    monitor, store = monitor_and_store
    h = _author(monitor, "g1", "obj-a", callers={"planner"})
    o = monitor.invoke(h, CONTENT, caller_id="planner")
    assert o.outcome == Outcome.OK


def test_authenticated_gate_accepts_valid_credential(monitor_and_store, agents):
    monitor, store = monitor_and_store
    h = _author(monitor, "g1", "obj-b", callers={"planner"}, require_auth=True)
    cred = _cred(monitor, "planner", agents["planner"], "g1")
    o = monitor.invoke(h, CONTENT, caller_id="planner", credential=cred)
    assert o.outcome == Outcome.OK


def test_authenticated_gate_rejects_bare_caller_id_with_no_credential(monitor_and_store):
    """The exact gap this mechanism closes: on an authenticated gate, a bare
    caller_id claim -- what the whole system relied on before -- is no
    longer sufficient by itself."""
    monitor, store = monitor_and_store
    h = _author(monitor, "g1", "obj-c", callers={"planner"}, require_auth=True)
    o = monitor.invoke(h, CONTENT, caller_id="planner")
    assert o.outcome == Outcome.UNAUTHENTICATED_CALLER
    assert o.charged_bits == 0.0


def test_impersonation_with_wrong_key_is_rejected(monitor_and_store, agents):
    """"worker" attempts to invoke a gate that only permits "planner",
    claiming caller_id="planner" but signing with its own key."""
    monitor, store = monitor_and_store
    h = _author(monitor, "g1", "obj-d", callers={"planner"}, require_auth=True)
    # Build the forged credential by hand-assembling worker's genuine
    # signed fields under a false agent_id label -- issue_call_credential
    # always signs with the caller's own asserted agent_id, so an attacker
    # forging one must do this, not call the helper directly.
    genuine = _cred(monitor, "worker", agents["worker"], "g1")
    forged = CallerCredential(
        agent_id="planner",
        gate_id=genuine.gate_id,
        workflow_id=genuine.workflow_id,
        epoch=genuine.epoch,
        content_digest=genuine.content_digest,
        args_digest=genuine.args_digest,
        nonce=genuine.nonce,
        issued_at=genuine.issued_at,
        expires_at=genuine.expires_at,
        signature=genuine.signature,
    )
    o = monitor.invoke(h, CONTENT, caller_id="planner", credential=forged)
    assert o.outcome == Outcome.UNAUTHENTICATED_CALLER
    assert o.charged_bits == 0.0


def test_credential_is_bound_to_its_own_gate_id(monitor_and_store, agents):
    """A credential issued for gate g1 must not verify for a different
    gate g2, even for the same agent and even though g2 also permits that
    agent -- otherwise one captured credential would authenticate every
    future call by that agent rather than just the one it was issued for."""
    monitor, store = monitor_and_store
    h1 = _author(monitor, "g1", "obj-e1", callers={"planner"}, require_auth=True)
    h2 = _author(monitor, "g2", "obj-e2", callers={"planner"}, require_auth=True)
    cred_for_g1 = _cred(monitor, "planner", agents["planner"], "g1")

    o1 = monitor.invoke(h1, CONTENT, caller_id="planner", credential=cred_for_g1)
    assert o1.outcome == Outcome.OK

    replayed = CallerCredential(
        agent_id=cred_for_g1.agent_id,
        gate_id="g2",
        workflow_id=cred_for_g1.workflow_id,
        epoch=cred_for_g1.epoch,
        content_digest=cred_for_g1.content_digest,
        args_digest=cred_for_g1.args_digest,
        nonce=cred_for_g1.nonce,
        issued_at=cred_for_g1.issued_at,
        expires_at=cred_for_g1.expires_at,
        signature=cred_for_g1.signature,
    )
    o2 = monitor.invoke(h2, CONTENT, caller_id="planner", credential=replayed)
    assert o2.outcome == Outcome.UNAUTHENTICATED_CALLER


def test_unregistered_agent_cannot_authenticate(monitor_and_store):
    """A caller_id with no corresponding entry in agent_keys can never
    produce a valid credential -- there is no key for it to sign with that
    the monitor would trust."""
    monitor, store = monitor_and_store
    h = _author(monitor, "g1", "obj-f", callers={"ghost"}, require_auth=True)
    forged = CallerCredential(
        agent_id="ghost", gate_id="g1", workflow_id="wf", epoch=0,
        content_digest="0" * 64, args_digest="0" * 64, nonce="x",
        issued_at=0.0, expires_at=1e18, signature="0" * 64,
    )
    o = monitor.invoke(h, CONTENT, caller_id="ghost", credential=forged)
    assert o.outcome == Outcome.UNAUTHENTICATED_CALLER


# ---- stolen-token, delayed replay, cross-session, relay, concurrency ----

def test_stolen_credential_can_be_used_once_but_not_twice(monitor_and_store, agents):
    """An attacker who captures a genuine, unexpired, correctly-bound
    credential in transit (a compromised transport, a logging sidecar) can
    use it exactly once -- cryptographically, that use is indistinguishable
    from the legitimate agent's own -- but the nonce is then burned, so
    whichever of {attacker, legitimate holder} is *second* to present it is
    rejected even though the credential itself is completely genuine. This
    is the actual mitigation for a stolen token: not preventing capture,
    but making a captured credential worth at most one use, and denying
    that use to whoever presents it second, not whoever presents it
    first."""
    monitor, store = monitor_and_store
    h = _author(monitor, "g1", "obj-stolen", callers={"planner"}, require_auth=True)
    cred = _cred(monitor, "planner", agents["planner"], "g1")

    # The attacker (holding only the intercepted credential, not the key)
    # presents it first.
    o_attacker = monitor.invoke(h, CONTENT, caller_id="planner", credential=cred)
    assert o_attacker.outcome == Outcome.OK

    # The legitimate holder's own subsequent attempt with the same
    # credential is rejected -- both by gate replay and by nonce reuse.
    o_legit = monitor.invoke(h, CONTENT, caller_id="planner", credential=cred)
    assert o_legit.outcome in (Outcome.REPLAYED, Outcome.UNAUTHENTICATED_CALLER)


def test_delayed_replay_after_expiry_is_rejected(monitor_and_store, agents):
    """A credential captured and held back, then presented after its
    expiry window has passed, is rejected on freshness alone -- even
    though nothing else about it is wrong and its nonce was never
    consumed."""
    monitor, store = monitor_and_store
    h = _author(monitor, "g1", "obj-delayed", callers={"planner"}, require_auth=True)
    cred = _cred(monitor, "planner", agents["planner"], "g1", ttl=0.001)
    import time as _time
    _time.sleep(0.05)
    o = monitor.invoke(h, CONTENT, caller_id="planner", credential=cred)
    assert o.outcome == Outcome.UNAUTHENTICATED_CALLER


def test_cross_session_credential_from_a_stale_epoch_is_rejected(monitor_and_store, agents):
    """A credential signed against policy_epoch 0 must not authenticate a
    call once the object has moved to a new epoch via reauthorization --
    a credential captured in one "session" (epoch) cannot be replayed into
    a later one, even for the same agent and gate_id-shaped identifier."""
    monitor, store = monitor_and_store
    h = _author(monitor, "g1", "obj-epoch", callers={"planner"}, require_auth=True)
    cred_epoch_0 = _cred(monitor, "planner", agents["planner"], "g1", epoch=0)

    # Forge a credential claiming epoch=1 for the same still-epoch-0 gate --
    # simulating a captured credential replayed after the object's epoch
    # advanced. Since g1 itself is still at epoch 0, the record's own
    # policy_epoch is 0, so a credential asserting epoch=1 fails the
    # cross-check against the authoritative record regardless of the
    # signature's own validity for whatever it actually signed.
    stale = CallerCredential(
        agent_id=cred_epoch_0.agent_id,
        gate_id=cred_epoch_0.gate_id,
        workflow_id=cred_epoch_0.workflow_id,
        epoch=1,
        content_digest=cred_epoch_0.content_digest,
        args_digest=cred_epoch_0.args_digest,
        nonce=cred_epoch_0.nonce,
        issued_at=cred_epoch_0.issued_at,
        expires_at=cred_epoch_0.expires_at,
        signature=cred_epoch_0.signature,
    )
    o = monitor.invoke(h, CONTENT, caller_id="planner", credential=stale)
    assert o.outcome == Outcome.UNAUTHENTICATED_CALLER


def test_relay_with_tampered_content_is_rejected(monitor_and_store, agents):
    """An attacker relays a genuine credential but pairs it with different
    content than the agent actually signed -- e.g. a compromised transport
    that swaps the payload while forwarding a legitimate agent's already-
    signed credential. The credential authenticates a specific request, not
    a bare identity, so this must fail even though the credential itself
    is completely genuine and unexpired."""
    monitor, store = monitor_and_store
    h = _author(monitor, "g1", "obj-relay", callers={"planner"}, require_auth=True)
    cred = _cred(monitor, "planner", agents["planner"], "g1", content="escalate now")
    o = monitor.invoke(h, "totally different content", caller_id="planner", credential=cred)
    assert o.outcome == Outcome.UNAUTHENTICATED_CALLER


def test_relay_with_tampered_args_is_rejected(monitor_and_store, agents):
    monitor, store = monitor_and_store
    template = ActionTemplate(name="act", tool="act", max_effect_class=EffectClass.REVERSIBLE)
    h = monitor.author_gate(
        gate_id="g1", workflow_id="wf", protected_object="obj-relay-args",
        direction=Direction.ENDORSE, symbols=[Symbol("benign", template)],
        author_identity="planner_authority", permitted_callers=frozenset({"planner"}),
        cap_bits=64.0, require_authenticated_caller=True,
        max_effect_class=EffectClass.REVERSIBLE,
    )
    cred = _cred(monitor, "planner", agents["planner"], "g1", content="benign", args={"x": "1"})
    o = monitor.invoke(h, "benign", caller_id="planner", args={"x": "2"}, credential=cred)
    assert o.outcome == Outcome.UNAUTHENTICATED_CALLER


def test_concurrent_duplicate_presentation_exactly_one_wins(monitor_and_store, agents):
    """Two threads present the identical, genuinely-valid credential at the
    same time -- a legitimate retry racing the original request, or an
    attacker racing a legitimate holder with an intercepted credential.
    Nonce consumption is atomic, so exactly one must observe OK and the
    other must be rejected, deterministically, not probabilistically."""
    monitor, store = monitor_and_store
    h = _author(monitor, "g1", "obj-concurrent", callers={"planner"}, require_auth=True)
    cred = _cred(monitor, "planner", agents["planner"], "g1")

    barrier = threading.Barrier(2)
    results: dict[str, Outcome] = {}
    errors: list[BaseException] = []

    def _present(name):
        try:
            barrier.wait(timeout=5)
            obs = monitor.invoke(h, CONTENT, caller_id="planner", credential=cred)
            results[name] = obs.outcome
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    t1 = threading.Thread(target=_present, args=("a",))
    t2 = threading.Thread(target=_present, args=("b",))
    t1.start()
    t2.start()
    t1.join(timeout=10)
    t2.join(timeout=10)

    assert not errors, f"unexpected exceptions: {errors}"
    assert set(results) == {"a", "b"}
    outcomes = [results["a"], results["b"]]
    assert outcomes.count(Outcome.OK) == 1, f"expected exactly one winner, got {outcomes}"


def test_concurrent_duplicate_is_deterministic_across_repeated_trials(agents):
    """The same race as above, repeated on fresh state, to rule out the
    property holding only by scheduling luck on a single run."""
    import tempfile

    for trial in range(15):
        db_path = tempfile.mkdtemp() + f"/dup-{trial}.db"
        store = DurableStore(db_path)
        monitor = ReferenceMonitor(
            store, MockBackend(), default_cap_bits=64.0, max_cardinality=8,
            trusted_planner_identities=frozenset({"planner_authority"}),
            agent_keys=agents,
        )
        try:
            h = _author(monitor, "g1", "obj-concurrent-repeat", callers={"planner"}, require_auth=True)
            cred = _cred(monitor, "planner", agents["planner"], "g1")
            barrier = threading.Barrier(2)
            results = {}

            def _present(name):
                barrier.wait(timeout=5)
                results[name] = monitor.invoke(
                    h, CONTENT, caller_id="planner", credential=cred
                ).outcome

            t1 = threading.Thread(target=_present, args=("a",))
            t2 = threading.Thread(target=_present, args=("b",))
            t1.start()
            t2.start()
            t1.join(timeout=10)
            t2.join(timeout=10)
            outcomes = [results["a"], results["b"]]
            assert outcomes.count(Outcome.OK) == 1, (trial, outcomes)
        finally:
            store.close()


# ---- delegation ----------------------------------------------------------

def test_delegation_lets_a_non_permitted_agent_act_for_a_permitted_one(
    monitor_and_store, agents
):
    """"planner" is the only permitted_caller; it delegates this one gate to
    "worker", who redeems it with its own credential. worker is never added
    to permitted_callers directly -- authorization flows entirely through
    the delegation chain."""
    monitor, store = monitor_and_store
    h = _author(monitor, "g1", "obj-g", callers={"planner"}, require_auth=True)
    grant = monitor.issue_delegation("planner", agents["planner"], "worker", "g1")
    cred = _cred(monitor, "worker", agents["worker"], "g1")
    o = monitor.invoke(
        h, CONTENT, caller_id="worker", credential=cred, delegation=grant
    )
    assert o.outcome == Outcome.OK


def test_forwarded_delegation_without_the_delegates_own_key_fails(
    monitor_and_store, agents
):
    """Capability forwarding: "eavesdropper" obtains a full, valid copy of
    the delegation grant meant for "worker" but does not possess worker's
    key. Presenting the grant alone, or presenting it while claiming to
    *be* worker, is not sufficient."""
    monitor, store = monitor_and_store
    h = _author(monitor, "g1", "obj-h", callers={"planner"}, require_auth=True)
    grant = monitor.issue_delegation("planner", agents["planner"], "worker", "g1")

    genuine_from_eavesdropper = _cred(monitor, "eavesdropper", agents["eavesdropper"], "g1")
    forged_cred = CallerCredential(
        agent_id="worker",
        gate_id=genuine_from_eavesdropper.gate_id,
        workflow_id=genuine_from_eavesdropper.workflow_id,
        epoch=genuine_from_eavesdropper.epoch,
        content_digest=genuine_from_eavesdropper.content_digest,
        args_digest=genuine_from_eavesdropper.args_digest,
        nonce=genuine_from_eavesdropper.nonce,
        issued_at=genuine_from_eavesdropper.issued_at,
        expires_at=genuine_from_eavesdropper.expires_at,
        signature=genuine_from_eavesdropper.signature,
    )
    o = monitor.invoke(
        h, CONTENT, caller_id="worker", credential=forged_cred, delegation=grant
    )
    assert o.outcome == Outcome.UNAUTHORIZED_DELEGATION
    assert o.charged_bits == 0.0

    own_cred = _cred(monitor, "eavesdropper", agents["eavesdropper"], "g1")
    o2 = monitor.invoke(
        h, CONTENT, caller_id="eavesdropper", credential=own_cred, delegation=grant
    )
    assert o2.outcome == Outcome.UNAUTHORIZED_DELEGATION


def test_delegation_laundering_by_a_non_permitted_delegator_fails(
    monitor_and_store, agents
):
    """"worker" is not itself a permitted_caller and has no authority to
    delegate. Its signature on the grant verifies fine, but that is not
    the same claim as actually being authorized on this gate."""
    monitor, store = monitor_and_store
    h = _author(monitor, "g1", "obj-i", callers={"planner"}, require_auth=True)
    bogus_grant = monitor.issue_delegation(
        "worker", agents["worker"], "eavesdropper", "g1"
    )
    cred = _cred(monitor, "eavesdropper", agents["eavesdropper"], "g1")
    o = monitor.invoke(
        h, CONTENT, caller_id="eavesdropper", credential=cred, delegation=bogus_grant
    )
    assert o.outcome == Outcome.UNAUTHORIZED_DELEGATION


def test_delegation_grant_cannot_be_redeemed_twice(monitor_and_store, agents):
    """Replay: the same grant_id redeemed a second time -- even against a
    different, otherwise-valid gate the delegator also permits -- must
    fail."""
    monitor, store = monitor_and_store
    h1 = _author(monitor, "g1", "obj-j1", callers={"planner"}, require_auth=True)
    h2 = _author(monitor, "g2", "obj-j2", callers={"planner"}, require_auth=True)
    grant = monitor.issue_delegation("planner", agents["planner"], "worker", "g1")

    cred1 = _cred(monitor, "worker", agents["worker"], "g1")
    o1 = monitor.invoke(h1, CONTENT, caller_id="worker", credential=cred1, delegation=grant)
    assert o1.outcome == Outcome.OK

    replayed_grant = DelegationGrant(
        grant_id=grant.grant_id,
        delegator_agent_id=grant.delegator_agent_id,
        delegate_agent_id=grant.delegate_agent_id,
        gate_id="g2",
        expiration=grant.expiration,
        signature=grant.signature,
    )
    cred2 = _cred(monitor, "worker", agents["worker"], "g2")
    o2 = monitor.invoke(
        h2, CONTENT, caller_id="worker", credential=cred2, delegation=replayed_grant
    )
    assert o2.outcome == Outcome.UNAUTHORIZED_DELEGATION


def test_expired_delegation_is_rejected(monitor_and_store, agents):
    monitor, store = monitor_and_store
    h = _author(monitor, "g1", "obj-k", callers={"planner"}, require_auth=True)
    grant = monitor.issue_delegation(
        "planner", agents["planner"], "worker", "g1", expiration=1.0
    )
    cred = _cred(monitor, "worker", agents["worker"], "g1")
    o = monitor.invoke(h, CONTENT, caller_id="worker", credential=cred, delegation=grant)
    assert o.outcome == Outcome.UNAUTHORIZED_DELEGATION


def test_delegation_gate_id_binding_prevents_cross_gate_use(monitor_and_store, agents):
    """A grant issued for g1 must not authorize worker on g2, even though
    both are permitted to planner and planner is the delegator on both --
    delegation scope is per-gate, not per-workflow or per-object."""
    monitor, store = monitor_and_store
    _author(monitor, "g1", "obj-l1", callers={"planner"}, require_auth=True)
    h2 = _author(monitor, "g2", "obj-l2", callers={"planner"}, require_auth=True)
    grant_for_g1 = monitor.issue_delegation("planner", agents["planner"], "worker", "g1")
    cred = _cred(monitor, "worker", agents["worker"], "g2")
    o = monitor.invoke(
        h2, CONTENT, caller_id="worker", credential=cred, delegation=grant_for_g1
    )
    assert o.outcome == Outcome.UNAUTHORIZED_DELEGATION


# ---- redeemer-bound action capabilities ----------------------------------

def _author_with_action(monitor, gate_id, protected_object, *, callers):
    template = ActionTemplate(
        name="send_message", tool="send_message", max_effect_class=EffectClass.REVERSIBLE
    )
    return monitor.author_gate(
        gate_id=gate_id,
        workflow_id="wf",
        protected_object=protected_object,
        direction=Direction.ENDORSE,
        symbols=[Symbol("send", action=template)],
        author_identity="planner_authority",
        permitted_callers=frozenset(callers),
        cap_bits=64.0,
        max_effect_class=EffectClass.REVERSIBLE,
    )


def test_unbound_capability_redemption_is_backward_compatible(monitor_and_store):
    """A capability minted with no redeemer_agent_id (the default, and
    every existing single-agent use in this paper) redeems exactly as
    before this mechanism existed: no credential required at consume
    time."""
    monitor, store = monitor_and_store
    h = _author_with_action(monitor, "g1", "obj-m", callers={"planner"})
    o = monitor.invoke(h, "send", caller_id="planner")
    assert o.outcome == Outcome.OK
    action, args = monitor.consume_action_capability(o)
    assert action.name == "send_message"


def test_redeemer_bound_capability_requires_matching_credential(
    monitor_and_store, agents
):
    """"planner" triggers the decision but binds the resulting capability to
    "worker" as the only agent allowed to actually execute it. Redemption
    with no credential, or with the wrong agent's credential, fails;
    redemption with worker's own valid credential -- bound to the
    capability_id being redeemed -- succeeds."""
    monitor, store = monitor_and_store
    h = _author_with_action(monitor, "g1", "obj-n", callers={"planner"})
    o = monitor.invoke(h, "send", caller_id="planner", redeemer_agent_id="worker")
    assert o.outcome == Outcome.OK
    assert o.redeemer_agent_id == "worker"

    with pytest.raises(ProvenanceViolation):
        monitor.consume_action_capability(o)

    wrong_cred = monitor.issue_call_credential(
        "planner", agents["planner"], "g1", "", 0, o.capability_id, args=dict(o.authorized_args)
    )
    forged = CallerCredential(
        agent_id="worker",
        gate_id=wrong_cred.gate_id,
        workflow_id=wrong_cred.workflow_id,
        epoch=wrong_cred.epoch,
        content_digest=wrong_cred.content_digest,
        args_digest=wrong_cred.args_digest,
        nonce=wrong_cred.nonce,
        issued_at=wrong_cred.issued_at,
        expires_at=wrong_cred.expires_at,
        signature=wrong_cred.signature,
    )
    with pytest.raises(ProvenanceViolation):
        monitor.consume_action_capability(o, credential=forged)

    right_cred = monitor.issue_call_credential(
        "worker", agents["worker"], "g1", "", 0, o.capability_id, args=dict(o.authorized_args)
    )
    action, args = monitor.consume_action_capability(o, credential=right_cred)
    assert action.name == "send_message"


def test_forwarded_capability_without_redeemers_key_fails(monitor_and_store, agents):
    """Capability forwarding at the action-execution layer: "eavesdropper"
    obtains a complete, genuine copy of the Observation but does not hold
    worker's key. HMAC validity alone proves the capability is authentic;
    it does not prove eavesdropper is entitled to redeem it."""
    monitor, store = monitor_and_store
    h = _author_with_action(monitor, "g1", "obj-o", callers={"planner"})
    o = monitor.invoke(h, "send", caller_id="planner", redeemer_agent_id="worker")
    assert o.outcome == Outcome.OK

    own_cred = monitor.issue_call_credential(
        "eavesdropper", agents["eavesdropper"], "g1", "", 0, o.capability_id,
        args=dict(o.authorized_args),
    )
    with pytest.raises(ProvenanceViolation):
        monitor.consume_action_capability(o, credential=own_cred)


def test_failed_redemption_attempt_does_not_burn_the_capability(monitor_and_store, agents):
    """A rejected redemption attempt must not consume the one-time
    capability -- otherwise an attacker who merely observes a capability in
    flight could deny service to the legitimate redeemer."""
    monitor, store = monitor_and_store
    h = _author_with_action(monitor, "g1", "obj-p", callers={"planner"})
    o = monitor.invoke(h, "send", caller_id="planner", redeemer_agent_id="worker")

    with pytest.raises(ProvenanceViolation):
        monitor.consume_action_capability(o)

    right_cred = monitor.issue_call_credential(
        "worker", agents["worker"], "g1", "", 0, o.capability_id, args=dict(o.authorized_args)
    )
    action, args = monitor.consume_action_capability(o, credential=right_cred)
    assert action.name == "send_message"
