"""Legacy-named adversarial checks for the gate-record-v4 monitor.

The pytest functions in this file are test cases, not a one-to-one proof of a
separate 26-item checklist.  Process isolation, direct file/socket/tool bypass,
secret-dependent scheduling/stopping, and adaptive schema-family evaluation
are deployment or experiment obligations that this unit file does not close.
The tests retain their historical item comments to aid a future reviewed
crosswalk, but no "N of 26" claim should be inferred from their count.
"""

from __future__ import annotations

import math
import threading
import time

import pytest

from actions import ActionTemplate, ArgConstraint, EffectClass
from monitor import (
    DOMAIN_GATE,
    Direction,
    GateHandle,
    MockBackend,
    Outcome,
    ProvenanceViolation,
    ReferenceMonitor,
    SluiceV2Error,
    Symbol,
    TamperViolation,
    canonical_bytes,
    gate_cost_bits,
)
from store import DurableStore, ReplayError


def make_monitor(tmp_path, **kwargs):
    db = str(tmp_path / "monitor.db")
    store = DurableStore(db)
    return ReferenceMonitor(store, MockBackend(), **kwargs), store


# 1. Same-hash schema substitution ------------------------------------
def test_01_handle_with_forged_digest_rejected(tmp_path):
    mon, _ = make_monitor(tmp_path)
    handle = mon.author_gate("g1", "wf", "obj", Direction.ENDORSE,
                              [Symbol("a"), Symbol("b")], "planner", frozenset({"agentA"}))
    forged = GateHandle(gate_id=handle.gate_id, digest="0" * 64)
    with pytest.raises(TamperViolation):
        mon.invoke(forged, "content says a", "agentA")


# 2. Forged singleton alphabets yielding zero-bit arbitrary output -----
def test_02_singleton_alphabet_still_enforces_all_other_checks(tmp_path):
    """A singleton still has distinguishable post-decode failure outcomes,
    so it has a nonzero charge as well as caller and replay enforcement."""
    mon, _ = make_monitor(tmp_path)
    handle = mon.author_gate("g2", "wf", "obj", Direction.ENDORSE,
                              [Symbol("only")], "planner", frozenset({"agentA"}))
    obs = mon.invoke(handle, "irrelevant", "attacker_not_permitted")
    assert obs.outcome == Outcome.UNAUTHORIZED_CALLER
    obs2 = mon.invoke(handle, "irrelevant", "agentA")
    assert obs2.outcome == Outcome.OK
    assert obs2.charged_bits == gate_cost_bits(1) > 0
    obs3 = mon.invoke(handle, "irrelevant", "agentA")  # replay
    assert obs3.outcome == Outcome.REPLAYED
    assert obs3.charged_bits == 0.0


# 3. Step-ID (gate-id) substitution ------------------------------------
def test_03_gate_id_substitution_rejected(tmp_path):
    mon, _ = make_monitor(tmp_path)
    h1 = mon.author_gate("g3a", "wf", "obj", Direction.ENDORSE,
                          [Symbol("a"), Symbol("b")], "planner", frozenset({"agentA"}))
    h2 = mon.author_gate("g3b", "wf", "obj", Direction.ENDORSE,
                          [Symbol(f"v{i}") for i in range(16)], "planner", frozenset({"agentA"}))
    # Attacker swaps gate_id to point at the cheap 2-symbol gate while
    # keeping g3b's digest -- must fail the digest cross-check, not
    # silently execute against g3a's cheaper alphabet.
    swapped = GateHandle(gate_id=h1.gate_id, digest=h2.digest)
    with pytest.raises(TamperViolation):
        mon.invoke(swapped, "content", "agentA")


# 4. Nonce substitution -------------------------------------------------
def test_04_nonce_is_bound_into_the_digest(tmp_path):
    mon, _ = make_monitor(tmp_path)
    handle = mon.author_gate("g4", "wf", "obj", Direction.ENDORSE,
                              [Symbol("a"), Symbol("b")], "planner", frozenset({"agentA"}))
    record, digest, _ = mon._load_record("g4")
    import dataclasses
    tampered = dataclasses.replace(record, nonce="attacker-chosen-nonce")
    recomputed = mon._digest(tampered.to_canonical_dict(), DOMAIN_GATE)
    assert recomputed != digest  # changing the nonce changes the digest


# 5. Symbol-set / cardinality substitution -------------------------------
def test_05_cardinality_substitution_rejected(tmp_path):
    mon, _ = make_monitor(tmp_path)
    handle = mon.author_gate("g5", "wf", "obj", Direction.ENDORSE,
                              [Symbol("a"), Symbol("b")], "planner", frozenset({"agentA"}))
    record, digest, _ = mon._load_record("g5")
    import dataclasses
    widened = dataclasses.replace(record, symbols=record.symbols + (Symbol("EXTRA"),))
    recomputed = mon._digest(widened.to_canonical_dict(), DOMAIN_GATE)
    assert recomputed != digest


# 6. Provenance spoofing with caller-supplied strings --------------------
def test_06_invoke_accepts_no_provenance_or_schema_arguments(tmp_path):
    """Structural check on the capability-based API surface itself: an
    untrusted caller has no parameter through which to supply an alphabet,
    cost, protected-object name, or author identity -- only content,
    caller_id, and (optionally) action args."""
    import inspect
    sig = inspect.signature(ReferenceMonitor.invoke)
    param_names = set(sig.parameters) - {"self"}
    assert param_names == {"handle", "untrusted_content", "caller_id", "args"}
    forbidden = {"symbols", "schema", "cost_bits", "protected_object", "author_identity", "cardinality"}
    assert not (param_names & forbidden)


# 7. Budget overshoot when spent + next_cost > cap -----------------------
def test_07_atomic_reservation_never_overshoots_cap(tmp_path):
    call_cost = gate_cost_bits(4)
    cap = 2 * call_cost
    mon, _ = make_monitor(tmp_path, default_cap_bits=cap)
    handles = [
        mon.author_gate(f"g7-{i}", "wf", "obj7", Direction.ENDORSE,
                         [Symbol("a"), Symbol("b"), Symbol("c"), Symbol("d")],
                         "planner", frozenset({"agentA"}), cap_bits=cap)
        for i in range(10)
    ]
    outcomes = [mon.invoke(h, "content says a", "agentA").outcome for h in handles]
    assert outcomes.count(Outcome.OK) == 2
    assert Outcome.BUDGET_EXHAUSTED in outcomes
    assert mon.spent("obj7", 0) == pytest.approx(cap)


# 8. Success-vs-error leakage --------------------------------------------
def test_08_success_and_schema_violation_charge_identical_bits(tmp_path):
    class AlwaysBadBackend:
        def decode(self, content, values):
            return "NOT_IN_ALPHABET"

    from monitor import ReferenceMonitor as RM
    db = str(tmp_path / "m8.db")
    store = DurableStore(db)
    mon = RM(store, AlwaysBadBackend(), default_cap_bits=100.0)
    h_bad = mon.author_gate("g8bad", "wf", "obj8", Direction.ENDORSE,
                             [Symbol("a"), Symbol("b")], "planner", frozenset({"agentA"}))
    obs_bad = mon.invoke(h_bad, "content", "agentA")
    assert obs_bad.outcome == Outcome.SCHEMA_VIOLATION

    mon2 = RM(DurableStore(str(tmp_path / "m8b.db")), MockBackend(), default_cap_bits=100.0)
    h_ok = mon2.author_gate("g8ok", "wf", "obj8", Direction.ENDORSE,
                             [Symbol("a"), Symbol("b")], "planner", frozenset({"agentA"}))
    obs_ok = mon2.invoke(h_ok, "content says a", "agentA")
    assert obs_ok.outcome == Outcome.OK
    assert obs_bad.charged_bits == obs_ok.charged_bits == gate_cost_bits(2)


# 9. Exception/rejection/retry/timeout/termination leakage ---------------
def test_09_content_independent_outcomes_are_free_and_deterministic(tmp_path):
    mon, _ = make_monitor(tmp_path)
    handle = mon.author_gate("g9", "wf", "obj9", Direction.ENDORSE,
                              [Symbol("a"), Symbol("b")], "planner", frozenset({"agentA"}),
                              expiration=time.time() - 1)
    obs = mon.invoke(handle, "content says a", "agentA")
    assert obs.outcome == Outcome.EXPIRED
    assert obs.charged_bits == 0.0  # deterministic from (now > expiration), not content-dependent


def test_09b_retries_are_each_charged_in_full(tmp_path):
    """An attacker cannot get free repeated probes by triggering a
    content-dependent rejection and retrying -- each retry that reaches
    decode consumes a fresh gate (gates are single-use; a 'retry' must be
    a newly authored gate, which the trusted planner controls the cost
    of) rather than a free re-roll of the same reservation."""
    call_cost = gate_cost_bits(2)
    cap = call_cost + 0.5
    mon, _ = make_monitor(tmp_path, default_cap_bits=cap)
    h1 = mon.author_gate("g9c-1", "wf", "obj9c", Direction.ENDORSE,
                          [Symbol("a"), Symbol("b")], "planner", frozenset({"agentA"}), cap_bits=cap)
    obs1 = mon.invoke(h1, "content says a", "agentA")
    assert obs1.outcome == Outcome.OK
    assert obs1.charged_bits == call_cost
    h2 = mon.author_gate("g9c-2", "wf", "obj9c", Direction.ENDORSE,
                          [Symbol("a"), Symbol("b")], "planner", frozenset({"agentA"}), cap_bits=cap)
    obs2 = mon.invoke(h2, "content says a", "agentA")
    assert obs2.outcome == Outcome.BUDGET_EXHAUSTED
    assert mon.spent("obj9c", 0) == call_cost


# 10. Unauthorized reauthorization ---------------------------------------
def test_10_reauthorization_requires_valid_signature(tmp_path):
    real_key = b"authorizer-secret-key-0123456789"
    wrong_key = b"attacker-guessed-key-abcdefghijk"
    mon, _ = make_monitor(
        tmp_path, trusted_authorizer_keys={"human-approver": real_key}
    )
    mon.author_gate("g10", "wf", "obj10", Direction.ENDORSE,
                    [Symbol("a")], "planner", frozenset({"agentA"}))
    forged = mon.issue_reauthorization(
        "obj10", 0, 1, 16.0, "human-approver", wrong_key
    )
    with pytest.raises(TamperViolation):
        mon.redeem_reauthorization(forged)
    grant = mon.issue_reauthorization(
        "obj10", 0, 1, 16.0, "human-approver", real_key
    )
    mon.redeem_reauthorization(grant)
    with pytest.raises(ReplayError):
        mon.redeem_reauthorization(grant)


# 11. Budget reset / history deletion ------------------------------------
def test_11_reauthorization_creates_new_epoch_preserving_lifetime_history(tmp_path):
    key = b"authorizer-key-xxxxxxxxxxxxxxxxx"
    mon, _ = make_monitor(
        tmp_path, default_cap_bits=6.0, trusted_authorizer_keys={"approver": key}
    )
    h = mon.author_gate("g11", "wf", "obj11", Direction.ENDORSE,
                         [Symbol("a"), Symbol("b")], "planner", frozenset({"agentA"}), cap_bits=6.0)
    mon.invoke(h, "content says a", "agentA")
    call_cost = gate_cost_bits(2)
    assert mon.spent("obj11", 0) == call_cost
    grant = mon.issue_reauthorization("obj11", 0, 1, 6.0, "approver", key)
    mon.redeem_reauthorization(grant)
    assert mon.spent("obj11", 1) == 0.0  # new epoch starts fresh
    assert mon.spent("obj11", 0) == call_cost  # OLD epoch's spend is NOT erased
    assert mon.lifetime_spent("obj11") == call_cost  # visible to a lifetime audit


# 12. Negative, NaN, and infinite charges --------------------------------
def test_12_cost_is_monitor_computed_never_caller_or_planner_supplied_directly(tmp_path):
    import inspect
    sig = inspect.signature(ReferenceMonitor.author_gate)
    assert "cost_bits" not in sig.parameters and "authorized_cost_bits" not in sig.parameters
    # Cost covers the full typed post-decode support: K successful symbols
    # plus four generic failure outcomes, conservatively rounded upward.
    mon, _ = make_monitor(tmp_path)
    h = mon.author_gate("g12", "wf", "obj12", Direction.ENDORSE,
                         [Symbol(f"v{i}") for i in range(7)], "planner", frozenset({"a"}))
    record, _, _ = mon._load_record("g12")
    assert record.authorized_cost_bits == gate_cost_bits(7)
    assert record.authorized_cost_bits >= math.log2(7 + 4)
    assert record.authorized_cost_bits > 0 and math.isfinite(record.authorized_cost_bits)


# 13. Empty and duplicate symbols ----------------------------------------
def test_13a_empty_symbol_set_rejected(tmp_path):
    mon, _ = make_monitor(tmp_path)
    with pytest.raises(SluiceV2Error):
        mon.author_gate("g13a", "wf", "obj", Direction.ENDORSE, [], "planner", frozenset({"a"}))


def test_13b_duplicate_symbol_values_rejected(tmp_path):
    mon, _ = make_monitor(tmp_path)
    with pytest.raises(SluiceV2Error):
        mon.author_gate("g13b", "wf", "obj", Direction.ENDORSE,
                         [Symbol("a"), Symbol("a")], "planner", frozenset({"x"}))


# 14. Embedded NUL and Unicode normalization ambiguity -------------------
def test_14_canonical_bytes_is_exact_and_non_nfc_policy_is_rejected(tmp_path):
    assert canonical_bytes("a\x00b") != canonical_bytes("ab")
    combining = "é"  # 'e' + combining acute accent
    precomposed = "é"  # 'é'
    assert canonical_bytes(combining) != canonical_bytes(precomposed)
    mon, _ = make_monitor(tmp_path)
    with pytest.raises(SluiceV2Error, match="non-NFC"):
        mon.author_gate("g14", "wf", "obj14", Direction.ENDORSE,
                        [Symbol(combining)], "planner", frozenset({"agentA"}))


# 15. Canonical-serialization collisions ---------------------------------
def test_15_no_delimiter_injection_collision_between_distinct_structures(tmp_path):
    # A naive "|".join or string-concat hash could collide ["a|b"] with
    # ["a","b"]. Length-prefixing must prevent this.
    a = canonical_bytes(["a|b"])
    b = canonical_bytes(["a", "b"])
    assert a != b
    c = canonical_bytes({"ab": "c"})
    d = canonical_bytes({"a": "bc"})
    assert c != d


# 16. Concurrent lost updates --------------------------------------------
def test_16_concurrent_reservations_against_same_object_no_lost_updates(tmp_path):
    mon, _ = make_monitor(tmp_path, default_cap_bits=1_000_000.0)
    n = 40
    handles = [
        mon.author_gate(f"g16-{i}", "wf", "obj16", Direction.ENDORSE,
                         [Symbol("a"), Symbol("b")], "planner", frozenset({"agentA"}),
                         cap_bits=1_000_000.0)
        for i in range(n)
    ]
    errors = []

    def worker(h):
        try:
            mon.invoke(h, "content says a", "agentA")
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(h,)) for h in handles]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert mon.spent("obj16", 0) == pytest.approx(n * gate_cost_bits(2))


# 18. Restart and crash recovery -----------------------------------------
def test_18_state_survives_reopening_the_store_file(tmp_path):
    db = str(tmp_path / "crash.db")
    store1 = DurableStore(db)
    mon1 = ReferenceMonitor(store1, MockBackend(), default_cap_bits=10.0)
    h = mon1.author_gate("g18", "wf", "obj18", Direction.ENDORSE,
                          [Symbol("a"), Symbol("b")], "planner", frozenset({"agentA"}), cap_bits=10.0)
    mon1.invoke(h, "content says a", "agentA")
    spent_before = mon1.spent("obj18", 0)
    store1.close()  # simulates process exit; WAL is fsynced (PRAGMA synchronous=FULL)

    store2 = DurableStore(db)  # simulates process restart, same DB file
    mon2 = ReferenceMonitor(store2, MockBackend(), default_cap_bits=10.0)
    assert mon2.spent("obj18", 0) == spent_before
    replay = mon2.invoke(h, "content says a", "agentA")
    assert replay.outcome == Outcome.REPLAYED  # consumed-flag survived restart too
    assert store2.verify_audit_chain() is True


# 19. Replay attacks ------------------------------------------------------
def test_19_consumed_gate_cannot_be_invoked_twice(tmp_path):
    mon, _ = make_monitor(tmp_path)
    h = mon.author_gate("g19", "wf", "obj19", Direction.ENDORSE,
                         [Symbol("a"), Symbol("b")], "planner", frozenset({"agentA"}))
    first = mon.invoke(h, "content says a", "agentA")
    second = mon.invoke(h, "content says a", "agentA")
    assert first.outcome == Outcome.OK
    assert second.outcome == Outcome.REPLAYED


# 20/21. Variable-length traces / adaptive schema-family selection -------
def test_20_complete_typed_support_has_no_phantom_stop(tmp_path):
    mon, _ = make_monitor(tmp_path)
    h = mon.author_gate("g20", "wf", "obj20", Direction.ENDORSE,
                         [Symbol("a"), Symbol("b")], "planner", frozenset({"agentA"}))
    record, _, _ = mon._load_record("g20")
    charged = set(record.charged_observable_support())
    assert charged == {
        (Outcome.OK, "a"),
        (Outcome.OK, "b"),
        (Outcome.SCHEMA_VIOLATION, None),
        (Outcome.BACKEND_ERROR, None),
        (Outcome.ARG_INVALID, None),
        (Outcome.EFFECT_TOO_STRONG, None),
    }
    assert set(record.observable_alphabet()) >= charged
    assert record.authorized_cost_bits >= math.log2(len(charged))
    assert not hasattr(Outcome, "STOP")


# 22. CFI bypass when authorization is advisory ---------------------------
def test_22_checks_are_not_advisory_invoke_returns_the_gating_decision(tmp_path):
    """There is no separate 'authorize() -> bool' the caller could check
    and then ignore -- invoke() itself performs the action-relevant
    decode/validation and returns the actual outcome; a caller cannot get
    the value without also passing every check, structurally."""
    mon, _ = make_monitor(tmp_path)
    h = mon.author_gate("g22", "wf", "obj22", Direction.ENDORSE,
                         [Symbol("a"), Symbol("b")], "planner", frozenset({"agentA"}))
    obs = mon.invoke(h, "content says a", "unauthorized_caller_id")
    assert obs.value is None  # no value is EVER returned alongside a non-OK outcome
    assert obs.outcome == Outcome.UNAUTHORIZED_CALLER


# 23. Caller/callee identity spoofing --------------------------------------
def test_23_unlisted_caller_rejected(tmp_path):
    """caller_id AUTHENTICATION itself (proving an agent really is who it
    claims) is a framework-integration responsibility and an explicit TCB
    boundary -- documented, not silently assumed away. What this monitor
    guarantees is that an authenticated identity outside permitted_callers
    is rejected."""
    mon, _ = make_monitor(tmp_path)
    h = mon.author_gate("g23", "wf", "obj23", Direction.ENDORSE,
                         [Symbol("a"), Symbol("b")], "planner", frozenset({"agentA"}))
    obs = mon.invoke(h, "content says a", "agentB_spoofing_as_agentA")
    assert obs.outcome == Outcome.UNAUTHORIZED_CALLER


# 24. Authorized calls carrying prohibited arguments ------------------------
def test_24_prohibited_action_arguments_rejected(tmp_path):
    mon, _ = make_monitor(tmp_path)
    send_email = ActionTemplate(
        name="send_email", tool="email",
        arg_constraints={"to": ArgConstraint(allowed_values=frozenset({"ops@company.com"}))},
        max_effect_class=EffectClass.IRREVERSIBLE,
    )
    h = mon.author_gate("g24", "wf", "obj24", Direction.ENDORSE,
                         [Symbol("send", send_email), Symbol("noop")],
                         "planner", frozenset({"agentA"}), max_effect_class=EffectClass.IRREVERSIBLE)
    obs = mon.invoke(h, "content says send", "agentA", args={"to": "attacker@evil.example"})
    assert obs.outcome == Outcome.ARG_INVALID
    assert obs.charged_bits > 0  # still charged -- the attempt itself cost real budget


# 25. Authorized calls causing prohibited external effects ------------------
def test_25_effect_ceiling_is_trusted_policy_not_a_caller_override(tmp_path):
    mon, _ = make_monitor(tmp_path)
    delete_all = ActionTemplate(name="delete_all_files", tool="fs", max_effect_class=EffectClass.IRREVERSIBLE)
    with pytest.raises(SluiceV2Error, match="exceeds gate ceiling"):
        mon.author_gate("g25", "wf", "obj25", Direction.ENDORSE,
                        [Symbol("delete", delete_all), Symbol("noop")],
                        "planner", frozenset({"agentA"}),
                        max_effect_class=EffectClass.REVERSIBLE)
