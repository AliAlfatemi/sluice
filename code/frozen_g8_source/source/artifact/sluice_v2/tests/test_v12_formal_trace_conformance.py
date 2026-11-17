"""Executable conformance checks for the independent ``SluiceSecure`` checker."""

from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import random

import pytest

from sluice_v2.formal_trace import (
    AbstractTransitionV1,
    FormalManifest,
    FormalTraceError,
    canonical_json_line,
    check_trace,
)


TRACE_ID = "formalTrace_20260820_AA"


def _manifest_mapping():
    return {
        "schema_version": "sluice.formal-config.v1",
        "domains": ["d0", "d1"],
        "objects": ["o0", "o1", "o2"],
        "workflows": ["w0", "w1"],
        "agents": ["a0", "a1"],
        "nonces": ["n0", "n1"],
        "redeemers": ["r0", "r1"],
        "scopes": [
            {"domain_slot": 0, "workflow_slot": 0, "object_slot": 0, "epoch": 0},
            {"domain_slot": 0, "workflow_slot": 0, "object_slot": 0, "epoch": 1},
            {"domain_slot": 0, "workflow_slot": 0, "object_slot": 1, "epoch": 0},
            {"domain_slot": 1, "workflow_slot": 1, "object_slot": 2, "epoch": 0},
        ],
        "gates": [
            {
                "name": "g-pre",
                "scope_slot": 0,
                "successor_gate_slots": [1, 2, 6],
                "requires_capability": False,
            },
            {"name": "g-a", "scope_slot": 0, "successor_gate_slots": [], "requires_capability": False},
            {"name": "g-b", "scope_slot": 0, "successor_gate_slots": [], "requires_capability": False},
            {"name": "g-effect-a", "scope_slot": 2, "successor_gate_slots": [], "requires_capability": True},
            {"name": "g-effect-b", "scope_slot": 3, "successor_gate_slots": [], "requires_capability": True},
            {"name": "g-epoch-one", "scope_slot": 1, "successor_gate_slots": [], "requires_capability": False},
            {"name": "g-cross-domain", "scope_slot": 3, "successor_gate_slots": [], "requires_capability": False},
        ],
        "delegations": [
            {"name": "del0", "agent_slot": 0, "gate_slot": 0},
            {"name": "del1", "agent_slot": 1, "gate_slot": 6},
        ],
        "reauth_grants": [
            {"name": "reauth0", "domain_slot": 0},
            {"name": "reauth1", "domain_slot": 1},
        ],
        "capabilities": [
            {"name": "cap0", "gate_slot": 3, "redeemer_slot": 0},
            {"name": "cap1", "gate_slot": 4, "redeemer_slot": 1},
        ],
        "event_charge_units": 1,
        "initial_budget_units": 3,
        "initial_horizon": 3,
        "reauth_budget_increment_units": 2,
        "reauth_attempt_increment": 2,
        "max_epoch": 1,
    }


@pytest.fixture
def manifest_line():
    return canonical_json_line(_manifest_mapping())


@pytest.fixture
def manifest(manifest_line):
    return FormalManifest.from_bytes(manifest_line)


def test_checked_manifest_is_the_exact_frozen_tlc_scope(manifest_line):
    frozen = Path(__file__).resolve().parents[2] / "formal" / "SluiceSecureTraceManifest.json"
    assert frozen.read_bytes() == manifest_line


def _projection(
    *,
    epoch=0,
    epoch_spent=(0, 0),
    attempts=0,
    horizon=3,
    spent=0,
    budget=3,
    visible=0,
    closed=False,
    auth=0,
):
    return {
        "epoch": epoch,
        "epoch_spent": epoch_spent,
        "attempts": attempts,
        "horizon": horizon,
        "spent": spent,
        "budget": budget,
        "visible": visible,
        "closed": closed,
        "auth": auth,
    }


def _transition(
    manifest,
    step,
    action,
    outcome,
    before,
    after,
    *,
    domain=0,
    scope=None,
    gate=None,
    agent=None,
    nonce=None,
    delegation=None,
    reauth=None,
    capability=None,
    redeemer=None,
    predecessor=None,
    gate_delta=0,
    nonce_delta=0,
    delegation_delta=0,
    reauth_delta=0,
    capability_delta=0,
    audit_delta=0,
    padding_delta=0,
):
    return AbstractTransitionV1(
        schema_version=1,
        config_sha256=manifest.config_sha256,
        trace_id=TRACE_ID,
        step=step,
        action=action,
        outcome=outcome,
        domain_slot=domain,
        scope_slot=scope,
        gate_slot=gate,
        agent_slot=agent,
        nonce_slot=nonce,
        delegation_slot=delegation,
        reauth_grant_slot=reauth,
        capability_slot=capability,
        redeemer_slot=redeemer,
        predecessor_gate_slot=predecessor,
        epoch_before=before["epoch"],
        epoch_after=after["epoch"],
        epoch_spent_before=before["epoch_spent"],
        epoch_spent_after=after["epoch_spent"],
        attempts_before=before["attempts"],
        attempts_after=after["attempts"],
        horizon_before=before["horizon"],
        horizon_after=after["horizon"],
        lifetime_spent_before=before["spent"],
        lifetime_spent_after=after["spent"],
        lifetime_budget_before=before["budget"],
        lifetime_budget_after=after["budget"],
        visible_events_before=before["visible"],
        visible_events_after=after["visible"],
        closed_before=before["closed"],
        closed_after=after["closed"],
        gate_claim_delta=gate_delta,
        nonce_use_delta=nonce_delta,
        delegation_use_delta=delegation_delta,
        reauth_use_delta=reauth_delta,
        capability_use_delta=capability_delta,
        audit_start_delta=audit_delta,
        padding_event_delta=padding_delta,
        authorization_version_before=before["auth"],
        authorization_version_after=after["auth"],
    )


def _wire(*records):
    return b"".join(record.to_wire() for record in records)


def test_direct_successor_rejection_close_and_stutter(manifest_line, manifest):
    p0 = _projection()
    p1 = _projection(epoch_spent=(1, 0), attempts=1, spent=1, auth=2)
    p2 = _projection(epoch_spent=(1, 0), attempts=1, spent=1, visible=1, auth=2)
    p3 = _projection(epoch_spent=(2, 0), attempts=2, spent=2, visible=1, auth=4)
    p4 = _projection(epoch_spent=(2, 0), attempts=2, spent=2, visible=2, auth=4)
    p5 = _projection(epoch_spent=(3, 0), attempts=3, spent=3, visible=3, auth=4)
    p6 = _projection(epoch_spent=(3, 0), attempts=3, spent=3, visible=3, closed=True, auth=4)
    records = [
        _transition(manifest, 1, "commit_direct", "reserved", p0, p1, scope=0, gate=0, agent=0, nonce=0, gate_delta=1, nonce_delta=1, audit_delta=1),
        _transition(manifest, 2, "finalize", "released", p1, p2, gate=0),
        _transition(manifest, 3, "commit_direct", "reserved", p2, p3, scope=0, gate=1, agent=0, nonce=1, predecessor=0, gate_delta=1, nonce_delta=1, audit_delta=1),
        _transition(manifest, 4, "finalize", "output_denied", p3, p4, gate=1),
        _transition(manifest, 5, "reject_scoped_direct", "route_denied", p4, p5, scope=0, gate=2, agent=1, nonce=0, predecessor=1),
        _transition(manifest, 6, "close_at_horizon", "domain_closed", p5, p6),
        _transition(manifest, 7, "closed_reply_stutter", "domain_closed", p6, p6),
    ]
    report = check_trace(manifest_line, _wire(*records))
    assert report.transitions == 7
    assert report.final_authorization_version == 4
    assert report.final_attempts == (3, 0)


def test_reauthorization_epoch_stale_rejection_and_stop_padding(manifest_line, manifest):
    p0 = _projection()
    p1 = _projection(epoch_spent=(1, 0), attempts=1, spent=1, visible=1)
    p2 = _projection(epoch=1, epoch_spent=(2, 0), attempts=2, horizon=5, spent=2, budget=5, visible=2, auth=1)
    p3 = _projection(epoch=1, epoch_spent=(2, 1), attempts=3, horizon=5, spent=3, budget=5, visible=2, auth=3)
    p4 = _projection(epoch=1, epoch_spent=(2, 1), attempts=3, horizon=5, spent=3, budget=5, visible=3, auth=3)
    p5 = _projection(epoch=1, epoch_spent=(2, 2), attempts=4, horizon=5, spent=4, budget=5, visible=4, auth=3)
    p6 = _projection(epoch=1, epoch_spent=(2, 3), attempts=5, horizon=5, spent=5, budget=5, visible=5, closed=True, auth=3)
    records = [
        _transition(manifest, 1, "continue", "continued", p0, p1),
        _transition(manifest, 2, "reauthorize", "reauthorized", p1, p2, reauth=0, reauth_delta=1),
        _transition(manifest, 3, "commit_direct", "reserved", p2, p3, scope=1, gate=5, agent=0, nonce=0, gate_delta=1, nonce_delta=1, audit_delta=1),
        _transition(manifest, 4, "finalize", "internal_denied", p3, p4, gate=5),
        _transition(manifest, 5, "reject_stale_epoch", "auth_denied", p4, p5, scope=0, gate=0, agent=0, nonce=1),
        _transition(manifest, 6, "stop_and_pad", "stopped", p5, p6),
    ]
    report = check_trace(manifest_line, _wire(*records))
    assert report.final_attempts == (5, 0)
    assert report.final_visible_events == (5, 0)


def test_delegated_and_effect_capability_transitions(manifest_line, manifest):
    d0 = _projection()
    d1 = _projection(epoch_spent=(1, 0), attempts=1, spent=1, auth=3)
    d2 = _projection(epoch_spent=(1, 0), attempts=1, spent=1, visible=1, auth=3)
    d3 = _projection(epoch_spent=(3, 0), attempts=3, spent=3, visible=3, closed=True, auth=3)
    records = [
        _transition(manifest, 1, "commit_delegated", "reserved", d0, d1, scope=0, gate=0, agent=0, nonce=0, delegation=0, gate_delta=1, nonce_delta=1, delegation_delta=1, audit_delta=1),
        _transition(manifest, 2, "finalize", "released", d1, d2, gate=0),
        _transition(manifest, 3, "stop_and_pad", "stopped", d2, d3, padding_delta=1),
    ]
    report = check_trace(manifest_line, _wire(*records))
    assert report.final_authorization_version == 3

    a0 = _projection()
    a1 = _projection(epoch_spent=(1, 0), attempts=1, spent=1, auth=3)
    a2 = _projection(epoch_spent=(1, 0), attempts=1, spent=1, visible=1, auth=3)
    b0 = _projection(auth=3)
    b1 = _projection(epoch_spent=(1, 0), attempts=1, spent=1, visible=1, auth=3)
    b2 = _projection(epoch_spent=(2, 0), attempts=2, spent=2, visible=1, auth=6)
    b3 = _projection(epoch_spent=(2, 0), attempts=2, spent=2, visible=2, auth=6)
    b4 = _projection(epoch_spent=(3, 0), attempts=3, spent=3, visible=3, closed=True, auth=6)
    effects = [
        _transition(manifest, 1, "commit_effect", "reserved", a0, a1, scope=2, gate=3, agent=0, nonce=0, capability=0, redeemer=0, gate_delta=1, nonce_delta=1, capability_delta=1, audit_delta=1),
        _transition(manifest, 2, "finalize", "released", a1, a2, gate=3),
        _transition(manifest, 3, "reject_capability_binding", "capability_denied", b0, b1, domain=1, scope=3, gate=4, agent=1, nonce=1, capability=1, redeemer=0),
        _transition(manifest, 4, "commit_effect", "reserved", b1, b2, domain=1, scope=3, gate=4, agent=1, nonce=0, capability=1, redeemer=1, gate_delta=1, nonce_delta=1, capability_delta=1, audit_delta=1),
        _transition(manifest, 5, "finalize", "output_denied", b2, b3, domain=1, gate=4),
        _transition(manifest, 6, "stop_and_pad", "stopped", b3, b4, domain=1),
    ]
    report = check_trace(manifest_line, _wire(*effects))
    assert report.final_attempts == (1, 3)
    assert report.final_authorization_version == 6


def test_cross_domain_successor_cannot_commit(manifest_line, manifest):
    p0 = _projection()
    p1 = _projection(epoch_spent=(1, 0), attempts=1, spent=1, auth=2)
    p2 = _projection(epoch_spent=(1, 0), attempts=1, spent=1, visible=1, auth=2)
    # Gate 6 is named as gate 0's successor but has domain/scope 1/3.  Its own
    # scope has no current predecessor, so the TLA SuccessorAuthorized guard is
    # false and a commit label must be rejected by the independent checker.
    b0 = _projection(auth=2)
    b1 = _projection(epoch_spent=(1, 0), attempts=1, spent=1, auth=4)
    invalid = [
        _transition(manifest, 1, "commit_direct", "reserved", p0, p1, scope=0, gate=0, agent=0, nonce=0, gate_delta=1, nonce_delta=1, audit_delta=1),
        _transition(manifest, 2, "finalize", "released", p1, p2, gate=0),
        _transition(manifest, 3, "commit_direct", "reserved", b0, b1, domain=1, scope=3, gate=6, agent=1, nonce=1, gate_delta=1, nonce_delta=1, audit_delta=1),
    ]
    with pytest.raises(FormalTraceError, match="CommitDirect guard"):
        check_trace(manifest_line, _wire(*invalid))


def test_every_transition_field_is_checked(manifest_line, manifest):
    p0 = _projection()
    p1 = _projection(epoch_spent=(1, 0), attempts=1, spent=1, visible=1)
    p2 = _projection(epoch_spent=(2, 0), attempts=2, spent=2, visible=2)
    first = _transition(manifest, 1, "continue", "continued", p0, p1)
    second = _transition(manifest, 2, "continue", "continued", p1, p2)

    mutations = {
        "schema_version": 2,
        "config_sha256": "0" * 64,
        "trace_id": "differentTrace_20260820_BB",
        "step": 3,
        "action": "stop_and_pad",
        "outcome": "released",
        "domain_slot": 1,
        "scope_slot": 0,
        "gate_slot": 0,
        "agent_slot": 0,
        "nonce_slot": 0,
        "delegation_slot": 0,
        "reauth_grant_slot": 0,
        "capability_slot": 0,
        "redeemer_slot": 0,
        "predecessor_gate_slot": 0,
        "epoch_before": 1,
        "epoch_after": 1,
        "epoch_spent_before": (9, 0),
        "epoch_spent_after": (9, 0),
        "attempts_before": 9,
        "attempts_after": 9,
        "horizon_before": 9,
        "horizon_after": 9,
        "lifetime_spent_before": 9,
        "lifetime_spent_after": 9,
        "lifetime_budget_before": 9,
        "lifetime_budget_after": 9,
        "visible_events_before": 9,
        "visible_events_after": 9,
        "closed_before": True,
        "closed_after": True,
        "gate_claim_delta": 1,
        "nonce_use_delta": 1,
        "delegation_use_delta": 1,
        "reauth_use_delta": 1,
        "capability_use_delta": 1,
        "audit_start_delta": 1,
        "padding_event_delta": 1,
        "authorization_version_before": 9,
        "authorization_version_after": 9,
    }
    for field, value in mutations.items():
        mutated = replace(second, **{field: value})
        with pytest.raises(FormalTraceError):
            check_trace(manifest_line, _wire(first, mutated))


def test_strict_manifest_and_jsonl_parser_fail_closed(manifest_line, manifest):
    mapping = _manifest_mapping()
    mapping["unexpected"] = 1
    with pytest.raises(FormalTraceError, match="key mismatch"):
        FormalManifest.from_bytes(canonical_json_line(mapping))

    noncanonical = json.dumps(_manifest_mapping(), sort_keys=False).encode() + b"\n"
    with pytest.raises(FormalTraceError, match="canonical"):
        FormalManifest.from_bytes(noncanonical)

    p0 = _projection()
    p1 = _projection(epoch_spent=(1, 0), attempts=1, spent=1, visible=1)
    event = _transition(manifest, 1, "continue", "continued", p0, p1)
    with pytest.raises(FormalTraceError, match="truncated"):
        check_trace(manifest_line, event.to_wire()[:-1])

    raw = event.to_wire().decode().strip()
    duplicate = raw[:-1] + ',"step":1}\n'
    with pytest.raises(FormalTraceError, match="duplicate"):
        check_trace(manifest_line, duplicate.encode())

    bool_step = event.to_mapping()
    bool_step["step"] = True
    with pytest.raises(FormalTraceError, match="strict integer"):
        check_trace(manifest_line, canonical_json_line(bool_step))


def test_randomized_two_domain_lifecycle_traces(manifest_line, manifest):
    """Exercise 64 deterministic adaptive interleavings against reconstructed Init."""

    for seed in range(64):
        rng = random.Random(0x5A17CE + seed)
        states = [_projection(), _projection()]
        records = []
        step = 0
        while not all(state["closed"] for state in states):
            candidates = [index for index, state in enumerate(states) if not state["closed"]]
            domain = rng.choice(candidates)
            before = dict(states[domain])
            after = dict(before)
            step += 1
            if before["attempts"] == before["horizon"]:
                after["closed"] = True
                action, outcome, padding = "close_at_horizon", "domain_closed", 0
            elif rng.random() < 0.35:
                remaining = before["horizon"] - before["attempts"]
                after["attempts"] = before["horizon"]
                after["spent"] += remaining
                epoch_vector = list(before["epoch_spent"])
                epoch_vector[before["epoch"]] += remaining
                after["epoch_spent"] = tuple(epoch_vector)
                after["visible"] += remaining
                after["closed"] = True
                action, outcome, padding = "stop_and_pad", "stopped", remaining - 1
            else:
                after["attempts"] += 1
                after["spent"] += 1
                epoch_vector = list(before["epoch_spent"])
                epoch_vector[before["epoch"]] += 1
                after["epoch_spent"] = tuple(epoch_vector)
                after["visible"] += 1
                action, outcome, padding = "continue", "continued", 0
            records.append(
                _transition(
                    manifest,
                    step,
                    action,
                    outcome,
                    before,
                    after,
                    domain=domain,
                    padding_delta=padding,
                )
            )
            states[domain] = after

        for _ in range(rng.randrange(4)):
            domain = rng.randrange(2)
            step += 1
            records.append(
                _transition(
                    manifest,
                    step,
                    "closed_reply_stutter",
                    "domain_closed",
                    states[domain],
                    states[domain],
                    domain=domain,
                )
            )
        report = check_trace(manifest_line, _wire(*records))
        assert report.final_attempts == (3, 3)
        assert report.final_visible_events == (3, 3)
