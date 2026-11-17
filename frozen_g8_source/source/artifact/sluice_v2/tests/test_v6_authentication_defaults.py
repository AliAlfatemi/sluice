"""Regression tests for secure-by-default caller authentication.

These tests intentionally describe the repaired contract.  They are added
before the implementation change so the vulnerable baseline fails for the
specific reasons recorded in the revision evidence.
"""

from __future__ import annotations

import json

import pytest

from sluice_v2.monitor import (
    DOMAIN_GATE,
    Direction,
    GateHandle,
    MockBackend,
    Outcome,
    ReferenceMonitor,
    SluiceV2Error,
    Symbol,
    TamperViolation,
)
from sluice_v2.store import DurableStore


AGENT_KEY = b"authenticated-agent-key-material-32b"
CONTENT = "allow"


@pytest.fixture()
def monitor_and_store(tmp_path):
    store = DurableStore(str(tmp_path / "auth-defaults.db"))
    monitor = ReferenceMonitor(
        store,
        MockBackend(),
        default_cap_bits=64.0,
        trusted_planner_identities=frozenset({"planner"}),
        agent_keys={"agent": AGENT_KEY},
    )
    yield monitor, store
    store.close()


def _author(
    monitor: ReferenceMonitor,
    gate_id: str,
    protected_object: str,
    **authentication_policy,
) -> GateHandle:
    return monitor.author_gate(
        gate_id=gate_id,
        workflow_id="wf-auth-default",
        protected_object=protected_object,
        direction=Direction.RELEASE,
        symbols=[Symbol("allow"), Symbol("deny")],
        author_identity="planner",
        permitted_callers=frozenset({"agent"}),
        cap_bits=64.0,
        **authentication_policy,
    )


def _credential(monitor: ReferenceMonitor, gate_id: str):
    return monitor.issue_call_credential(
        "agent",
        AGENT_KEY,
        gate_id,
        "wf-auth-default",
        0,
        CONTENT,
    )


def test_omitted_authentication_policy_rejects_bare_caller_claim(
    monitor_and_store,
):
    """Merely supplying a permitted caller_id is not authentication."""
    monitor, _store = monitor_and_store
    handle = _author(monitor, "default-rejects-bare", "auth-object-bare")

    observation = monitor.invoke(handle, CONTENT, caller_id="agent")

    assert observation.outcome == Outcome.UNAUTHENTICATED_CALLER
    assert observation.charged_bits == 0.0


def test_omitted_authentication_policy_accepts_valid_bound_credential(
    monitor_and_store,
):
    """The new secure default remains usable with a valid fresh proof."""
    monitor, _store = monitor_and_store
    handle = _author(monitor, "default-accepts-proof", "auth-object-proof")
    credential = _credential(monitor, handle.gate_id)

    observation = monitor.invoke(
        handle,
        CONTENT,
        caller_id="agent",
        credential=credential,
    )

    assert observation.outcome == Outcome.OK


@pytest.mark.parametrize("invalid_policy", ["false", "true", 0, 1])
def test_authentication_policy_rejects_string_and_integer_bool_likes(
    monitor_and_store,
    invalid_policy,
):
    """Policy authors cannot cross the trust boundary via Python truthiness."""
    monitor, _store = monitor_and_store

    with pytest.raises(SluiceV2Error):
        _author(
            monitor,
            f"invalid-auth-policy-{invalid_policy!s}",
            f"invalid-auth-object-{type(invalid_policy).__name__}-{invalid_policy!s}",
            unsafe_allow_unauthenticated_caller=invalid_policy,
        )


def test_authenticated_policy_accepts_an_actual_boolean(monitor_and_store):
    monitor, _store = monitor_and_store
    handle = _author(
        monitor,
        "explicit-auth-boolean",
        "auth-object-explicit",
        unsafe_allow_unauthenticated_caller=False,
    )
    credential = _credential(monitor, handle.gate_id)

    observation = monitor.invoke(
        handle,
        CONTENT,
        caller_id="agent",
        credential=credential,
    )

    assert observation.outcome == Outcome.OK


def test_explicitly_named_unsafe_compatibility_is_opt_in_and_audited(
    monitor_and_store,
):
    monitor, store = monitor_and_store
    handle = _author(
        monitor,
        "explicit-unsafe-compat",
        "auth-object-unsafe-compat",
        unsafe_allow_unauthenticated_caller=True,
    )

    observation = monitor.invoke(handle, CONTENT, caller_id="agent")

    assert observation.outcome == Outcome.OK
    authored = [
        entry
        for entry in store.audit_log()
        if entry["event"] == "gate_authored"
        and entry["gate_id"] == handle.gate_id
    ]
    assert authored[-1]["detail"]["caller_authentication"] == (
        "unsafe_caller_id_compat"
    )


def test_authenticated_policy_string_in_signed_storage_fails_closed(
    monitor_and_store,
):
    """Even a correctly MACed record must not deserialize a string as bool."""
    monitor, store = monitor_and_store
    handle = _author(
        monitor,
        "stored-auth-string",
        "auth-object-stored",
        unsafe_allow_unauthenticated_caller=False,
    )
    row = store.get_gate(handle.gate_id)
    assert row is not None
    malformed = dict(row["record"])
    malformed["require_authenticated_caller"] = "false"
    malformed_digest = monitor._digest(malformed, DOMAIN_GATE)

    with store.transaction() as conn:
        conn.execute(
            "UPDATE gates SET record_json=?, digest=? WHERE gate_id=?",
            (json.dumps(malformed, sort_keys=True), malformed_digest, handle.gate_id),
        )

    malformed_handle = GateHandle(handle.gate_id, malformed_digest)
    with pytest.raises(TamperViolation):
        monitor.invoke(malformed_handle, CONTENT, caller_id="agent")
