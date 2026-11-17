"""Fail-first contract for exact in-memory credential payload execution.

The in-memory prototype is not a G2 boundary, but a successful credential
claim must still execute the exact canonical payload that was authenticated.
The caller's mutable object must never remain the handler's data source.
"""

from __future__ import annotations

import threading

from sluice_v2.observer import OutcomeCode
from sluice_v2.secure import (
    AttemptCredential,
    DomainConfig,
    ObserverSpec,
    RouteCodebook,
    SecureDomain,
)


CALLER_KEY = b"inmemory-snapshot-caller-key-32b"


def test_handler_receives_exact_authenticated_payload_snapshot() -> None:
    codebook = RouteCodebook(
        name="release",
        public_values=frozenset({0, 1}),
        requires_capability=False,
    )
    observer = ObserverSpec(
        permitted_value_codes=frozenset({0, 1}),
        observer_spec_id="inmemory-snapshot-observer-v1",
        route_codebooks=(codebook,),
    )
    domain = SecureDomain(
        DomainConfig(
            domain_id="inmemory-snapshot-domain",
            protected_objects=frozenset({"protected"}),
            lifetime_budget_units=4,
            attempt_horizon=1,
            event_charge_units=4,
        ),
        observer_spec=observer,
        agent_keys={"worker": CALLER_KEY},
        reauthorization_keys={},
    )

    handler_entered = threading.Event()
    allow_handler_read = threading.Event()
    observed_values: list[int] = []

    def handler(handler_payload: object) -> int:
        assert isinstance(handler_payload, dict)
        handler_entered.set()
        assert allow_handler_read.wait(timeout=2)
        value = handler_payload["value"]
        assert type(value) is int
        observed_values.append(value)
        return value

    route = domain.register_route(
        name="release",
        protected_object="protected",
        handler=handler,
        public_values=frozenset({0, 1}),
        requires_capability=False,
    )
    domain.seal()
    domain.activate()

    caller_payload = {"value": 0}
    credential = AttemptCredential.sign(
        agent_id="worker",
        signing_key=CALLER_KEY,
        route=route,
        payload=caller_payload,
        nonce="snapshot-nonce",
    )
    results = []

    worker = threading.Thread(
        target=lambda: results.append(
            domain.attempt(route, caller_payload, credential=credential)
        )
    )
    worker.start()
    assert handler_entered.wait(timeout=2)
    caller_payload["value"] = 1
    allow_handler_read.set()
    worker.join(timeout=2)

    assert not worker.is_alive()
    assert len(results) == 1
    assert results[0].outcome is OutcomeCode.RELEASED
    assert results[0].value_code == 0
    assert observed_values == [0]
