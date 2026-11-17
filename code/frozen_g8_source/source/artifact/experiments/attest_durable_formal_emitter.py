#!/usr/bin/env python3
"""Emit one reproducible trace from real durable v2 operations and attest it."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile

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
from sluice_v2.formal_emitter import DurableFormalBinding, DurableFormalEmitter


CALLER_KEY = b"formal-emitter-caller-key-32bytes"
REAUTH_KEY = b"formal-emitter-reauth-key-32bytes"


def direct_handler(_payload):
    return 0


def effect_execute(request: EffectRequest) -> EffectResult:
    return EffectResult.for_request(request, 1)


def effect_reconcile(_request: EffectRequest) -> EffectResult | None:
    return None


HANDLERS = {
    "direct": direct_handler,
    "effect": IdempotentEffectHandler(effect_execute, effect_reconcile),
    "stale": direct_handler,
    "epoch-one": direct_handler,
}


def credential(domain, route, payload, nonce):
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


def run(trace_output: Path | None) -> dict[str, object]:
    artifact = Path(__file__).resolve().parents[1]
    manifest_line = (artifact / "formal" / "SluiceDurableTraceManifest.json").read_bytes()
    with tempfile.TemporaryDirectory(prefix="sluice-durable-formal-") as temporary:
        database = Path(temporary) / "domain.sqlite3"
        domain = DurableSecureDomain.create(
            database,
            config=DomainConfig(
                domain_id="durable-formal-domain",
                protected_objects=frozenset(
                    {
                        "direct-object",
                        "effect-object",
                        "stale-object",
                        "epoch-one-object",
                    }
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
            manifest_line,
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
        emitter = DurableFormalEmitter(
            domain, binding, trace_id="durableAttestation_20260820"
        )

        stale_payload = {"stale": "private"}
        stale_credential = credential(
            domain, routes["stale"], stale_payload, "stale-nonce"
        )
        direct_payload = {"direct": "private"}
        emitter.attempt(
            routes["direct"],
            direct_payload,
            credential=credential(
                domain, routes["direct"], direct_payload, "direct-nonce"
            ),
        )
        effect_credential = credential(
            domain, routes["effect"], effect_payload, "effect-nonce"
        )
        emitter.attempt(
            routes["effect"],
            effect_payload,
            credential=effect_credential,
            capability=capability,
            redeemer_id="wrong-broker",
        )
        emitter.attempt(
            routes["effect"],
            effect_payload,
            credential=effect_credential,
            capability=capability,
            redeemer_id="broker",
        )
        emitter.continue_work()
        grant = ReauthorizationGrant.sign(
            authorizer_id="security-admin",
            signing_key=REAUTH_KEY,
            domain_context=domain.reauthorization_context,
            expected_epoch=domain.current_epoch,
            budget_increment_units=16,
            attempt_increment=2,
            nonce="grant-nonce",
            expires_at_lifetime_attempt=9,
        )
        emitter.reauthorize(grant)
        emitter.attempt(
            routes["stale"], stale_payload, credential=stale_credential
        )
        emitter.reauthorize(grant)
        emitter.stop()
        emitter.continue_work()

        if emitter.evidence_status != "exportable":
            raise RuntimeError("completed attestation trace is not exportable")
        trace = emitter.trace_bytes
        report = emitter.verify()
        records = [json.loads(line) for line in trace.splitlines()]
        private_values = [
            routes["direct"].to_wire(),
            routes["effect"].to_wire(),
            capability.to_wire(),
            "worker",
            "direct-nonce",
            "broker",
            "private",
        ]
        privacy_ok = all(value.encode() not in trace for value in private_values)
        connection = sqlite3.connect(database)
        try:
            row_counts = {
                "attempts": connection.execute(
                    "SELECT COUNT(*) FROM attempts"
                ).fetchone()[0],
                "audit_starts": connection.execute(
                    "SELECT COUNT(*) FROM audit_log WHERE phase='START'"
                ).fetchone()[0],
                "audit_finals": connection.execute(
                    "SELECT COUNT(*) FROM audit_log WHERE phase='FINAL'"
                ).fetchone()[0],
                "used_credentials": connection.execute(
                    "SELECT COUNT(*) FROM used_credentials"
                ).fetchone()[0],
                "used_grants": connection.execute(
                    "SELECT COUNT(*) FROM used_grants"
                ).fetchone()[0],
                "used_capabilities": connection.execute(
                    "SELECT COUNT(*) FROM capabilities WHERE consumed_attempt IS NOT NULL"
                ).fetchone()[0],
            }
        finally:
            connection.close()

    if trace_output is not None:
        trace_output.parent.mkdir(parents=True, exist_ok=True)
        trace_output.write_bytes(trace)
    return {
        "schema_version": "sluice.durable-formal-attestation.v2",
        "status": "pass",
        "evidence_status": emitter.evidence_status,
        "manifest_sha256": hashlib.sha256(manifest_line).hexdigest(),
        "trace_sha256": hashlib.sha256(trace).hexdigest(),
        "transition_count": report.transitions,
        "final_attempts": list(report.final_attempts),
        "final_visible_events": list(report.final_visible_events),
        "final_authorization_version": report.final_authorization_version,
        "actions": [record["action"] for record in records],
        "formal_claim_audit_deltas": sum(
            record["audit_start_delta"] for record in records
        ),
        "database_rows": row_counts,
        "integer_slot_only_trace": privacy_ok,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trace-output", type=Path)
    arguments = parser.parse_args()
    result = run(arguments.trace_output)
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
