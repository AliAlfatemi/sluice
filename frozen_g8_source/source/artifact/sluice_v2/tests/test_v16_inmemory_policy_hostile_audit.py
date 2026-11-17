"""Hostile checks for the in-memory prototype's public policy envelope.

These tests deliberately exercise only :mod:`sluice_v2.secure`.  That module
is an in-memory, single-process/thread-synchronised prototype; passing this
suite is not evidence of crash durability, process isolation, OS mediation,
or the G2 end-to-end boundary.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from sluice_v2.observer import OutcomeCode
from sluice_v2.secure import (
    DomainConfig,
    ObserverSpec,
    ReauthorizationGrant,
    ReauthorizationPolicy,
    RouteCodebook,
    SecureDomain,
)


CALLER_KEY = b"inmemory-caller-key-material-32b"
REAUTH_KEY = b"inmemory-reauth-key-material-32b"


def _codebook(
    name: str = "release",
    values: frozenset[int] = frozenset({0, 1}),
    *,
    requires_capability: bool = False,
) -> RouteCodebook:
    return RouteCodebook(
        name=name,
        public_values=values,
        requires_capability=requires_capability,
    )


def _spec(*codebooks: RouteCodebook) -> ObserverSpec:
    if not codebooks:
        codebooks = (_codebook(),)
    permitted = frozenset(
        value for codebook in codebooks for value in codebook.public_values
    )
    return ObserverSpec(
        permitted_value_codes=permitted,
        observer_spec_id="pre-secret-observer-spec-v1",
        route_codebooks=tuple(codebooks),
    )


def _domain(
    spec: ObserverSpec,
    *,
    policy: ReauthorizationPolicy | None = None,
    horizon: int = 5,
    charge: int = 4,
    budget: int | None = None,
) -> SecureDomain:
    if budget is None:
        budget = horizon * charge
    return SecureDomain(
        DomainConfig(
            domain_id="inmemory-hostile-domain",
            protected_objects=frozenset({"protected-a", "protected-b"}),
            lifetime_budget_units=budget,
            attempt_horizon=horizon,
            event_charge_units=charge,
        ),
        observer_spec=spec,
        reauthorization_policy=policy,
        agent_keys={"worker": CALLER_KEY},
        reauthorization_keys={"admin": REAUTH_KEY},
    )


def _register(
    domain: SecureDomain,
    codebook: RouteCodebook,
    *,
    protected_object: str = "protected-a",
):
    return domain.register_route(
        name=codebook.name,
        protected_object=protected_object,
        handler=lambda _payload: min(codebook.public_values),
        public_values=codebook.public_values,
        requires_capability=codebook.requires_capability,
    )


def _grant(
    domain: SecureDomain,
    *,
    budget_increment: int,
    attempt_increment: int,
    nonce: str,
) -> ReauthorizationGrant:
    return ReauthorizationGrant.sign(
        authorizer_id="admin",
        signing_key=REAUTH_KEY,
        domain_context=domain.reauthorization_context,
        budget_increment_units=budget_increment,
        attempt_increment=attempt_increment,
        nonce=nonce,
    )


def test_observer_spec_is_required_before_any_handler_attachment():
    config = DomainConfig(
        domain_id="missing-observer-spec",
        protected_objects=frozenset({"protected-a"}),
        lifetime_budget_units=4,
        attempt_horizon=1,
        event_charge_units=4,
    )
    with pytest.raises(TypeError, match="observer_spec"):
        SecureDomain(
            config,
            observer_spec=None,  # type: ignore[arg-type]
            agent_keys={"worker": CALLER_KEY},
            reauthorization_keys={"admin": REAUTH_KEY},
        )


def test_route_attachment_must_exactly_match_precommitted_codebook():
    committed = _codebook("release", frozenset({0, 1}))
    domain = _domain(_spec(committed))

    with pytest.raises(ValueError, match="precommitted|codebook|exact"):
        domain.register_route(
            name="release",
            protected_object="protected-a",
            handler=lambda _payload: 0,
            public_values=frozenset({0}),
            requires_capability=False,
        )
    with pytest.raises(ValueError, match="precommitted|codebook|exact"):
        domain.register_route(
            name="secret-selected-route",
            protected_object="protected-a",
            handler=lambda _payload: 0,
            public_values=frozenset({0, 1}),
            requires_capability=False,
        )
    with pytest.raises(ValueError, match="precommitted|codebook|exact"):
        domain.register_route(
            name="release",
            protected_object="protected-a",
            handler=lambda _payload: 0,
            public_values=frozenset({0, 1}),
            requires_capability=True,
        )

    # Failed, secret-selected bindings did not reserve or alter the route.
    _register(domain, committed)
    domain.seal()


def test_seal_rejects_incomplete_precommitted_route_set():
    left = _codebook("left", frozenset({0}))
    right = _codebook("right", frozenset({1}))
    domain = _domain(_spec(left, right), charge=4)
    _register(domain, left)

    with pytest.raises(ValueError, match="precommitted|codebook|registered|complete"):
        domain.seal()

    _register(domain, right, protected_object="protected-b")
    domain.seal()


@pytest.mark.parametrize(
    "values,expected_exception",
    [
        ({0, 1}, TypeError),
        (frozenset(), TypeError),
        (frozenset({True}), TypeError),
        (frozenset({-1}), TypeError),
        (frozenset({1.0}), TypeError),
    ],
)
def test_route_codebook_rejects_ambiguous_or_mutable_alphabets(
    values, expected_exception
):
    with pytest.raises(expected_exception):
        RouteCodebook(name="route", public_values=values)


def test_observer_spec_is_canonical_immutable_and_order_independent():
    alpha = _codebook("alpha", frozenset({0, 2}))
    beta = _codebook("beta", frozenset({1}))
    forward = _spec(alpha, beta)
    reverse = _spec(beta, alpha)

    assert forward.route_codebooks == (alpha, beta)
    assert reverse.route_codebooks == (alpha, beta)
    assert forward.codebook_sha256 == reverse.codebook_sha256
    assert len(forward.codebook_sha256) == 64
    with pytest.raises((FrozenInstanceError, AttributeError)):
        forward.route_codebooks = (alpha,)  # type: ignore[misc]
    with pytest.raises((FrozenInstanceError, AttributeError)):
        alpha.public_values = frozenset({999})  # type: ignore[misc]


def test_observer_spec_rejects_duplicate_routes_and_out_of_spec_values():
    duplicate_a = _codebook("same", frozenset({0}))
    duplicate_b = _codebook("same", frozenset({1}))
    with pytest.raises(ValueError, match="unique|duplicate"):
        ObserverSpec(
            permitted_value_codes=frozenset({0, 1}),
            observer_spec_id="duplicate-spec",
            route_codebooks=(duplicate_a, duplicate_b),
        )
    with pytest.raises(ValueError, match="outside|ObserverSpec|permitted"):
        ObserverSpec(
            permitted_value_codes=frozenset({0}),
            observer_spec_id="narrow-spec",
            route_codebooks=(_codebook("wide", frozenset({0, 1})),),
        )


@pytest.mark.parametrize(
    "budget_increment,attempt_increment",
    [
        (True, 1),
        (1, True),
        (0, 1),
        (1, 0),
        (-1, 1),
        (1, -1),
    ],
)
def test_reauthorization_policy_requires_exact_positive_integers(
    budget_increment, attempt_increment
):
    with pytest.raises((TypeError, ValueError)):
        ReauthorizationPolicy(
            budget_increment_units=budget_increment,
            attempt_increment=attempt_increment,
        )


def test_disabled_reauthorization_is_the_default_and_is_still_charged():
    codebook = _codebook()
    domain = _domain(_spec(codebook), horizon=3, budget=12)
    _register(domain, codebook)
    domain.seal()
    domain.activate()
    grant = _grant(
        domain,
        budget_increment=4,
        attempt_increment=1,
        nonce="cryptographically-valid-but-disabled",
    )

    event = domain.reauthorize(grant)

    assert event.outcome is OutcomeCode.REAUTH_DENIED
    assert event.charge_units == 4
    assert domain.attempts_used == 1
    assert domain.lifetime_spent_units == 4
    assert domain.lifetime_budget_units == 12
    assert domain.attempt_horizon == 3
    assert domain.reauthorization_policy is None


def test_only_the_precommitted_reauthorization_shape_can_succeed():
    codebook = _codebook()
    policy = ReauthorizationPolicy(
        budget_increment_units=8,
        attempt_increment=2,
    )
    domain = _domain(_spec(codebook), policy=policy, horizon=5, budget=20)
    _register(domain, codebook)
    domain.seal()
    domain.activate()

    wrong_shape = domain.reauthorize(
        _grant(
            domain,
            budget_increment=12,
            attempt_increment=3,
            nonce="wrong-shape",
        )
    )
    exact_grant = _grant(
        domain,
        budget_increment=8,
        attempt_increment=2,
        nonce="exact-shape",
    )
    accepted = domain.reauthorize(exact_grant)
    replayed = domain.reauthorize(exact_grant)

    assert wrong_shape.outcome is OutcomeCode.REAUTH_DENIED
    assert accepted.outcome is OutcomeCode.REAUTHORIZED
    assert replayed.outcome is OutcomeCode.REAUTH_DENIED
    assert domain.reauthorization_policy == policy
    assert domain.lifetime_budget_units == 28
    assert domain.attempt_horizon == 7
    assert domain.attempts_used == 3
    assert domain.lifetime_spent_units == 12


def test_underfunded_or_initially_impossible_fixed_policy_is_rejected_early():
    spec = _spec()
    with pytest.raises(ValueError, match="policy|fund|attempt"):
        _domain(
            spec,
            policy=ReauthorizationPolicy(
                budget_increment_units=3,
                attempt_increment=1,
            ),
            charge=4,
        )
    with pytest.raises(ValueError, match="policy|padding|horizon|bound"):
        _domain(
            spec,
            policy=ReauthorizationPolicy(
                budget_increment_units=4,
                attempt_increment=1,
            ),
            horizon=1_000_000,
            charge=4,
            budget=4_000_000,
        )
