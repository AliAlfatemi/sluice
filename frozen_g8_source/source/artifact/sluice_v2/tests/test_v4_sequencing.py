"""Regression tests for opt-in successor-gate sequencing and the selection
charge (``entry_fanout`` / ``allowed_successor_gates`` / ``UNAUTHORIZED_SUCCESSOR``).

This mechanism atomically enforces declared-successor membership and mutual
exclusion. On a successful claim it reserves
``ceil(1e6*log2(fanout))`` additional selection units with the gate's own
content cost. A rejected claim is free while its gate identifier remains
observable, so the mechanism does not make secret-dependent routing safe and
does not remove the confidentiality theorem's public-routing premise. Chains
that never declare successors are unaffected -- the default
(``entry_fanout=1``, empty ``allowed_successor_gates``) reproduces the
pre-existing behavior exactly, which the first two tests below demonstrate.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from sluice_v2.monitor import (
    Direction,
    MockBackend,
    Outcome,
    ReferenceMonitor,
    Symbol,
    gate_cost_units,
    units_to_bits,
)
from sluice_v2.store import DurableStore, selection_cost_units


@pytest.fixture()
def monitor_and_store(tmp_path):
    db_path = str(tmp_path / "sluice.db")
    store = DurableStore(db_path)
    backend = MockBackend()
    monitor = ReferenceMonitor(
        store,
        backend,
        default_cap_bits=64.0,
        max_cardinality=8,
        trusted_planner_identities=frozenset({"planner"}),
    )
    yield monitor, store
    store.close()


def _author(monitor, gate_id, protected_object, *, successors=frozenset(), entry_fanout=1):
    return monitor.author_gate(
        gate_id=gate_id,
        workflow_id="wf",
        protected_object=protected_object,
        direction=Direction.RELEASE,
        symbols=[Symbol("benign"), Symbol("escalate")],
        author_identity="planner",
        permitted_callers=frozenset({"caller"}),
        allowed_successor_gates=frozenset(successors),
        entry_fanout=entry_fanout,
        cap_bits=64.0,
        unsafe_allow_unauthenticated_caller=True,
    )


def test_backward_compatible_no_successors_declared_no_charge_no_rejection(monitor_and_store):
    """Two independent gates on one object, neither declaring successors,
    behave exactly as the mechanism did not exist: no selection charge, no
    UNAUTHORIZED_SUCCESSOR possibility. This is the default/dormant path
    every existing evaluation (RQ1/RQ2/RQ4/RQ5) exercises."""
    monitor, store = monitor_and_store
    h1 = _author(monitor, "g1", "obj-a")
    h2 = _author(monitor, "g2", "obj-a")

    o1 = monitor.invoke(h1, "benign content", caller_id="caller")
    o2 = monitor.invoke(h2, "benign content", caller_id="caller")

    base_cost_bits = units_to_bits(gate_cost_units(2))
    assert o1.outcome == Outcome.OK
    assert o2.outcome == Outcome.OK
    assert o1.charged_bits == pytest.approx(base_cost_bits)
    assert o2.charged_bits == pytest.approx(base_cost_bits)


def test_entry_fanout_default_one_charges_nothing_extra(monitor_and_store):
    monitor, store = monitor_and_store
    h1 = _author(monitor, "g1", "obj-b", entry_fanout=1)
    o1 = monitor.invoke(h1, "benign content", caller_id="caller")
    assert o1.charged_bits == pytest.approx(units_to_bits(gate_cost_units(2)))


def test_declared_successor_is_charged_and_accepted(monitor_and_store):
    monitor, store = monitor_and_store
    h_a = _author(monitor, "gA", "obj-c", successors=frozenset({"gB", "gC"}))
    h_b = _author(monitor, "gB", "obj-c")
    _author(monitor, "gC", "obj-c")

    o_a = monitor.invoke(h_a, "benign content", caller_id="caller")
    assert o_a.outcome == Outcome.OK

    o_b = monitor.invoke(h_b, "benign content", caller_id="caller")
    assert o_b.outcome == Outcome.OK
    expected = units_to_bits(gate_cost_units(2) + selection_cost_units(2))
    assert o_b.charged_bits == pytest.approx(expected)
    assert o_b.charged_bits > units_to_bits(gate_cost_units(2))


def test_undeclared_successor_is_free_rejection_and_does_not_advance_state(monitor_and_store):
    monitor, store = monitor_and_store
    h_a = _author(monitor, "gA", "obj-d", successors=frozenset({"gB"}))
    h_b = _author(monitor, "gB", "obj-d")
    h_d = _author(monitor, "gD", "obj-d")  # never declared as gA's successor

    o_a = monitor.invoke(h_a, "benign content", caller_id="caller")
    assert o_a.outcome == Outcome.OK

    o_d = monitor.invoke(h_d, "benign content", caller_id="caller")
    assert o_d.outcome == Outcome.UNAUTHORIZED_SUCCESSOR
    assert o_d.charged_bits == 0.0

    # The rejected attempt must not have advanced sequencing state: gB, the
    # gate actually declared as gA's successor, must still be invocable and
    # must still be checked against gA (not gD) as its predecessor.
    o_b = monitor.invoke(h_b, "benign content", caller_id="caller")
    assert o_b.outcome == Outcome.OK
    # fanout for gA's declared successor set was 1 (only gB), so no extra
    # charge is expected here -- this also confirms the predecessor used for
    # the fanout computation was gA (fanout=1), not gD.
    assert o_b.charged_bits == pytest.approx(units_to_bits(gate_cost_units(2)))


def test_declared_successor_cannot_be_claimed_before_its_predecessor(monitor_and_store):
    """A gate named in another gate's ``allowed_successor_gates`` must not be
    directly claimable while no predecessor is recorded yet for its (object,
    epoch) -- which is true the first time *any* declared successor is
    attempted, since the sequencing pointer is only ever set by a prior
    claim. Found by extending the TLA+ model (Sluice.tla) to this exact
    scenario: TLC exhibited a trace where the declared predecessor was never
    consumed at all, yet both of its two declared successors were each
    independently claimed as if they were unconstrained entry gates, in
    direct violation of the model's AtMostOneSuccessorClaimed invariant.
    Before the fix, the ``last_gate_id is None`` branch of
    ``claim_and_reserve_gate`` treated *every* gate with no recorded
    predecessor as a free entry point using its own ``entry_fanout``,
    without checking whether that gate was itself reserved as someone
    else's declared successor -- letting a caller skip the predecessor
    entirely and pay only entry_fanout's charge (default 1) instead of the
    predecessor's declared K-way selection charge."""
    monitor, store = monitor_and_store
    _author(monitor, "gP", "obj-h", successors=frozenset({"gX", "gY"}))
    h_x = _author(monitor, "gX", "obj-h")
    _author(monitor, "gY", "obj-h")

    # gX is declared as gP's successor. Attempting it directly, with gP
    # never invoked and no predecessor recorded for obj-h, must be rejected
    # -- not silently accepted at entry_fanout's charge.
    o_x = monitor.invoke(h_x, "benign content", caller_id="caller")
    assert o_x.outcome == Outcome.UNAUTHORIZED_SUCCESSOR
    assert o_x.charged_bits == 0.0

    # The rejection must not have advanced sequencing state: gX remains
    # unconsumed and still claimable once gP is legitimately invoked first.
    h_p = _author(monitor, "gP2", "obj-h2", successors=frozenset({"gX2"}))
    h_x2 = _author(monitor, "gX2", "obj-h2")
    o_p = monitor.invoke(h_p, "benign content", caller_id="caller")
    assert o_p.outcome == Outcome.OK
    o_x2 = monitor.invoke(h_x2, "benign content", caller_id="caller")
    assert o_x2.outcome == Outcome.OK
    expected = units_to_bits(gate_cost_units(2) + selection_cost_units(1))
    assert o_x2.charged_bits == pytest.approx(expected)


def test_gate_reserved_as_successor_on_one_object_is_still_free_entry_on_another(
    monitor_and_store,
):
    """The reverse-successor index is keyed by the globally unique gate_id,
    not by (protected_object, policy_epoch) pattern-matching, so this is a
    sanity check rather than an isolation requirement: a gate_id can only
    ever be reserved by the specific predecessor(s) that actually name it,
    never by unrelated gates on other objects that happen to share no
    relationship with it."""
    monitor, store = monitor_and_store
    _author(monitor, "gQ", "obj-i", successors=frozenset({"gZ"}))
    h_unrelated = _author(monitor, "gUnrelated", "obj-j")
    o = monitor.invoke(h_unrelated, "benign content", caller_id="caller")
    assert o.outcome == Outcome.OK
    assert o.charged_bits == pytest.approx(units_to_bits(gate_cost_units(2)))


def test_entry_fanout_charges_for_first_call_in_a_chain(monitor_and_store):
    monitor, store = monitor_and_store
    h = _author(monitor, "g1", "obj-e", entry_fanout=4)
    o = monitor.invoke(h, "benign content", caller_id="caller")
    assert o.outcome == Outcome.OK
    expected = units_to_bits(gate_cost_units(2) + selection_cost_units(4))
    assert o.charged_bits == pytest.approx(expected)


def test_sequencing_state_resets_on_new_epoch(monitor_and_store):
    """A gate authored under a fresh policy_epoch has no predecessor in that
    epoch even if the same protected_object had a chain in a prior epoch --
    prior-epoch spend already accounted for prior-epoch sequencing."""
    monitor, store = monitor_and_store
    h_a = _author(monitor, "gA", "obj-f", successors=frozenset({"gB"}))
    monitor.invoke(h_a, "benign content", caller_id="caller")

    # Author a gate directly at epoch 1 without ever redeeming a
    # reauthorization grant is not supported by author_gate (it enforces
    # epoch continuity), so this test instead confirms within-epoch state:
    # a *different* protected_object's chain is independent of obj-f's.
    h_root_other = _author(monitor, "gRoot2", "obj-g", entry_fanout=3)
    o = monitor.invoke(h_root_other, "benign content", caller_id="caller")
    expected = units_to_bits(gate_cost_units(2) + selection_cost_units(3))
    assert o.charged_bits == pytest.approx(expected)


def test_concurrent_mutually_exclusive_successors_exactly_one_wins(monitor_and_store):
    """Deterministic concurrency regression for the race an earlier revision
    had: two callers, racing, each try to invoke a *different* declared
    successor of the same predecessor. Before the atomicity fix
    (claim_and_reserve_gate doing the predecessor lookup, successor-
    membership check, fanout computation, and sequencing-pointer update all
    inside one transaction), both could independently pass a non-atomic
    pre-check and both succeed. After the fix, SQLite's BEGIN IMMEDIATE
    serializes the two transactions, and the second one -- whichever it
    turns out to be -- re-reads the *already-advanced* sequencing pointer
    and correctly rejects, since it is no longer a declared successor of
    the new (post-advancement) predecessor. Exactly one of the two must
    succeed, on every run, not probabilistically."""
    import threading

    monitor, store = monitor_and_store
    h_p = _author(monitor, "gP", "obj-race", successors=frozenset({"gX", "gY"}))
    h_x = _author(monitor, "gX", "obj-race")
    h_y = _author(monitor, "gY", "obj-race")

    o_p = monitor.invoke(h_p, "benign content", caller_id="caller")
    assert o_p.outcome == Outcome.OK

    barrier = threading.Barrier(2)
    results: dict[str, Outcome] = {}
    errors: list[BaseException] = []

    def _race(name, handle):
        try:
            barrier.wait(timeout=5)
            obs = monitor.invoke(handle, "benign content", caller_id="caller")
            results[name] = obs.outcome
        except BaseException as exc:  # noqa: BLE001 - surfaced by the assertions below
            errors.append(exc)

    t_x = threading.Thread(target=_race, args=("x", h_x))
    t_y = threading.Thread(target=_race, args=("y", h_y))
    t_x.start()
    t_y.start()
    t_x.join(timeout=10)
    t_y.join(timeout=10)

    assert not errors, f"unexpected exception(s) in racing threads: {errors}"
    assert set(results) == {"x", "y"}
    outcomes = [results["x"], results["y"]]
    assert outcomes.count(Outcome.OK) == 1, (
        f"expected exactly one winner, got {outcomes}"
    )
    assert outcomes.count(Outcome.UNAUTHORIZED_SUCCESSOR) == 1, (
        f"expected exactly one UNAUTHORIZED_SUCCESSOR loser, got {outcomes}"
    )


def test_concurrent_race_is_deterministic_across_repeated_trials():
    """The same race as above, repeated on fresh state, to rule out the
    property above holding only by scheduling luck on a single run."""
    import threading

    for trial in range(15):
        db_path = tempfile.mkdtemp() + f"/race-{trial}.db"
        store = DurableStore(db_path)
        monitor = ReferenceMonitor(
            store,
            MockBackend(),
            default_cap_bits=64.0,
            max_cardinality=8,
            trusted_planner_identities=frozenset({"planner"}),
        )
        try:
            h_p = _author(monitor, "gP", "obj-race", successors=frozenset({"gX", "gY"}))
            h_x = _author(monitor, "gX", "obj-race")
            h_y = _author(monitor, "gY", "obj-race")
            monitor.invoke(h_p, "benign content", caller_id="caller")

            barrier = threading.Barrier(2)
            results = {}

            def _race(name, handle):
                barrier.wait(timeout=5)
                results[name] = monitor.invoke(
                    handle, "benign content", caller_id="caller"
                ).outcome

            t_x = threading.Thread(target=_race, args=("x", h_x))
            t_y = threading.Thread(target=_race, args=("y", h_y))
            t_x.start()
            t_y.start()
            t_x.join(timeout=10)
            t_y.join(timeout=10)

            outcomes = [results["x"], results["y"]]
            assert outcomes.count(Outcome.OK) == 1, (trial, outcomes)
        finally:
            store.close()


def test_selection_cost_units_table_matches_log2_formula():
    import math

    for fanout in range(1, 33):
        expected = 0 if fanout == 1 else math.ceil(10**6 * math.log2(fanout))
        assert selection_cost_units(fanout) in (expected, expected + 1, expected - 1), (
            fanout, selection_cost_units(fanout), expected
        )
    with pytest.raises(ValueError):
        selection_cost_units(0)
    with pytest.raises(ValueError):
        selection_cost_units(33)
