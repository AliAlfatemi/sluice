"""Reproduction of the free_route_leak counterexample against
claim_and_reserve_gate()/invoke() as implemented (unchanged by the
Sec. 5.2 theorem-scope correction this counterexample motivated -- see
FORMAL_REVIEW.md and paper/main.tex Sec. 5). The code's behavior here is
exactly why the confidentiality theorem must require that successor
selection be a function of public history alone (I(S;G_i|H_i)=0): using
allowed_successor_gates with a secret-dependent choice of which declared
successor to invoke is not bounded by the theorem, and this script shows
concretely why.

Setup: predecessor gate P on object "victim" declares two successors,
A and B (fanout 2). P is claimed, leaving a remaining budget too small
to cover either A's or B's own (content + selection) charge. Two
independent runs, from byte-identical initial state, each invoke exactly
one of {A, B} chosen by a secret bit. Both hit BUDGET_EXHAUSTED with
zero added spend -- the question is whether the public audit transcript
still distinguishes which one was invoked.

Run from code/source/: python3 formal/counterexamples/free_route_leak_repro.py
"""
import os
import sys

ARTIFACT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ARTIFACT_ROOT not in sys.path:
    sys.path.insert(0, ARTIFACT_ROOT)

from sluice_v2.actions import EffectClass  # noqa: E402
from sluice_v2.monitor import (  # noqa: E402
    Direction,
    MockBackend,
    Outcome,
    ReferenceMonitor,
    Symbol,
)
from sluice_v2.store import DurableStore  # noqa: E402

PLANNER = "planner"
CALLER = "caller"


def run_branch(secret_bit: int, db_path: str):
    if os.path.exists(db_path):
        os.remove(db_path)
    store = DurableStore(db_path)
    monitor = ReferenceMonitor(
        store, MockBackend(), default_cap_bits=32.0, max_cardinality=8,
        trusted_planner_identities=frozenset({PLANNER}),
    )
    obj = "victim"
    # P: 2-symbol alphabet -> K+4=6 support -> ceil(1e6*log2(6)) content bits.
    # Fanout-2 successors add ceil(1e6*log2(2)) = 1_000_000 selection bits.
    # cap_bits is chosen so P succeeds but leaves too little for A or B.
    p_handle = monitor.author_gate(
        gate_id="P", workflow_id="wf", protected_object=obj,
        direction=Direction.RELEASE, symbols=[Symbol("x"), Symbol("y")],
        author_identity=PLANNER, permitted_callers=frozenset({CALLER}),
        allowed_successor_gates=frozenset({"A", "B"}),
        cap_bits=4.0,
    )
    p_obs = monitor.invoke(p_handle, "x", caller_id=CALLER)
    assert p_obs.outcome == Outcome.OK, p_obs.outcome

    a_handle = monitor.author_gate(
        gate_id="A", workflow_id="wf", protected_object=obj,
        direction=Direction.RELEASE, symbols=[Symbol("x"), Symbol("y")],
        author_identity=PLANNER, permitted_callers=frozenset({CALLER}),
        cap_bits=4.0,
    )
    b_handle = monitor.author_gate(
        gate_id="B", workflow_id="wf", protected_object=obj,
        direction=Direction.RELEASE, symbols=[Symbol("x"), Symbol("y")],
        author_identity=PLANNER, permitted_callers=frozenset({CALLER}),
        cap_bits=4.0,
    )

    chosen_handle = a_handle if secret_bit == 0 else b_handle
    chosen_id = "A" if secret_bit == 0 else "B"
    obs = monitor.invoke(chosen_handle, "x", caller_id=CALLER)

    audit = store.audit_log()
    store.close()
    return chosen_id, obs, audit


def main():
    results = {}
    for secret_bit in (0, 1):
        db = f"/tmp/free_route_leak_{secret_bit}.db"
        chosen_id, obs, audit = run_branch(secret_bit, db)
        results[secret_bit] = (chosen_id, obs, audit)
        print(f"\n=== secret_bit={secret_bit} (invoked {chosen_id}) ===")
        print(f"outcome={obs.outcome.value} charged_bits={obs.charged_bits} "
              f"gate_id_in_observation={obs.gate_id}")
        print("audit log tail:")
        for row in audit[-3:]:
            print(f"  seq={row['seq']} gate_id={row['gate_id']} event={row['event']} "
                  f"detail={row['detail']}")

    obs0, obs1 = results[0][1], results[1][1]
    audit0, audit1 = results[0][2], results[1][2]
    gate_id_0 = audit0[-1]["gate_id"]
    gate_id_1 = audit1[-1]["gate_id"]

    print("\n=== VERDICT ===")
    print(f"both outcomes BUDGET_EXHAUSTED: "
          f"{obs0.outcome == Outcome.BUDGET_EXHAUSTED == obs1.outcome}")
    print(f"both charged 0.0 bits: {obs0.charged_bits == 0.0 == obs1.charged_bits}")
    print(f"audit gate_id distinguishes secret_bit: "
          f"{gate_id_0 != gate_id_1} (branch0 logged {gate_id_0!r}, "
          f"branch1 logged {gate_id_1!r})")
    leak_confirmed = (
        obs0.outcome == Outcome.BUDGET_EXHAUSTED
        and obs1.outcome == Outcome.BUDGET_EXHAUSTED
        and obs0.charged_bits == 0.0
        and obs1.charged_bits == 0.0
        and gate_id_0 != gate_id_1
    )
    print(f"\nfree_route_leak counterexample confirmed: {leak_confirmed}")
    return 0 if leak_confirmed else 1


if __name__ == "__main__":
    raise SystemExit(main())
