"""Executable LangGraph API-path integration for the v2 reference monitor.

An untrusted email is classified through an ENDORSE gate, and this graph's
external alert path calls ``MediatedToolExecutor.execute()`` with a monitor-
issued one-time capability.  Tests exercise this provided path, including
forgery and replay rejection.  This is not a same-process sandbox: strong
complete mediation requires deploying the broker and tool credentials behind
an OS isolation boundary, as documented in ``SECURITY_PROOF.md``.
"""

from __future__ import annotations

import os
import sys
import threading
from typing import Optional, TypedDict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "sluice_v2"))
from actions import ActionTemplate, ArgConstraint, EffectClass  # noqa: E402
from monitor import Direction, MockBackend, Observation, Outcome, ReferenceMonitor, Symbol  # noqa: E402
from store import DurableStore  # noqa: E402
from langgraph.graph import StateGraph, END  # noqa: E402
from langgraph_tools import GateInvoker, MediatedToolExecutor  # noqa: E402

LABELS = ["benign", "suspicious", "escalate"]


def build_monitor(db_path: str) -> ReferenceMonitor:
    store = DurableStore(db_path)
    return ReferenceMonitor(
        store,
        MockBackend(),
        default_cap_bits=64.0,
        max_cardinality=8,
        trusted_planner_identities=frozenset({"triage_planner"}),
    )


def build_executor(monitor: ReferenceMonitor, sent_log: list) -> MediatedToolExecutor:
    def send_alert(to: str, subject: str) -> str:
        sent_log.append({"to": to, "subject": subject})
        return f"sent to {to}"

    return MediatedToolExecutor(monitor, {"alert": send_alert})


class TriageState(TypedDict, total=False):
    email_id: str
    email_content: str
    label: Optional[str]
    result: Optional[str]
    _observation: Optional[Observation]


def build_graph(monitor: ReferenceMonitor, executor: MediatedToolExecutor):
    # The trusted assembly code retains the planner-capable monitor. Ordinary
    # graph nodes receive only this invocation facade. Separate-process broker
    # deployment remains required against malicious Python reflection.
    invoker = GateInvoker(monitor)
    handle_lock = threading.RLock()
    handles = {}
    escalate_action = ActionTemplate(
        name="escalate_to_security",
        tool="alert",
        arg_constraints={
            "to": ArgConstraint(allowed_values=frozenset({"security-team@company.internal"})),
            "subject": ArgConstraint(max_length=200),
        },
        max_effect_class=EffectClass.REVERSIBLE,
    )
    symbols = [Symbol("benign"), Symbol("suspicious"), Symbol("escalate", escalate_action)]

    def classify_node(state: TriageState) -> dict:
        gate_id = f"classify-{state['email_id']}"
        with handle_lock:
            handle = handles.get(gate_id)
            if handle is None:
                handle = monitor.author_gate(
                    gate_id=gate_id, workflow_id="email-triage",
                    protected_object="inbox", direction=Direction.ENDORSE,
                    symbols=symbols, author_identity="triage_planner",
                    permitted_callers=frozenset({"triage_agent"}),
                    max_effect_class=EffectClass.REVERSIBLE,
                )
                handles[gate_id] = handle
        obs = invoker.invoke(
            handle,
            state["email_content"],
            caller_id="triage_agent",
            args={
                "to": "security-team@company.internal",
                "subject": f"triage:{state['email_id']}",
            },
        )
        if obs.outcome != Outcome.OK:
            return {"label": None, "result": f"blocked:{obs.outcome.value}"}
        return {"label": obs.value, "_observation": obs}

    def act_node(state: TriageState) -> dict:
        if state.get("result", "").startswith("blocked:"):
            return {}
        if state.get("label") != "escalate":
            return {"result": "noop"}
        obs = state["_observation"]
        try:
            result = executor.execute(obs)
        except Exception as exc:  # noqa: BLE001
            return {"result": f"execute_failed:{type(exc).__name__}"}
        return {"result": result}

    g = StateGraph(TriageState)
    g.add_node("classify", classify_node)
    g.add_node("act", act_node)
    g.set_entry_point("classify")
    g.add_edge("classify", "act")
    g.add_edge("act", END)
    return g.compile()
