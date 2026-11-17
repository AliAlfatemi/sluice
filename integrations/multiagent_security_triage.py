"""Three-agent security-triage workflow (\\S\\ref{sec:multiagent}).

Not a LangGraph node relabeling: TriageAgent, ResearchAgent, and
ExecutorAgent are three distinct authenticated identities, each holding its
own HMAC key registered with the monitor. Crossing between them is
enforced by the monitor's own cryptographic checks, not by which Python
function a caller happens to invoke:

1. TriageAgent classifies an incoming email (benign / suspicious /
   escalate) through an authenticated RELEASE gate.
2. On escalate, TriageAgent -- the only agent statically permitted on the
   investigation gate -- issues a single-hop DelegationGrant handing
   *this one gate* to ResearchAgent. ResearchAgent redeems it with its own
   credential and investigates (substantiated / unsubstantiated). The
   investigation gate is declared as the classification gate's sole
   successor, so the monitor enforces that handoff atomically. Its fanout is
   one, so it adds no selection units; this sequencing relation does not
   relax the separate public-routing premise.
3. If substantiated, ResearchAgent -- who *is* statically permitted on the
   action gate -- invokes it directly, but binds the resulting action
   capability to ExecutorAgent via redeemer_agent_id: ResearchAgent decides
   an action is warranted but never itself holds the tool credentials to
   perform it.
4. ExecutorAgent redeems the capability with its own credential and
   performs the mediated effect.

Each handoff (Triage->Research via delegation, Research->Executor via a
redeemer-bound capability) fails closed if the wrong agent, or an agent
without proof of its own key, attempts it -- see
test_multiagent_security_triage.py for the mechanized attack suite this
enables (compromised-agent lateral movement, cross-agent injection,
unauthorized delegation skip, stale delegation reuse, capability
interception by an upstream agent trying to shortcut the handoff).

Not a same-process security boundary: strong complete mediation still
requires the OS-level process/credential isolation this paper's threat
model already states (\\S\\ref{sec:tcb}). What this demonstrates is that
the *monitor's* enforcement of who may claim which gate and who may redeem
which capability depends on cryptographic proof of agent identity, not on
which Python function happened to call invoke().
"""

from __future__ import annotations

import os
import secrets
import sys
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from sluice_v2.actions import ActionTemplate, ArgConstraint, EffectClass  # noqa: E402
from sluice_v2.monitor import (  # noqa: E402
    Direction,
    MockBackend,
    Outcome,
    ReferenceMonitor,
    Symbol,
)
from sluice_v2.store import DurableStore  # noqa: E402

TRIAGE_PLANNER = "triage_planner"
TRIAGE_AGENT = "triage_agent"
RESEARCH_AGENT = "research_agent"
EXECUTOR_AGENT = "executor_agent"

ALERT_ACTION = ActionTemplate(
    name="escalate_to_security",
    tool="alert",
    arg_constraints={
        "to": ArgConstraint(allowed_values=frozenset({"security-team@company.internal"})),
        "subject": ArgConstraint(max_length=200),
    },
    max_effect_class=EffectClass.REVERSIBLE,
)


def build_agent_keys() -> Dict[str, bytes]:
    return {
        TRIAGE_AGENT: secrets.token_bytes(32),
        RESEARCH_AGENT: secrets.token_bytes(32),
        EXECUTOR_AGENT: secrets.token_bytes(32),
    }


def build_monitor(db_path: str, agent_keys: Dict[str, bytes], backend=None) -> ReferenceMonitor:
    """``backend=None`` keeps this the deterministic, same-process
    controlled mechanism test (MockBackend) every existing test depends
    on. Passing a real backend (e.g. real_llm_multiagent_workflow.py's
    VLLMBackend) reuses the same gate/identity/delegation wiring against
    genuine model inference instead."""
    store = DurableStore(db_path)
    return ReferenceMonitor(
        store,
        backend if backend is not None else MockBackend(),
        default_cap_bits=64.0,
        max_cardinality=8,
        trusted_planner_identities=frozenset({TRIAGE_PLANNER}),
        agent_keys=agent_keys,
    )


@dataclass
class WorkflowTrace:
    steps: List[str] = field(default_factory=list)
    label: Optional[str] = None
    finding: Optional[str] = None
    action_result: Optional[str] = None
    blocked_at: Optional[str] = None
    blocked_outcome: Optional[Outcome] = None

    def log(self, step: str) -> None:
        self.steps.append(step)


def run_workflow(
    monitor: ReferenceMonitor,
    agent_keys: Dict[str, bytes],
    email_id: str,
    email_content: str,
    send_alert: Callable[[str, str], str],
) -> WorkflowTrace:
    """The golden (non-adversarial) path: every credential is genuine and
    every agent acts only within its own scope. Attack-suite tests reuse
    the same three authored gates but substitute a forged credential,
    missing delegation, or stolen capability at exactly one step."""
    trace = WorkflowTrace()
    protected_object = f"inbox-{email_id}"

    classify_gate_id = f"classify-{email_id}"
    investigate_gate_id = f"investigate-{email_id}"
    act_gate_id = f"act-{email_id}"

    classify_handle = monitor.author_gate(
        gate_id=classify_gate_id,
        workflow_id="security-triage",
        protected_object=protected_object,
        direction=Direction.RELEASE,
        symbols=[Symbol("benign"), Symbol("suspicious"), Symbol("escalate")],
        author_identity=TRIAGE_PLANNER,
        permitted_callers=frozenset({TRIAGE_AGENT}),
        allowed_successor_gates=frozenset({investigate_gate_id}),
        cap_bits=64.0,
        require_authenticated_caller=True,
    )
    triage_cred = monitor.issue_call_credential(
        TRIAGE_AGENT, agent_keys[TRIAGE_AGENT], classify_gate_id,
        "security-triage", 0, email_content,
    )
    classify_obs = monitor.invoke(
        classify_handle, email_content, caller_id=TRIAGE_AGENT, credential=triage_cred
    )
    trace.log(f"classify:{classify_obs.outcome.value}")
    if classify_obs.outcome != Outcome.OK:
        trace.blocked_at = "classify"
        trace.blocked_outcome = classify_obs.outcome
        return trace
    trace.label = classify_obs.value
    if classify_obs.value != "escalate":
        return trace

    investigate_handle = monitor.author_gate(
        gate_id=investigate_gate_id,
        workflow_id="security-triage",
        protected_object=protected_object,
        direction=Direction.RELEASE,
        symbols=[Symbol("substantiated"), Symbol("unsubstantiated")],
        author_identity=TRIAGE_PLANNER,
        permitted_callers=frozenset({TRIAGE_AGENT}),
        cap_bits=64.0,
        require_authenticated_caller=True,
    )
    delegation = monitor.issue_delegation(
        TRIAGE_AGENT, agent_keys[TRIAGE_AGENT], RESEARCH_AGENT, investigate_gate_id
    )
    investigate_content = "threat-intel lookup: " + email_content
    research_cred = monitor.issue_call_credential(
        RESEARCH_AGENT, agent_keys[RESEARCH_AGENT], investigate_gate_id,
        "security-triage", 0, investigate_content,
    )
    investigate_obs = monitor.invoke(
        investigate_handle,
        investigate_content,
        caller_id=RESEARCH_AGENT,
        credential=research_cred,
        delegation=delegation,
    )
    trace.log(f"investigate:{investigate_obs.outcome.value}")
    if investigate_obs.outcome != Outcome.OK:
        trace.blocked_at = "investigate"
        trace.blocked_outcome = investigate_obs.outcome
        return trace
    trace.finding = investigate_obs.value
    if investigate_obs.value != "substantiated":
        return trace

    act_handle = monitor.author_gate(
        gate_id=act_gate_id,
        workflow_id="security-triage",
        protected_object=protected_object,
        direction=Direction.ENDORSE,
        symbols=[Symbol("send", ALERT_ACTION)],
        author_identity=TRIAGE_PLANNER,
        permitted_callers=frozenset({RESEARCH_AGENT}),
        max_effect_class=EffectClass.REVERSIBLE,
        cap_bits=64.0,
        require_authenticated_caller=True,
    )
    act_args = {"to": "security-team@company.internal", "subject": f"triage:{email_id}"}
    act_cred = monitor.issue_call_credential(
        RESEARCH_AGENT, agent_keys[RESEARCH_AGENT], act_gate_id,
        "security-triage", 0, "send", args=act_args,
    )
    act_obs = monitor.invoke(
        act_handle,
        "send",
        caller_id=RESEARCH_AGENT,
        args=act_args,
        credential=act_cred,
        redeemer_agent_id=EXECUTOR_AGENT,
    )
    trace.log(f"act:{act_obs.outcome.value}")
    if act_obs.outcome != Outcome.OK:
        trace.blocked_at = "act"
        trace.blocked_outcome = act_obs.outcome
        return trace

    executor_cred = monitor.issue_call_credential(
        EXECUTOR_AGENT, agent_keys[EXECUTOR_AGENT], act_gate_id,
        "", act_obs.policy_epoch, act_obs.capability_id, args=dict(act_obs.authorized_args),
    )
    action, args = monitor.consume_action_capability(act_obs, credential=executor_cred)
    trace.action_result = send_alert(args["to"], args["subject"])
    trace.log("execute:ok")
    return trace
