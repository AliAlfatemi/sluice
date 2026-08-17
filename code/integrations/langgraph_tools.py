"""Tool broker for the provided LangGraph integration.

The broker redeems a monitor-issued one-time action capability and treats
registered tools as effect sinks.  It exposes neither tool return values nor
exception details.  Strong complete mediation still requires deploying this
broker in a separate process/account that alone holds tool credentials;
Python underscore attributes are not a sandbox against malicious same-process
code.
"""

from __future__ import annotations

import sys
import os
from typing import Callable, Dict, List, Mapping, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "sluice_v2"))
from monitor import Observation, Outcome, ReferenceMonitor  # noqa: E402


class MediationError(Exception):
    pass


class MediatedToolExecutor:
    def __init__(self, monitor: ReferenceMonitor, tools: Dict[str, Callable]):
        self._monitor = monitor
        self._tools = dict(tools)
        self.executed: List[dict] = []  # audit trail actually mutated by real calls only

    def execute(self, observation: Observation):
        if observation.outcome != Outcome.OK:
            raise MediationError(f"cannot execute: gate outcome was {observation.outcome.value!r}, not OK")
        if observation.action is None:
            raise MediationError("cannot execute: no ActionTemplate bound to the selected symbol")
        if observation.action.tool not in self._tools:
            # Do not burn a valid one-time capability for a deployment
            # configuration error that can be decided before redemption.
            raise MediationError("cannot execute: action tool is not registered")
        try:
            action, authorized_args = self._monitor.consume_action_capability(observation)
        except Exception as exc:
            raise MediationError("cannot execute: invalid or replayed action capability") from exc
        if action.tool not in self._tools:
            raise MediationError("cannot execute: action tool is not registered")
        try:
            # Tools in this integration are effect sinks.  Their return value
            # and exception text are never exposed to the graph: either could
            # otherwise become an unbounded channel outside the monitor's
            # typed observation alphabet.
            self._tools[action.tool](**authorized_args)
        except BaseException as exc:
            if isinstance(exc, (KeyboardInterrupt, SystemExit, GeneratorExit)):
                raise
            self.executed.append({
                "action": action.name,
                "tool": action.tool,
                "argument_names": sorted(authorized_args),
                "gate_id": observation.gate_id,
                "status": "failed",
            })
            raise MediationError("mediated tool execution failed") from None
        self.executed.append({
            "action": action.name, "tool": action.tool,
            "argument_names": sorted(authorized_args), "gate_id": observation.gate_id,
            "status": "completed",
        })
        return "completed"


class GateInvoker:
    """Narrow facade given to ordinary graph nodes.

    It intentionally provides only invocation and no access to monitor keys,
    storage, gate authorship, reauthorization, or capability issuance.
    """

    __slots__ = ("__invoke",)

    def __init__(self, monitor: ReferenceMonitor):
        self.__invoke = monitor.invoke

    def invoke(
        self,
        handle,
        untrusted_content: str,
        caller_id: str,
        args: Optional[Mapping] = None,
    ):
        return self.__invoke(handle, untrusted_content, caller_id, args)
