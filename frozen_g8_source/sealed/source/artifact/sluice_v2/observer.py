"""Finite, versioned public transcript schema for secure Sluice domains.

This module deliberately contains no monitor identifiers, diagnostic strings,
or extensible metadata.  A :class:`TranscriptEvent` is the complete public
projection of one charged domain slot.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping


TRANSCRIPT_SCHEMA_VERSION = 1
MAX_PUBLIC_INTEGER = (1 << 63) - 1


class TranscriptSchemaError(ValueError):
    """Raised when a public event is not exactly the supported wire schema."""


class EventKind(str, Enum):
    """Closed alphabet of public event classes."""

    ATTEMPT = "attempt"
    CONTINUE = "continue"
    STOP = "stop"
    PADDING = "padding"
    REAUTHORIZE = "reauthorize"
    DOMAIN_CLOSED = "domain_closed"


class OutcomeCode(str, Enum):
    """Closed alphabet of public outcomes.

    Denials intentionally coarsen private implementation failures.  In
    particular, ``INTERNAL_DENIED`` carries no exception class or text.
    """

    RELEASED = "released"
    AUTH_DENIED = "auth_denied"
    ROUTE_DENIED = "route_denied"
    CAPABILITY_DENIED = "capability_denied"
    OUTPUT_DENIED = "output_denied"
    INTERNAL_DENIED = "internal_denied"
    CONTINUED = "continued"
    STOPPED = "stopped"
    PADDED = "padded"
    REAUTHORIZED = "reauthorized"
    REAUTH_DENIED = "reauth_denied"
    DOMAIN_CLOSED = "domain_closed"


_WIRE_FIELDS = frozenset(
    {
        "schema_version",
        "sequence",
        "attempt",
        "kind",
        "outcome",
        "value_code",
        "charge_units",
        "terminal",
    }
)

_OUTCOMES_BY_KIND = {
    EventKind.ATTEMPT: frozenset(
        {
            OutcomeCode.RELEASED,
            OutcomeCode.AUTH_DENIED,
            OutcomeCode.ROUTE_DENIED,
            OutcomeCode.CAPABILITY_DENIED,
            OutcomeCode.OUTPUT_DENIED,
            OutcomeCode.INTERNAL_DENIED,
        }
    ),
    EventKind.CONTINUE: frozenset({OutcomeCode.CONTINUED}),
    EventKind.STOP: frozenset({OutcomeCode.STOPPED}),
    EventKind.PADDING: frozenset({OutcomeCode.PADDED}),
    EventKind.REAUTHORIZE: frozenset(
        {OutcomeCode.REAUTHORIZED, OutcomeCode.REAUTH_DENIED}
    ),
    EventKind.DOMAIN_CLOSED: frozenset({OutcomeCode.DOMAIN_CLOSED}),
}


def _is_int(value: object) -> bool:
    """Return true only for an actual integer, never for ``bool``."""

    return type(value) is int


def _bounded_int(value: object, *, minimum: int, name: str) -> bool:
    """Accept only JSON-portable signed-64-bit public integers."""

    return _is_int(value) and minimum <= value <= MAX_PUBLIC_INTEGER


@dataclass(frozen=True, slots=True)
class TranscriptEvent:
    """One element of the complete, finite public transcript."""

    schema_version: int
    sequence: int
    attempt: int
    kind: EventKind
    outcome: OutcomeCode
    value_code: int | None
    charge_units: int
    terminal: bool

    def __post_init__(self) -> None:
        if not _is_int(self.schema_version) or (
            self.schema_version != TRANSCRIPT_SCHEMA_VERSION
        ):
            raise TranscriptSchemaError("unsupported transcript schema version")
        if not _bounded_int(self.sequence, minimum=1, name="sequence"):
            raise TranscriptSchemaError("sequence must be a positive integer")
        if not _bounded_int(self.attempt, minimum=1, name="attempt"):
            raise TranscriptSchemaError("attempt must be a positive integer")
        if type(self.kind) is not EventKind:
            raise TranscriptSchemaError("kind must be an EventKind")
        if type(self.outcome) is not OutcomeCode:
            raise TranscriptSchemaError("outcome must be an OutcomeCode")
        if self.value_code is not None and (
            not _bounded_int(self.value_code, minimum=0, name="value_code")
        ):
            raise TranscriptSchemaError(
                "value_code must be a nonnegative integer or null"
            )
        if not _bounded_int(self.charge_units, minimum=0, name="charge_units"):
            raise TranscriptSchemaError("charge_units must be a nonnegative integer")
        if type(self.terminal) is not bool:
            raise TranscriptSchemaError("terminal must be a boolean")
        if self.outcome not in _OUTCOMES_BY_KIND[self.kind]:
            raise TranscriptSchemaError("event kind and outcome are inconsistent")
        if self.outcome is OutcomeCode.RELEASED:
            if self.value_code is None:
                raise TranscriptSchemaError("released events require a value code")
        elif self.value_code is not None:
            raise TranscriptSchemaError("only released events may carry a value code")
        if self.kind is EventKind.DOMAIN_CLOSED:
            if self.charge_units != 0 or not self.terminal:
                raise TranscriptSchemaError(
                    "domain-closed replies must be uncharged and terminal"
                )
        elif self.charge_units == 0:
            raise TranscriptSchemaError("charged transcript events require a charge")

    def to_wire(self) -> dict[str, object]:
        """Return the exact JSON-compatible public schema."""

        return {
            "schema_version": self.schema_version,
            "sequence": self.sequence,
            "attempt": self.attempt,
            "kind": self.kind.value,
            "outcome": self.outcome.value,
            "value_code": self.value_code,
            "charge_units": self.charge_units,
            "terminal": self.terminal,
        }

    @classmethod
    def from_wire(cls, wire: Mapping[str, Any]) -> "TranscriptEvent":
        """Parse an event, rejecting every schema deviation.

        Exact key and concrete-type checks are intentional.  Python's
        ``bool`` is an ``int`` subclass and is therefore checked explicitly.
        """

        if type(wire) is not dict:
            raise TranscriptSchemaError("wire event must be a plain object")
        if set(wire) != _WIRE_FIELDS:
            raise TranscriptSchemaError("wire event fields do not match schema")
        if wire["schema_version"] != TRANSCRIPT_SCHEMA_VERSION or not _is_int(
            wire["schema_version"]
        ):
            raise TranscriptSchemaError("unsupported transcript schema version")
        if not _bounded_int(wire["sequence"], minimum=1, name="sequence"):
            raise TranscriptSchemaError("sequence must be a positive integer")
        if not _bounded_int(wire["attempt"], minimum=1, name="attempt"):
            raise TranscriptSchemaError("attempt must be a positive integer")
        if type(wire["kind"]) is not str:
            raise TranscriptSchemaError("kind must be a string enum code")
        if type(wire["outcome"]) is not str:
            raise TranscriptSchemaError("outcome must be a string enum code")
        value_code = wire["value_code"]
        if value_code is not None and (
            not _bounded_int(value_code, minimum=0, name="value_code")
        ):
            raise TranscriptSchemaError(
                "value_code must be a nonnegative integer or null"
            )
        if not _bounded_int(
            wire["charge_units"], minimum=0, name="charge_units"
        ):
            raise TranscriptSchemaError("charge_units must be a nonnegative integer")
        if type(wire["terminal"]) is not bool:
            raise TranscriptSchemaError("terminal must be a boolean")
        try:
            kind = EventKind(wire["kind"])
            outcome = OutcomeCode(wire["outcome"])
        except ValueError as exc:
            raise TranscriptSchemaError("unknown finite event code") from exc
        return cls(
            schema_version=wire["schema_version"],
            sequence=wire["sequence"],
            attempt=wire["attempt"],
            kind=kind,
            outcome=outcome,
            value_code=value_code,
            charge_units=wire["charge_units"],
            terminal=wire["terminal"],
        )
