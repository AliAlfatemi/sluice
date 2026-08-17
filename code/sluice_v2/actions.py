"""Action templates: the fix for "a one-bit decision can still trigger a
catastrophic operation." A gate symbol alone is not a safety property --
this module binds each symbol to a prevalidated, capability-scoped
ActionTemplate whose arguments, recipients, and effect class are checked
by the monitor before an action is considered authorized, independent of
how few bits it cost to select the symbol in the first place.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import FrozenSet, Mapping, Optional, Tuple


class EffectClass:
    NONE = "none"
    REVERSIBLE = "reversible"
    IRREVERSIBLE = "irreversible"

    ORDER = {NONE: 0, REVERSIBLE: 1, IRREVERSIBLE: 2}

    @classmethod
    def at_most(cls, value: str, ceiling: str) -> bool:
        if value not in cls.ORDER or ceiling not in cls.ORDER:
            return False
        return cls.ORDER[value] <= cls.ORDER[ceiling]


@dataclass(frozen=True)
class ArgConstraint:
    """Validates one action-template argument. All three checks are
    optional and conjunctive; an argument with no constraint object at all
    is not permitted -- every argument an action can take must be
    explicitly declared (see ActionTemplate.validate_args)."""

    allowed_values: Optional[FrozenSet[str]] = None
    pattern: Optional[str] = None
    max_length: Optional[int] = None

    def validate(self, value: str) -> Tuple[bool, str]:
        if not isinstance(value, str):
            return False, "not_a_string"
        if self.max_length is not None and len(value) > self.max_length:
            return False, "too_long"
        if self.allowed_values is not None and value not in self.allowed_values:
            return False, "not_allowed"
        if self.pattern is not None and re.fullmatch(self.pattern, value) is None:
            return False, "pattern_mismatch"
        return True, "ok"

    def to_dict(self) -> dict:
        return {
            "allowed_values": sorted(self.allowed_values) if self.allowed_values is not None else None,
            "pattern": self.pattern,
            "max_length": self.max_length,
        }

    @staticmethod
    def from_dict(d: dict) -> "ArgConstraint":
        return ArgConstraint(
            allowed_values=frozenset(d["allowed_values"]) if d.get("allowed_values") is not None else None,
            pattern=d.get("pattern"),
            max_length=d.get("max_length"),
        )


@dataclass(frozen=True)
class ActionTemplate:
    """A prevalidated, capability-scoped action a gate symbol may map to.
    Trusted-authored only, exactly like gate symbols themselves -- an
    untrusted caller can select *among* declared templates via the gate,
    but cannot construct or modify one."""

    name: str
    tool: Optional[str] = None
    arg_constraints: Mapping[str, ArgConstraint] = field(default_factory=dict)
    recipient_scope: FrozenSet[str] = frozenset()
    resource_scope: FrozenSet[str] = frozenset()
    recipient_arg: Optional[str] = None
    resource_arg: Optional[str] = None
    max_effect_class: str = EffectClass.NONE

    def validate_definition(self) -> Tuple[bool, str]:
        if not isinstance(self.name, str) or not self.name:
            return False, "invalid_action_name"
        if self.tool is not None and not isinstance(self.tool, str):
            return False, "invalid_tool_name"
        if self.max_effect_class not in EffectClass.ORDER:
            return False, "invalid_effect_class"
        for key, constraint in self.arg_constraints.items():
            if not isinstance(key, str) or not isinstance(constraint, ArgConstraint):
                return False, "invalid_argument_constraint"
            if (
                constraint.max_length is not None
                and (
                    isinstance(constraint.max_length, bool)
                    or not isinstance(constraint.max_length, int)
                    or constraint.max_length < 0
                )
            ):
                return False, "invalid_max_length"
            if constraint.allowed_values is not None and not all(
                isinstance(value, str) for value in constraint.allowed_values
            ):
                return False, "invalid_allowed_value"
            if constraint.pattern is not None:
                if not isinstance(constraint.pattern, str):
                    return False, "invalid_pattern"
                try:
                    re.compile(constraint.pattern)
                except re.error:
                    return False, "invalid_pattern"
        if not all(isinstance(value, str) for value in self.recipient_scope):
            return False, "invalid_recipient_scope"
        if not all(isinstance(value, str) for value in self.resource_scope):
            return False, "invalid_resource_scope"
        for scope, argument, label in (
            (self.recipient_scope, self.recipient_arg, "recipient"),
            (self.resource_scope, self.resource_arg, "resource"),
        ):
            if scope:
                if (
                    not isinstance(argument, str)
                    or argument not in self.arg_constraints
                ):
                    return False, f"unbound_{label}_scope"
            elif argument is not None:
                return False, f"{label}_arg_without_scope"
        return True, "ok"

    def validate_args(self, args: Mapping[str, str]) -> Tuple[bool, str]:
        if not isinstance(args, Mapping):
            return False, "arguments_not_a_mapping"
        if not all(isinstance(key, str) and isinstance(value, str) for key, value in args.items()):
            return False, "arguments_must_be_strings"
        declared = set(self.arg_constraints)
        supplied = set(args)
        missing = declared - supplied
        if missing:
            return False, "missing_required_arguments"
        extra = supplied - declared
        if extra:
            # Undeclared arguments are rejected outright, not ignored --
            # an attacker who can smuggle an extra kwarg past validation
            # (e.g. a second "cc" recipient alongside a validated "to")
            # would otherwise bypass the whole point of scoping the
            # template's arguments in the first place.
            return False, "undeclared_arguments"
        for key, constraint in self.arg_constraints.items():
            ok, reason = constraint.validate(args[key])
            if not ok:
                return False, f"invalid_argument:{key}:{reason}"
        if self.recipient_scope:
            if args[self.recipient_arg] not in self.recipient_scope:
                return False, "recipient_outside_scope"
        if self.resource_scope:
            if args[self.resource_arg] not in self.resource_scope:
                return False, "resource_outside_scope"
        return True, "ok"

    def effect_permitted(self, ceiling: str) -> bool:
        return EffectClass.at_most(self.max_effect_class, ceiling)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "tool": self.tool,
            "arg_constraints": {k: v.to_dict() for k, v in sorted(self.arg_constraints.items())},
            "recipient_scope": sorted(self.recipient_scope),
            "resource_scope": sorted(self.resource_scope),
            "recipient_arg": self.recipient_arg,
            "resource_arg": self.resource_arg,
            "max_effect_class": self.max_effect_class,
        }

    @staticmethod
    def from_dict(d: dict) -> "ActionTemplate":
        return ActionTemplate(
            name=d["name"],
            tool=d.get("tool"),
            arg_constraints={k: ArgConstraint.from_dict(v) for k, v in d.get("arg_constraints", {}).items()},
            recipient_scope=frozenset(d.get("recipient_scope", [])),
            resource_scope=frozenset(d.get("resource_scope", [])),
            recipient_arg=d.get("recipient_arg"),
            resource_arg=d.get("resource_arg"),
            max_effect_class=d.get("max_effect_class", EffectClass.NONE),
        )
