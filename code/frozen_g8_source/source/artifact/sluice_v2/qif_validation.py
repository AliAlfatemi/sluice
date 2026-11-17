"""Finite-distribution validation for Sluice's transcript bound.

The routines in this module are deliberately independent of the monitor and
its handlers.  A validation input is a completely explicit finite probability
model: a prior over a (possibly correlated) secret vector, one public envelope
for each reachable public history, and one conditional event kernel for each
secret/history pair.  The validator checks the public envelope before it
computes mutual information.

The additive mixed-process path validates a fixed public chronology containing
both charged finite observations and exact-rational public-history
post-processing kernels.  It preserves the original all-charged API.

This is executable finite-model evidence, not a proof for arbitrary
distributions and not a substitute for enforcing the complete observer
projection or a live process boundary.  The mathematical argument is recorded
in ``analysis/INFORMATION_THEORETIC_PROOF.md``.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from fractions import Fraction
import math
from types import MappingProxyType
from typing import Hashable, Mapping, TypeAlias


Secret: TypeAlias = Hashable
Event: TypeAlias = Hashable
History: TypeAlias = tuple[Event, ...]

MAX_VALIDATION_STEPS = 1_024
MAX_REACHABLE_JOINT_STATES = 1_000_000
MAX_ALPHABET_CARDINALITY = 1_000_000
MAX_ACCOUNTING_UNITS_PER_BIT = 1_000_000
MAX_CHARGE_UNITS = (1 << 64) - 1
MAX_EXACT_PROBABILITY_COMPONENT_BITS = 4_096
MAX_MODEL_MAPPING_ENTRIES = 1_000_000
MAX_SYMBOL_DEPTH = 32
MAX_SYMBOL_ITEMS = 4_096
MAX_SYMBOL_TEXT_BYTES = 65_536
_NUMERIC_TOLERANCE_BITS = 1e-10


class QIFValidationError(ValueError):
    """Base class for a malformed or unsound finite validation model."""


class UnderchargedEnvelopeError(QIFValidationError):
    """The declared charge cannot encode the declared public support."""


class ProjectionCompletenessError(QIFValidationError):
    """A kernel emits an event outside the declared complete projection."""


class ChronologyCompletenessError(QIFValidationError):
    """A required observable slot is missing, reordered, or mislabeled."""


class PostprocessingIndependenceError(QIFValidationError):
    """A nominally free step is not secret-independent given public history."""


def _strict_positive_int(name: str, value: object, maximum: int) -> int:
    if type(value) is not int:
        raise TypeError(f"{name} must be an integer")
    if not 1 <= value <= maximum:
        raise QIFValidationError(f"{name} is outside the validation bound")
    return value


def _strict_nonnegative_int(
    name: str, value: object, maximum: int | None = None
) -> int:
    if type(value) is not int:
        raise TypeError(f"{name} must be an integer")
    if value < 0:
        raise QIFValidationError(f"{name} must be nonnegative")
    if maximum is not None and value > maximum:
        raise QIFValidationError(f"{name} is outside the validation bound")
    return value


def _require_bounded_mapping(
    name: str, value: object, *, maximum: int = MAX_MODEL_MAPPING_ENTRIES
) -> Mapping[object, object]:
    if not isinstance(value, Mapping) or not value:
        raise TypeError(f"{name} must be a nonempty mapping")
    if len(value) > maximum:
        raise QIFValidationError(f"{name} exceeds the validation entry bound")
    return value


def _probability(value: object, *, name: str) -> Fraction:
    if type(value) is bool:
        raise TypeError(f"{name} must be an exact rational probability")
    if type(value) is int:
        result = Fraction(value, 1)
    elif type(value) is Fraction:
        result = value
    else:
        raise TypeError(f"{name} must be an int or Fraction")
    if result < 0 or result > 1:
        raise QIFValidationError(f"{name} is outside [0, 1]")
    if (
        result.numerator.bit_length() > MAX_EXACT_PROBABILITY_COMPONENT_BITS
        or result.denominator.bit_length() > MAX_EXACT_PROBABILITY_COMPONENT_BITS
    ):
        raise QIFValidationError(
            f"{name} exceeds the exact-rational validation bound"
        )
    return result


def _finite_symbol(value: object, *, name: str) -> None:
    """Require a stable, immutable equality relation for finite symbols."""

    item_count = 0

    def visit(item: object, depth: int) -> None:
        nonlocal item_count
        item_count += 1
        if item_count > MAX_SYMBOL_ITEMS:
            raise QIFValidationError(f"{name} exceeds the finite item bound")
        if depth > MAX_SYMBOL_DEPTH:
            raise QIFValidationError(f"{name} exceeds the nesting bound")
        if item is None or type(item) is bool:
            return
        if type(item) is int:
            if not -(1 << 63) <= item <= (1 << 63) - 1:
                raise QIFValidationError(f"{name} integer is outside signed 64-bit")
            return
        if type(item) is str:
            try:
                encoded = item.encode("utf-8")
            except UnicodeError as exc:
                raise QIFValidationError(f"{name} is not valid UTF-8") from exc
            if len(encoded) > MAX_SYMBOL_TEXT_BYTES:
                raise QIFValidationError(f"{name} text exceeds the byte bound")
            return
        if type(item) is tuple:
            for child in item:
                visit(child, depth + 1)
            return
        raise TypeError(
            f"{name} must use only immutable JSON scalars and nested tuples"
        )

    visit(value, 0)


def _symbol_key(value: object) -> tuple[object, ...]:
    """Return a recursively type-tagged key for Python-equality collisions."""

    _finite_symbol(value, name="finite symbol")
    if value is None:
        return ("null",)
    if type(value) is bool:
        return ("bool", value)
    if type(value) is int:
        return ("int", value)
    if type(value) is str:
        return ("string", value)
    assert type(value) is tuple
    return ("tuple", tuple(_symbol_key(item) for item in value))


def _log2_fraction(value: Fraction) -> float:
    """Take log2 without first converting an unbounded ratio to binary64."""

    if value <= 0:
        raise QIFValidationError("logarithm input must be positive")
    numerator = value.numerator
    denominator = value.denominator
    if denominator // 2 <= numerator <= denominator * 2:
        exact_delta = Fraction(numerator - denominator, denominator)
        delta = _finite_report_float(
            exact_delta, name="logarithm ratio displacement"
        )
        result = math.log1p(delta) / math.log(2.0)
    else:
        result = math.log2(numerator) - math.log2(denominator)
    if not math.isfinite(result) or (value != 1 and result == 0.0):
        raise QIFValidationError(
            "logarithm is outside the finite binary64 validation range"
        )
    return result


def _finite_report_float(value: Fraction, *, name: str) -> float:
    """Convert one exact result to finite binary64 or fail in-domain."""

    try:
        result = float(value)
    except (OverflowError, ValueError) as exc:
        raise QIFValidationError(
            f"{name} is not representable as finite binary64"
        ) from exc
    if not math.isfinite(result) or (value != 0 and result == 0.0):
        raise QIFValidationError(
            f"{name} is not representable as finite binary64"
        )
    return result


def _weighted_log2(probability: Fraction, ratio: Fraction) -> Fraction:
    """Return an exact weighting of the computed binary64 logarithm.

    The logarithm itself is a checked finite binary64 approximation, but its
    multiplication by an exact probability and all subsequent accumulation
    remain rational until the bounded report conversion.  This avoids losing
    representable totals merely because an individual probability is
    subnormal.
    """

    logarithm = _log2_fraction(ratio)
    if logarithm == 0.0 or probability == 0:
        return Fraction(0, 1)
    return probability * Fraction.from_float(logarithm)


def minimum_charge_units(cardinality: int, accounting_units_per_bit: int) -> int:
    """Return ``ceil(q log2(cardinality))`` using exact integer arithmetic.

    For positive integers ``K`` and ``q``, this is
    ``ceil(log2(K**q))``.  The explicit operational limits keep the exact big
    integer bounded and avoid a floating-point decision at powers of two or
    immediately adjacent cardinalities.
    """

    cardinality = _strict_positive_int(
        "cardinality", cardinality, MAX_ALPHABET_CARDINALITY
    )
    accounting_units_per_bit = _strict_positive_int(
        "accounting_units_per_bit",
        accounting_units_per_bit,
        MAX_ACCOUNTING_UNITS_PER_BIT,
    )
    if cardinality == 1:
        return 0
    powered = pow(cardinality, accounting_units_per_bit)
    return (powered - 1).bit_length()


@dataclass(frozen=True, slots=True)
class PublicEnvelope:
    """History-indexed union support and its pre-observation charge."""

    alphabet: tuple[Event, ...]
    charge_units: int

    def __post_init__(self) -> None:
        if type(self.alphabet) is not tuple or not self.alphabet:
            raise TypeError("alphabet must be a nonempty tuple")
        if len(self.alphabet) > MAX_ALPHABET_CARDINALITY:
            raise QIFValidationError("alphabet exceeds the validation bound")
        unique = frozenset(_symbol_key(event) for event in self.alphabet)
        if len(unique) != len(self.alphabet):
            raise QIFValidationError("public alphabet contains duplicate events")
        _strict_nonnegative_int(
            "charge_units", self.charge_units, MAX_CHARGE_UNITS
        )


@dataclass(frozen=True, slots=True)
class QIFValidationReport:
    """Numerical information quantities over exact enumerated probabilities."""

    mutual_information_bits: float
    chain_rule_sum_bits: float
    expected_declared_support_bits: float
    expected_charge_bits: float
    maximum_path_charge_bits: Fraction
    step_mutual_information_bits: tuple[float, ...]
    step_declared_support_bits: tuple[float, ...]
    step_expected_charge_bits: tuple[float, ...]
    reachable_histories_by_step: tuple[int, ...]
    final_joint_states: int


class MixedStepAuthorization(str, Enum):
    """Authorization rule for one complete-chronology observable."""

    CHARGED_FINITE = "CHARGED_FINITE"
    PUBLIC_HISTORY_POSTPROCESSING = "PUBLIC_HISTORY_POSTPROCESSING"


def _observable_kind(value: object) -> str:
    if type(value) is not str:
        raise TypeError("observable_kind must be a string")
    if not value or len(value.encode("ascii", errors="ignore")) != len(value):
        raise QIFValidationError("observable_kind must be nonempty ASCII")
    if len(value) > 128 or any(
        not (character.isupper() or character.isdigit() or character == "_")
        for character in value
    ):
        raise QIFValidationError(
            "observable_kind must use at most 128 uppercase ASCII letters, digits, or _"
        )
    return value


@dataclass(frozen=True, slots=True)
class MixedPublicEnvelope:
    """One history-indexed slot in a complete mixed observable chronology.

    ``CHARGED_FINITE`` slots use the ordinary support/charge rule.
    ``PUBLIC_HISTORY_POSTPROCESSING`` slots must carry zero charge and their
    exact kernels must be identical across every secret still possible after
    the public prefix.  The latter is the finite-model form of
    ``S independent of O_i | P,O_<i``.
    """

    observable_kind: str
    authorization: MixedStepAuthorization
    alphabet: tuple[Event, ...]
    charge_units: int

    def __post_init__(self) -> None:
        _observable_kind(self.observable_kind)
        if type(self.authorization) is not MixedStepAuthorization:
            raise TypeError("authorization must be a MixedStepAuthorization")
        if type(self.alphabet) is not tuple or not self.alphabet:
            raise TypeError("alphabet must be a nonempty tuple")
        if len(self.alphabet) > MAX_ALPHABET_CARDINALITY:
            raise QIFValidationError("alphabet exceeds the validation bound")
        unique = frozenset(_symbol_key(event) for event in self.alphabet)
        if len(unique) != len(self.alphabet):
            raise QIFValidationError("public alphabet contains duplicate observations")
        _strict_nonnegative_int(
            "charge_units", self.charge_units, MAX_CHARGE_UNITS
        )
        if (
            self.authorization
            is MixedStepAuthorization.PUBLIC_HISTORY_POSTPROCESSING
            and self.charge_units != 0
        ):
            raise QIFValidationError(
                "public-history post-processing must not disguise a charged step"
            )


@dataclass(frozen=True, slots=True)
class MixedQIFValidationReport:
    """Information quantities for a complete charged/free chronology."""

    mutual_information_bits: float
    chain_rule_sum_bits: float
    expected_charged_support_bits: float
    expected_charge_bits: float
    maximum_path_charge_bits: Fraction
    step_mutual_information_bits: tuple[float, ...]
    step_expected_charged_support_bits: tuple[float, ...]
    step_expected_charge_bits: tuple[float, ...]
    reachable_histories_by_step: tuple[int, ...]
    charged_history_checks: int
    postprocessing_history_checks: int
    final_joint_states: int


class FiniteAdaptiveProcess:
    """An immutable, explicit finite model of an adaptive public transcript.

    ``envelopes`` is indexed only by public history.  ``kernels`` may depend
    arbitrarily on the secret and public history, so validation does not assume
    conditional independence of private metadata, handlers, or outcomes.  All
    such private state is marginalized into these conditional kernels.
    """

    def __init__(
        self,
        *,
        prior: Mapping[Secret, Fraction | int],
        max_steps: int,
        accounting_units_per_bit: int,
        envelopes: Mapping[History, PublicEnvelope],
        kernels: Mapping[
            tuple[Secret, History], Mapping[Event, Fraction | int]
        ],
    ) -> None:
        max_steps = _strict_positive_int(
            "max_steps", max_steps, MAX_VALIDATION_STEPS
        )
        accounting_units_per_bit = _strict_positive_int(
            "accounting_units_per_bit",
            accounting_units_per_bit,
            MAX_ACCOUNTING_UNITS_PER_BIT,
        )
        _require_bounded_mapping("prior", prior)
        copied_prior: dict[tuple[object, ...], Fraction] = {}
        for secret, probability in prior.items():
            canonical_secret = _symbol_key(secret)
            if canonical_secret in copied_prior:
                raise QIFValidationError("prior contains a duplicate secret")
            exact = _probability(probability, name="prior probability")
            if exact == 0:
                raise QIFValidationError("prior support must not contain zero mass")
            copied_prior[canonical_secret] = exact
        if sum(copied_prior.values(), Fraction(0, 1)) != 1:
            raise QIFValidationError("prior probabilities must sum exactly to one")

        _require_bounded_mapping("envelopes", envelopes)
        copied_envelopes: dict[History, PublicEnvelope] = {}
        for history, envelope in envelopes.items():
            if type(history) is not tuple:
                raise TypeError("envelope histories must be tuples")
            if len(history) >= max_steps:
                raise QIFValidationError("envelope history is outside max_steps")
            canonical_history = tuple(_symbol_key(event) for event in history)
            if type(envelope) is not PublicEnvelope:
                raise TypeError("envelope values must be PublicEnvelope instances")
            if canonical_history in copied_envelopes:
                raise QIFValidationError(
                    "envelope histories collide after typed canonicalization"
                )
            copied_envelopes[canonical_history] = PublicEnvelope(
                tuple(envelope.alphabet), envelope.charge_units
            )

        _require_bounded_mapping("kernels", kernels)
        copied_kernels: dict[
            tuple[tuple[object, ...], History], Mapping[Event, Fraction]
        ] = {}
        for key, distribution in kernels.items():
            if type(key) is not tuple or len(key) != 2:
                raise TypeError("kernel keys must be (secret, history) tuples")
            secret, history = key
            canonical_secret = _symbol_key(secret)
            if canonical_secret not in copied_prior:
                raise QIFValidationError(
                    "kernel refers to a typed secret outside the prior"
                )
            if type(history) is not tuple or len(history) >= max_steps:
                raise QIFValidationError("kernel history is outside max_steps")
            canonical_history = tuple(_symbol_key(event) for event in history)
            _require_bounded_mapping(
                "kernel distribution",
                distribution,
                maximum=MAX_ALPHABET_CARDINALITY,
            )
            copied_distribution: dict[Event, Fraction] = {}
            for event, probability in distribution.items():
                canonical_event = _symbol_key(event)
                exact = _probability(probability, name="kernel probability")
                if exact == 0:
                    raise QIFValidationError(
                        "kernel support must not contain zero probability"
                    )
                if canonical_event in copied_distribution:
                    raise QIFValidationError(
                        "kernel events collide after typed canonicalization"
                    )
                copied_distribution[canonical_event] = exact
            if sum(copied_distribution.values(), Fraction(0, 1)) != 1:
                raise QIFValidationError(
                    "each kernel distribution must sum exactly to one"
                )
            canonical_key = (canonical_secret, canonical_history)
            if canonical_key in copied_kernels:
                raise QIFValidationError(
                    "kernel keys collide after typed canonicalization"
                )
            copied_kernels[canonical_key] = MappingProxyType(
                copied_distribution
            )

        self.max_steps = max_steps
        self.accounting_units_per_bit = accounting_units_per_bit
        self.prior = MappingProxyType(copied_prior)
        self.envelopes = MappingProxyType(copied_envelopes)
        self.kernels = MappingProxyType(copied_kernels)

    def validate(self) -> QIFValidationReport:
        """Enumerate the joint law and validate the chain-rule bound."""

        state: dict[tuple[Secret, History], Fraction] = {
            (secret, ()): probability for secret, probability in self.prior.items()
        }
        path_charge_units: dict[History, int] = {(): 0}
        step_mi: list[float] = []
        step_support: list[float] = []
        step_charge: list[float] = []
        step_mi_exact: list[Fraction] = []
        step_support_exact: list[Fraction] = []
        step_charge_exact: list[Fraction] = []
        histories_by_step: list[int] = [1]

        for _step in range(self.max_steps):
            histories: dict[History, dict[Secret, Fraction]] = {}
            for (secret, history), mass in state.items():
                histories.setdefault(history, {})[secret] = mass

            conditional_mi_exact = Fraction(0, 1)
            expected_support_exact = Fraction(0, 1)
            expected_charge_exact = Fraction(0, 1)
            next_state: dict[tuple[Secret, History], Fraction] = {}
            next_path_charge: dict[History, int] = {}

            for history, secret_masses in histories.items():
                envelope = self.envelopes.get(history)
                if envelope is None:
                    raise QIFValidationError(
                        f"missing public envelope at reachable history {history!r}"
                    )
                required = minimum_charge_units(
                    len(envelope.alphabet), self.accounting_units_per_bit
                )
                if envelope.charge_units < required:
                    raise UnderchargedEnvelopeError(
                        "declared event support exceeds the pre-observation charge"
                    )
                alphabet = frozenset(
                    _symbol_key(event) for event in envelope.alphabet
                )
                history_mass = sum(secret_masses.values(), Fraction(0, 1))
                expected_support_exact += _weighted_log2(
                    history_mass, Fraction(len(alphabet), 1)
                )
                expected_charge_exact += history_mass * Fraction(
                    envelope.charge_units, self.accounting_units_per_bit
                )

                event_mass: dict[Event, Fraction] = {}
                distributions: dict[Secret, Mapping[Event, Fraction]] = {}
                for secret, secret_history_mass in secret_masses.items():
                    distribution = self.kernels.get((secret, history))
                    if distribution is None:
                        raise QIFValidationError(
                            "missing kernel for a reachable secret/history pair"
                        )
                    outside = set(distribution).difference(alphabet)
                    if outside:
                        raise ProjectionCompletenessError(
                            "kernel emits an event outside the complete public envelope"
                        )
                    distributions[secret] = distribution
                    for event, conditional_probability in distribution.items():
                        event_mass[event] = event_mass.get(event, Fraction(0, 1)) + (
                            secret_history_mass * conditional_probability
                        )

                for secret, secret_history_mass in secret_masses.items():
                    distribution = distributions[secret]
                    for event, conditional_probability in distribution.items():
                        joint = secret_history_mass * conditional_probability
                        public_conditional = event_mass[event] / history_mass
                        conditional_mi_exact += _weighted_log2(
                            joint,
                            conditional_probability / public_conditional
                        )
                        extended = history + (event,)
                        key = (secret, extended)
                        next_state[key] = next_state.get(key, Fraction(0, 1)) + joint
                        charged = (
                            path_charge_units[history] + envelope.charge_units
                        )
                        prior_charge = next_path_charge.get(extended)
                        if prior_charge is not None and prior_charge != charged:
                            raise QIFValidationError(
                                "charge is not a deterministic function of public history"
                            )
                        next_path_charge[extended] = charged

            if len(next_state) > MAX_REACHABLE_JOINT_STATES:
                raise QIFValidationError(
                    "reachable finite model exceeds the validation state bound"
                )
            conditional_mi = _finite_report_float(
                conditional_mi_exact, name="step mutual information"
            )
            expected_support = _finite_report_float(
                expected_support_exact, name="step expected support"
            )
            expected_charge = _finite_report_float(
                expected_charge_exact, name="step expected charge"
            )
            if conditional_mi > expected_support + _NUMERIC_TOLERANCE_BITS:
                raise AssertionError("conditional mutual information exceeds entropy")
            if expected_support > expected_charge + _NUMERIC_TOLERANCE_BITS:
                raise AssertionError("declared support exceeds charged capacity")
            step_mi.append(conditional_mi)
            step_support.append(expected_support)
            step_charge.append(expected_charge)
            step_mi_exact.append(conditional_mi_exact)
            step_support_exact.append(expected_support_exact)
            step_charge_exact.append(expected_charge_exact)
            state = next_state
            path_charge_units = next_path_charge
            histories_by_step.append(len(next_path_charge))

        final_history_mass: dict[History, Fraction] = {}
        for (_secret, history), mass in state.items():
            final_history_mass[history] = final_history_mass.get(
                history, Fraction(0, 1)
            ) + mass
        mutual_information_exact = Fraction(0, 1)
        for (secret, history), joint in state.items():
            denominator = self.prior[secret] * final_history_mass[history]
            mutual_information_exact += _weighted_log2(
                joint, joint / denominator
            )

        chain_sum_exact = sum(step_mi_exact, Fraction(0, 1))
        expected_support_total_exact = sum(
            step_support_exact, Fraction(0, 1)
        )
        expected_charge_total_exact = sum(
            step_charge_exact, Fraction(0, 1)
        )
        mutual_information = _finite_report_float(
            mutual_information_exact, name="mutual information"
        )
        chain_sum = _finite_report_float(
            chain_sum_exact, name="chain-rule sum"
        )
        expected_support_total = _finite_report_float(
            expected_support_total_exact, name="expected support"
        )
        expected_charge_total = _finite_report_float(
            expected_charge_total_exact, name="expected charge"
        )
        if abs(mutual_information - chain_sum) > _NUMERIC_TOLERANCE_BITS:
            raise AssertionError("chain-rule decomposition did not reconcile")
        if mutual_information > expected_charge_total + _NUMERIC_TOLERANCE_BITS:
            raise AssertionError("mutual information exceeds charged capacity")
        maximum_path_units = max(path_charge_units.values(), default=0)
        return QIFValidationReport(
            mutual_information_bits=mutual_information,
            chain_rule_sum_bits=chain_sum,
            expected_declared_support_bits=expected_support_total,
            expected_charge_bits=expected_charge_total,
            maximum_path_charge_bits=Fraction(
                maximum_path_units, self.accounting_units_per_bit
            ),
            step_mutual_information_bits=tuple(step_mi),
            step_declared_support_bits=tuple(step_support),
            step_expected_charge_bits=tuple(step_charge),
            reachable_histories_by_step=tuple(histories_by_step),
            final_joint_states=len(state),
        )


class FiniteMixedAdaptiveProcess:
    """Validate a complete chronology mixing charged and free public steps.

    Each entry of ``chronology_slots`` is a public, fixed observable role.
    Envelopes remain adaptive functions of the exact prior public history, but
    every reachable history must supply the role reserved for its slot.  A
    finite deployment can therefore represent retries, control traffic,
    responses, failures, and post-close replies explicitly, using typed
    stutters for unused slots.

    The model is one fixed public-state fiber ``P=p``.  Charged slots are
    checked exactly as in :class:`FiniteAdaptiveProcess`.  At a nominally free
    post-processing slot, exact rational kernels must agree for all secrets
    having positive posterior mass at that history.  Later charged kernels
    may depend on the whole chronology prefix; this class intentionally does
    not claim equality with an event-only projection.
    """

    def __init__(
        self,
        *,
        prior: Mapping[Secret, Fraction | int],
        chronology_slots: tuple[str, ...],
        accounting_units_per_bit: int,
        envelopes: Mapping[History, MixedPublicEnvelope],
        kernels: Mapping[
            tuple[Secret, History], Mapping[Event, Fraction | int]
        ],
    ) -> None:
        if type(chronology_slots) is not tuple or not chronology_slots:
            raise TypeError("chronology_slots must be a nonempty tuple")
        if len(chronology_slots) > MAX_VALIDATION_STEPS:
            raise QIFValidationError("chronology exceeds the validation bound")
        copied_slots = tuple(_observable_kind(slot) for slot in chronology_slots)
        accounting_units_per_bit = _strict_positive_int(
            "accounting_units_per_bit",
            accounting_units_per_bit,
            MAX_ACCOUNTING_UNITS_PER_BIT,
        )

        _require_bounded_mapping("prior", prior)
        copied_prior: dict[tuple[object, ...], Fraction] = {}
        for secret, probability in prior.items():
            canonical_secret = _symbol_key(secret)
            if canonical_secret in copied_prior:
                raise QIFValidationError(
                    "prior secrets collide after typed canonicalization"
                )
            exact = _probability(probability, name="prior probability")
            if exact == 0:
                raise QIFValidationError("prior support must not contain zero mass")
            copied_prior[canonical_secret] = exact
        if sum(copied_prior.values(), Fraction(0, 1)) != 1:
            raise QIFValidationError("prior probabilities must sum exactly to one")

        _require_bounded_mapping("envelopes", envelopes)
        copied_envelopes: dict[History, MixedPublicEnvelope] = {}
        for history, envelope in envelopes.items():
            if type(history) is not tuple:
                raise TypeError("envelope histories must be tuples")
            if len(history) >= len(copied_slots):
                raise QIFValidationError(
                    "envelope history is outside the chronology bound"
                )
            canonical_history = tuple(_symbol_key(event) for event in history)
            if type(envelope) is not MixedPublicEnvelope:
                raise TypeError(
                    "envelope values must be MixedPublicEnvelope instances"
                )
            expected_kind = copied_slots[len(history)]
            if envelope.observable_kind != expected_kind:
                raise ChronologyCompletenessError(
                    "observable kind does not match the public chronology slot"
                )
            if canonical_history in copied_envelopes:
                raise QIFValidationError(
                    "envelope histories collide after typed canonicalization"
                )
            copied_envelopes[canonical_history] = MixedPublicEnvelope(
                observable_kind=envelope.observable_kind,
                authorization=envelope.authorization,
                alphabet=tuple(envelope.alphabet),
                charge_units=envelope.charge_units,
            )

        _require_bounded_mapping("kernels", kernels)
        copied_kernels: dict[
            tuple[tuple[object, ...], History], Mapping[Event, Fraction]
        ] = {}
        for key, distribution in kernels.items():
            if type(key) is not tuple or len(key) != 2:
                raise TypeError("kernel keys must be (secret, history) tuples")
            secret, history = key
            canonical_secret = _symbol_key(secret)
            if canonical_secret not in copied_prior:
                raise QIFValidationError(
                    "kernel refers to a typed secret outside the prior"
                )
            if type(history) is not tuple or len(history) >= len(copied_slots):
                raise QIFValidationError(
                    "kernel history is outside the chronology bound"
                )
            canonical_history = tuple(_symbol_key(event) for event in history)
            _require_bounded_mapping(
                "kernel distribution",
                distribution,
                maximum=MAX_ALPHABET_CARDINALITY,
            )
            copied_distribution: dict[Event, Fraction] = {}
            for event, probability in distribution.items():
                canonical_event = _symbol_key(event)
                exact = _probability(probability, name="kernel probability")
                if exact == 0:
                    raise QIFValidationError(
                        "kernel support must not contain zero probability"
                    )
                if canonical_event in copied_distribution:
                    raise QIFValidationError(
                        "kernel observations collide after typed canonicalization"
                    )
                copied_distribution[canonical_event] = exact
            if sum(copied_distribution.values(), Fraction(0, 1)) != 1:
                raise QIFValidationError(
                    "each kernel distribution must sum exactly to one"
                )
            canonical_key = (canonical_secret, canonical_history)
            if canonical_key in copied_kernels:
                raise QIFValidationError(
                    "kernel keys collide after typed canonicalization"
                )
            copied_kernels[canonical_key] = MappingProxyType(copied_distribution)

        self.max_steps = len(copied_slots)
        self.chronology_slots = copied_slots
        self.accounting_units_per_bit = accounting_units_per_bit
        self.prior = MappingProxyType(copied_prior)
        self.envelopes = MappingProxyType(copied_envelopes)
        self.kernels = MappingProxyType(copied_kernels)

    def validate(self) -> MixedQIFValidationReport:
        """Enumerate and check the mixed chronological chain-rule bound."""

        state: dict[tuple[Secret, History], Fraction] = {
            (secret, ()): probability for secret, probability in self.prior.items()
        }
        path_charge_units: dict[History, int] = {(): 0}
        step_mi: list[float] = []
        step_charged_support: list[float] = []
        step_charge: list[float] = []
        step_mi_exact: list[Fraction] = []
        step_charged_support_exact: list[Fraction] = []
        step_charge_exact: list[Fraction] = []
        histories_by_step: list[int] = [1]
        charged_checks = 0
        postprocessing_checks = 0

        for step, expected_kind in enumerate(self.chronology_slots):
            histories: dict[History, dict[Secret, Fraction]] = {}
            for (secret, history), mass in state.items():
                histories.setdefault(history, {})[secret] = mass

            conditional_mi_exact = Fraction(0, 1)
            expected_charged_support_exact = Fraction(0, 1)
            expected_charge_exact = Fraction(0, 1)
            next_state: dict[tuple[Secret, History], Fraction] = {}
            next_path_charge: dict[History, int] = {}

            for history, secret_masses in histories.items():
                envelope = self.envelopes.get(history)
                if envelope is None:
                    raise ChronologyCompletenessError(
                        "missing public envelope for a required observable slot"
                    )
                if envelope.observable_kind != expected_kind:
                    raise ChronologyCompletenessError(
                        "reachable observable is reordered or mislabeled"
                    )
                alphabet = frozenset(
                    _symbol_key(observation) for observation in envelope.alphabet
                )
                history_mass = sum(secret_masses.values(), Fraction(0, 1))

                if envelope.authorization is MixedStepAuthorization.CHARGED_FINITE:
                    charged_checks += 1
                    required = minimum_charge_units(
                        len(envelope.alphabet), self.accounting_units_per_bit
                    )
                    if envelope.charge_units < required:
                        raise UnderchargedEnvelopeError(
                            "declared charged support exceeds the pre-observation charge"
                        )
                    expected_charged_support_exact += _weighted_log2(
                        history_mass, Fraction(len(alphabet), 1)
                    )
                    expected_charge_exact += history_mass * Fraction(
                        envelope.charge_units, self.accounting_units_per_bit
                    )
                else:
                    postprocessing_checks += 1
                    if envelope.charge_units != 0:
                        raise QIFValidationError(
                            "post-processing chronology slot has nonzero charge"
                        )

                event_mass: dict[Event, Fraction] = {}
                distributions: dict[Secret, Mapping[Event, Fraction]] = {}
                for secret, secret_history_mass in secret_masses.items():
                    distribution = self.kernels.get((secret, history))
                    if distribution is None:
                        raise ChronologyCompletenessError(
                            "missing kernel for a required observable slot"
                        )
                    outside = set(distribution).difference(alphabet)
                    if outside:
                        raise ProjectionCompletenessError(
                            "kernel emits an observation outside the complete chronology"
                        )
                    distributions[secret] = distribution
                    for observation, conditional_probability in distribution.items():
                        event_mass[observation] = event_mass.get(
                            observation, Fraction(0, 1)
                        ) + secret_history_mass * conditional_probability

                if (
                    envelope.authorization
                    is MixedStepAuthorization.PUBLIC_HISTORY_POSTPROCESSING
                ):
                    reference = next(iter(distributions.values()))
                    if any(
                        dict(distribution) != dict(reference)
                        for distribution in distributions.values()
                    ):
                        raise PostprocessingIndependenceError(
                            "post-processing kernel depends on the secret given public history"
                        )

                history_information_exact = Fraction(0, 1)
                for secret, secret_history_mass in secret_masses.items():
                    distribution = distributions[secret]
                    for observation, conditional_probability in distribution.items():
                        joint = secret_history_mass * conditional_probability
                        public_conditional = event_mass[observation] / history_mass
                        contribution = _weighted_log2(
                            joint,
                            conditional_probability / public_conditional,
                        )
                        conditional_mi_exact += contribution
                        history_information_exact += contribution
                        extended = history + (observation,)
                        key = (secret, extended)
                        next_state[key] = next_state.get(
                            key, Fraction(0, 1)
                        ) + joint
                        charged = (
                            path_charge_units[history] + envelope.charge_units
                        )
                        prior_charge = next_path_charge.get(extended)
                        if prior_charge is not None and prior_charge != charged:
                            raise QIFValidationError(
                                "charge is not a deterministic function of public history"
                            )
                        next_path_charge[extended] = charged

                if (
                    envelope.authorization
                    is MixedStepAuthorization.PUBLIC_HISTORY_POSTPROCESSING
                    and history_information_exact != 0
                ):
                    raise AssertionError(
                        "secret-independent post-processing has nonzero incremental information"
                    )

            if len(next_state) > MAX_REACHABLE_JOINT_STATES:
                raise QIFValidationError(
                    "reachable mixed model exceeds the validation state bound"
                )
            conditional_mi = _finite_report_float(
                conditional_mi_exact, name="mixed-step mutual information"
            )
            expected_charged_support = _finite_report_float(
                expected_charged_support_exact,
                name="mixed-step expected charged support",
            )
            expected_charge = _finite_report_float(
                expected_charge_exact, name="mixed-step expected charge"
            )
            if conditional_mi > (
                expected_charged_support + _NUMERIC_TOLERANCE_BITS
            ):
                raise AssertionError(
                    "mixed-step mutual information exceeds charged support"
                )
            if expected_charged_support > (
                expected_charge + _NUMERIC_TOLERANCE_BITS
            ):
                raise AssertionError("charged support exceeds charged capacity")
            step_mi.append(conditional_mi)
            step_charged_support.append(expected_charged_support)
            step_charge.append(expected_charge)
            step_mi_exact.append(conditional_mi_exact)
            step_charged_support_exact.append(expected_charged_support_exact)
            step_charge_exact.append(expected_charge_exact)
            state = next_state
            path_charge_units = next_path_charge
            histories_by_step.append(len(next_path_charge))

        final_history_mass: dict[History, Fraction] = {}
        for (_secret, history), mass in state.items():
            final_history_mass[history] = final_history_mass.get(
                history, Fraction(0, 1)
            ) + mass
        mutual_information_exact = Fraction(0, 1)
        for (secret, history), joint in state.items():
            denominator = self.prior[secret] * final_history_mass[history]
            mutual_information_exact += _weighted_log2(
                joint, joint / denominator
            )

        chain_sum_exact = sum(step_mi_exact, Fraction(0, 1))
        expected_charged_support_total_exact = sum(
            step_charged_support_exact, Fraction(0, 1)
        )
        expected_charge_total_exact = sum(
            step_charge_exact, Fraction(0, 1)
        )
        mutual_information = _finite_report_float(
            mutual_information_exact, name="mixed mutual information"
        )
        chain_sum = _finite_report_float(
            chain_sum_exact, name="mixed chain-rule sum"
        )
        expected_charged_support_total = _finite_report_float(
            expected_charged_support_total_exact,
            name="mixed expected charged support",
        )
        expected_charge_total = _finite_report_float(
            expected_charge_total_exact, name="mixed expected charge"
        )
        if abs(mutual_information - chain_sum) > _NUMERIC_TOLERANCE_BITS:
            raise AssertionError("mixed chain-rule decomposition did not reconcile")
        if mutual_information > expected_charge_total + _NUMERIC_TOLERANCE_BITS:
            raise AssertionError("mixed chronology exceeds charged capacity")
        maximum_path_units = max(path_charge_units.values(), default=0)
        return MixedQIFValidationReport(
            mutual_information_bits=mutual_information,
            chain_rule_sum_bits=chain_sum,
            expected_charged_support_bits=expected_charged_support_total,
            expected_charge_bits=expected_charge_total,
            maximum_path_charge_bits=Fraction(
                maximum_path_units, self.accounting_units_per_bit
            ),
            step_mutual_information_bits=tuple(step_mi),
            step_expected_charged_support_bits=tuple(step_charged_support),
            step_expected_charge_bits=tuple(step_charge),
            reachable_histories_by_step=tuple(histories_by_step),
            charged_history_checks=charged_checks,
            postprocessing_history_checks=postprocessing_checks,
            final_joint_states=len(state),
        )


__all__ = [
    "ChronologyCompletenessError",
    "FiniteAdaptiveProcess",
    "FiniteMixedAdaptiveProcess",
    "MixedPublicEnvelope",
    "MixedQIFValidationReport",
    "MixedStepAuthorization",
    "PostprocessingIndependenceError",
    "ProjectionCompletenessError",
    "PublicEnvelope",
    "QIFValidationError",
    "QIFValidationReport",
    "UnderchargedEnvelopeError",
    "minimum_charge_units",
]
