"""CPU-only isolated AgentLeak launch ordering and attestation.

The state machine authenticates a prior-public schedule and the concrete
finite-corpus codebooks, seals all seven ObserverSpec routes, and compiles the
public policy DTO before the protected corpus is opened.  Only then may the
scenario and its allowed projection attach to the post-seal handler.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from . import agentleak as agentleak_module
from . import agentleak_codebooks as codebook_module
from . import agentleak_construction_corpus as construction_corpus_module
from . import agentleak_fullstack as fullstack_module
from . import agentleak_public_schedule as public_schedule_module
from .agentleak import CORPUS_ROWS, CORPUS_SHA256, load_pinned_corpus
from .agentleak_codebooks import (
    CodebookBuildError,
    canonical_allowed_projection,
    validate_codebook_construction_artifacts,
)
from .agentleak_fullstack import (
    MAX_POLICY_JSON_BYTES,
    CodebookBundle,
    HarnessError,
    PolicyAuthorInput,
    PostSealHandler,
    RouteRegistration,
    SealedTemplateCodebooks,
    _canonical_json_bytes,
    _freeze_json,
    _identifier,
    _read_regular_bounded,
    _sha256_pin,
    _strict_int,
    _strict_json_loads,
    _strict_object,
    _strict_sequence,
    build_policy_author_input,
    seal_template_codebooks,
)
from .agentleak_public_schedule import MAX_SCHEDULE_BYTES, SCHEMA_VERSION


CONCRETE_CODEBOOK_MANIFEST_SHA256 = (
    "f6605767a814011edd2f4588a074d40abffa9cd86482ed7f56313656af430627"
)
CONCRETE_CODEBOOK_REPORT_SHA256 = (
    "8c738a3e6e735d195a7fecd205fd76196e263efe03dc0e373b629a54a7e1a016"
)
CONCRETE_CODEBOOK_CHECKSUMS_SHA256 = (
    "9c440cae66201df6819699510bdf2fdbee83034c2d516444d56911fe1c75c488"
)
CONCRETE_CODEBOOK_BUILDER_SOURCE_SHA256 = (
    "69665d9d4e3acf9472586dfe345c0a1e6b8e8b9ffa1c30c324fece24c94fae5d"
)
CONCRETE_CONSTRUCTION_CORPUS_LOADER_SOURCE_SHA256 = (
    "2e2a9df2e369ee10ef807eaeede966b913ffb2bbd466c1cb7d32ebaca817d767"
)
CONCRETE_CODEBOOK_MANIFEST_ID = "agentleak-codebooks-c4688b860a01-69665d9d4e3a"
CONCRETE_PUBLIC_SCHEDULE_SHA256 = (
    "ff7956d57317510a07233f055d17cb0039dceac6b2d9e1c79bb3a98fe1da68b4"
)
CONCRETE_PUBLIC_SCHEDULE_BUILDER_SOURCE_SHA256 = (
    "34082ee283de2c97aa6542f484c07796274d9ce76578e1c36a1555f7be6809dc"
)
CONCRETE_CORPUS_LOADER_SOURCE_SHA256 = (
    "94cd5563e5b4f79e3a773e3784b7db2901ed708789b079169ffdd89524fde968"
)
CONCRETE_HARNESS_SOURCE_SHA256 = (
    "f51904dfe744aaf457c05e2af969d0b452ea968e20bceee393521a1ba6f6999b"
)
CONCRETE_TEMPLATE_COUNT = 16
CONCRETE_PRIVATE_CODEBOOK_COUNT = 112
ATTESTATION_SCHEMA_VERSION = "sluice-agentleak-isolated-launch-attestation-v2"
EXECUTION_MODE = "cpu_order_attestation_only"

_SESSION_TOKEN = object()
_ATTESTATION_TOKEN = object()
_LAUNCHED_TOKEN = object()
_MAPPING_PROXY_TYPE = type(MappingProxyType({}))

_SCHEDULE_KEYS = frozenset(
    {
        "schema_version",
        "corpus_sha256",
        "corpus_rows",
        "schedule_builder_source_sha256",
        "construction_corpus_loader_source_sha256",
        "rows",
    }
)
_SCHEDULE_ROW_KEYS = frozenset(
    {
        "scenario_id",
        "template_code",
        "objective",
        "agents",
        "tools",
        "allowed_field_names",
    }
)


class LaunchOrderError(HarnessError):
    """The isolated launch state, artifact pin, or ordering contract failed."""


class LaunchStage(str, Enum):
    CREATED = "CREATED"
    PUBLIC_SCHEDULE_AUTHENTICATED = "PUBLIC_SCHEDULE_AUTHENTICATED"
    CODEBOOKS_AUTHENTICATED = "CODEBOOKS_AUTHENTICATED"
    DOMAIN_SEALED = "DOMAIN_SEALED"
    PUBLIC_POLICY_COMPILED = "PUBLIC_POLICY_COMPILED"
    PROTECTED_STATE_ATTACHED = "PROTECTED_STATE_ATTACHED"
    FINALIZED = "FINALIZED"


@dataclass(frozen=True, slots=True)
class LaunchOrderAttestation:
    schema_version: str
    execution_mode: str
    scenario_id: str
    template_code: str
    public_schedule_sha256: str
    public_schedule_builder_source_sha256: str
    construction_corpus_loader_source_sha256: str
    corpus_sha256: str
    codebook_manifest_id: str
    codebook_manifest_sha256: str
    construction_report_sha256: str
    checksums_sha256: str
    codebook_builder_source_sha256: str
    observer_spec_id: str
    observer_spec_sha256: str
    template_count: int
    private_codebook_count: int
    route_count: int
    policy_input_sha256: str
    launcher_source_sha256: str
    corpus_loader_source_sha256: str
    harness_source_sha256: str
    events: tuple[str, ...]
    attestation_sha256: str
    _attestation_token: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._attestation_token is not _ATTESTATION_TOKEN:
            raise LaunchOrderError("launch attestations must come from the isolated session")
        if self.schema_version != ATTESTATION_SCHEMA_VERSION:
            raise LaunchOrderError("launch attestation schema is invalid")
        if self.execution_mode != EXECUTION_MODE:
            raise LaunchOrderError("launch attestation is not CPU-only")
        _identifier("attested scenario_id", self.scenario_id)
        _identifier("attested template_code", self.template_code)
        _identifier("attested codebook manifest_id", self.codebook_manifest_id)
        _identifier("attested observer_spec_id", self.observer_spec_id)
        for name in (
            "public_schedule_sha256",
            "public_schedule_builder_source_sha256",
            "construction_corpus_loader_source_sha256",
            "corpus_sha256",
            "codebook_manifest_sha256",
            "construction_report_sha256",
            "checksums_sha256",
            "codebook_builder_source_sha256",
            "observer_spec_sha256",
            "policy_input_sha256",
            "launcher_source_sha256",
            "corpus_loader_source_sha256",
            "harness_source_sha256",
            "attestation_sha256",
        ):
            _sha256_pin(name, getattr(self, name))
        if self.template_count != CONCRETE_TEMPLATE_COUNT:
            raise LaunchOrderError("attestation template population is not concrete")
        if self.private_codebook_count != CONCRETE_PRIVATE_CODEBOOK_COUNT:
            raise LaunchOrderError("attestation private codebook population is not concrete")
        if self.route_count != 7:
            raise LaunchOrderError("attestation does not bind exact C1--C7 routes")
        if (
            self.public_schedule_sha256 != CONCRETE_PUBLIC_SCHEDULE_SHA256
            or self.public_schedule_builder_source_sha256
            != CONCRETE_PUBLIC_SCHEDULE_BUILDER_SOURCE_SHA256
            or self.construction_corpus_loader_source_sha256
            != CONCRETE_CONSTRUCTION_CORPUS_LOADER_SOURCE_SHA256
            or self.corpus_sha256 != CORPUS_SHA256
            or self.codebook_manifest_id != CONCRETE_CODEBOOK_MANIFEST_ID
            or self.codebook_manifest_sha256 != CONCRETE_CODEBOOK_MANIFEST_SHA256
            or self.construction_report_sha256 != CONCRETE_CODEBOOK_REPORT_SHA256
            or self.checksums_sha256 != CONCRETE_CODEBOOK_CHECKSUMS_SHA256
            or self.codebook_builder_source_sha256
            != CONCRETE_CODEBOOK_BUILDER_SOURCE_SHA256
            or self.corpus_loader_source_sha256
            != CONCRETE_CORPUS_LOADER_SOURCE_SHA256
            or self.harness_source_sha256 != CONCRETE_HARNESS_SOURCE_SHA256
        ):
            raise LaunchOrderError("launch attestation differs from a concrete artifact/source pin")
        expected_events = (
            "public_schedule_authenticated",
            "codebook_artifacts_authenticated",
            "codebook_domain_sealed",
            "public_policy_compiled",
            "protected_corpus_authenticated",
            "scenario_public_projection_rebound",
            "protected_state_attached",
        )
        if self.events != expected_events:
            raise LaunchOrderError("launch attestation event order is not exact")
        observed = hashlib.sha256(
            _canonical_json_bytes(
                self.wire_without_hash(), maximum=MAX_POLICY_JSON_BYTES
            )
        ).hexdigest()
        if self.attestation_sha256 != observed:
            raise LaunchOrderError("launch attestation SHA-256 is inconsistent")

    def wire_without_hash(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "execution_mode": self.execution_mode,
            "scenario_id": self.scenario_id,
            "template_code": self.template_code,
            "public_schedule_sha256": self.public_schedule_sha256,
            "public_schedule_builder_source_sha256": self.public_schedule_builder_source_sha256,
            "construction_corpus_loader_source_sha256": self.construction_corpus_loader_source_sha256,
            "corpus_sha256": self.corpus_sha256,
            "codebook_manifest_id": self.codebook_manifest_id,
            "codebook_manifest_sha256": self.codebook_manifest_sha256,
            "construction_report_sha256": self.construction_report_sha256,
            "checksums_sha256": self.checksums_sha256,
            "codebook_builder_source_sha256": self.codebook_builder_source_sha256,
            "observer_spec_id": self.observer_spec_id,
            "observer_spec_sha256": self.observer_spec_sha256,
            "template_count": self.template_count,
            "private_codebook_count": self.private_codebook_count,
            "route_count": self.route_count,
            "policy_input_sha256": self.policy_input_sha256,
            "launcher_source_sha256": self.launcher_source_sha256,
            "corpus_loader_source_sha256": self.corpus_loader_source_sha256,
            "harness_source_sha256": self.harness_source_sha256,
            "events": list(self.events),
        }

    def to_wire(self) -> dict[str, Any]:
        return {**self.wire_without_hash(), "attestation_sha256": self.attestation_sha256}


@dataclass(frozen=True, slots=True)
class LaunchedScenario:
    scenario: Mapping[str, Any]
    codebooks: SealedTemplateCodebooks
    policy_input: PolicyAuthorInput
    post_seal_handler: PostSealHandler
    attestation: LaunchOrderAttestation
    _launched_token: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._launched_token is not _LAUNCHED_TOKEN:
            raise LaunchOrderError("launched scenarios must come from the isolated session")
        if not isinstance(self.scenario, _MAPPING_PROXY_TYPE):
            raise LaunchOrderError("launched scenario must be an immutable corpus row")
        if type(self.codebooks) is not SealedTemplateCodebooks:
            raise LaunchOrderError("launched scenario lacks sealed codebooks")
        if type(self.policy_input) is not PolicyAuthorInput:
            raise LaunchOrderError("launched scenario lacks its public policy DTO")
        if type(self.post_seal_handler) is not PostSealHandler:
            raise LaunchOrderError("launched scenario lacks its post-seal handler")
        if type(self.attestation) is not LaunchOrderAttestation:
            raise LaunchOrderError("launched scenario lacks its ordering attestation")


class IsolatedLaunchSession:
    """One-shot state machine whose only protected read is the final attach step."""

    __slots__ = (
        "public_schedule_path",
        "codebook_root",
        "corpus_path",
        "scenario_id",
        "_stage",
        "_events",
        "_public_row",
        "_bundle",
        "_codebooks",
        "_policy_input",
        "_scenario",
        "_post_seal_handler",
    )

    def __init__(
        self,
        *,
        public_schedule_path: Path,
        codebook_root: Path,
        corpus_path: Path,
        scenario_id: str,
        _session_token: object,
    ) -> None:
        if _session_token is not _SESSION_TOKEN:
            raise LaunchOrderError("isolated launch sessions require the strict factory")
        self.public_schedule_path = Path(public_schedule_path)
        self.codebook_root = Path(codebook_root)
        self.corpus_path = Path(corpus_path)
        self.scenario_id = _identifier("launch scenario_id", scenario_id)
        self._stage = LaunchStage.CREATED
        self._events: list[str] = []
        self._public_row: Mapping[str, Any] | None = None
        self._bundle: CodebookBundle | None = None
        self._codebooks: SealedTemplateCodebooks | None = None
        self._policy_input: PolicyAuthorInput | None = None
        self._scenario: Mapping[str, Any] | None = None
        self._post_seal_handler: PostSealHandler | None = None

    @classmethod
    def create(
        cls,
        *,
        public_schedule_path: str | Path,
        codebook_root: str | Path,
        corpus_path: str | Path,
        scenario_id: str,
    ) -> "IsolatedLaunchSession":
        return cls(
            public_schedule_path=Path(public_schedule_path),
            codebook_root=Path(codebook_root),
            corpus_path=Path(corpus_path),
            scenario_id=scenario_id,
            _session_token=_SESSION_TOKEN,
        )

    @property
    def stage(self) -> LaunchStage:
        return self._stage

    def _require(self, expected: LaunchStage) -> None:
        if self._stage is not expected:
            raise LaunchOrderError(
                f"launch stage must be {expected.value}, observed {self._stage.value}"
            )

    def authenticate_public_schedule(self) -> None:
        self._require(LaunchStage.CREATED)
        executing_corpus_loader = hashlib.sha256(
            _read_regular_bounded(
                Path(agentleak_module.__file__),
                maximum=2_097_152,
                label="executing AgentLeak corpus loader source",
            )
        ).hexdigest()
        executing_harness = hashlib.sha256(
            _read_regular_bounded(
                Path(fullstack_module.__file__),
                maximum=2_097_152,
                label="executing AgentLeak harness source",
            )
        ).hexdigest()
        if executing_corpus_loader != CONCRETE_CORPUS_LOADER_SOURCE_SHA256:
            raise LaunchOrderError("executing AgentLeak corpus loader source is not pinned")
        if executing_harness != CONCRETE_HARNESS_SOURCE_SHA256:
            raise LaunchOrderError("executing AgentLeak harness source is not pinned")
        executing_builder = hashlib.sha256(
            _read_regular_bounded(
                Path(public_schedule_module.__file__),
                maximum=2_097_152,
                label="executing public schedule builder source",
            )
        ).hexdigest()
        if executing_builder != CONCRETE_PUBLIC_SCHEDULE_BUILDER_SOURCE_SHA256:
            raise LaunchOrderError("executing public schedule builder source is not pinned")
        executing_construction_loader = hashlib.sha256(
            _read_regular_bounded(
                Path(construction_corpus_module.__file__),
                maximum=2_097_152,
                label="executing construction-only corpus loader source",
            )
        ).hexdigest()
        if (
            executing_construction_loader
            != CONCRETE_CONSTRUCTION_CORPUS_LOADER_SOURCE_SHA256
        ):
            raise LaunchOrderError("executing construction-only corpus loader source is not pinned")
        raw = _read_regular_bounded(
            self.public_schedule_path,
            maximum=MAX_SCHEDULE_BYTES,
            label="prior-public launch schedule",
        )
        observed = hashlib.sha256(raw).hexdigest()
        if observed != CONCRETE_PUBLIC_SCHEDULE_SHA256:
            raise LaunchOrderError("public schedule SHA-256 does not match the concrete pin")
        body = _strict_json_loads(raw, maximum=MAX_SCHEDULE_BYTES)
        schedule = _strict_object(body, _SCHEDULE_KEYS, "public launch schedule")
        if _canonical_json_bytes(schedule, maximum=MAX_SCHEDULE_BYTES) != raw:
            raise LaunchOrderError("public launch schedule is not canonical JSON")
        if (
            schedule["schema_version"] != SCHEMA_VERSION
            or schedule["corpus_sha256"] != CORPUS_SHA256
            or schedule["corpus_rows"] != CORPUS_ROWS
            or schedule["schedule_builder_source_sha256"]
            != CONCRETE_PUBLIC_SCHEDULE_BUILDER_SOURCE_SHA256
            or schedule["construction_corpus_loader_source_sha256"]
            != CONCRETE_CONSTRUCTION_CORPUS_LOADER_SOURCE_SHA256
        ):
            raise LaunchOrderError("public launch schedule provenance is inconsistent")
        rows = _strict_sequence(
            "public launch schedule rows",
            schedule["rows"],
            minimum=CORPUS_ROWS,
            maximum=CORPUS_ROWS,
        )
        matches = tuple(
            _strict_object(row, _SCHEDULE_ROW_KEYS, "public launch schedule row")
            for row in rows
            if isinstance(row, Mapping) and row.get("scenario_id") == self.scenario_id
        )
        if len(matches) != 1:
            raise LaunchOrderError("public launch schedule scenario binding is ambiguous")
        frozen = _freeze_json(matches[0])
        if not isinstance(frozen, _MAPPING_PROXY_TYPE):
            raise LaunchOrderError("public launch schedule row did not freeze")
        self._public_row = frozen
        self._events.append("public_schedule_authenticated")
        self._stage = LaunchStage.PUBLIC_SCHEDULE_AUTHENTICATED

    def authenticate_codebooks(self) -> None:
        self._require(LaunchStage.PUBLIC_SCHEDULE_AUTHENTICATED)
        root = self.codebook_root
        executing_builder = hashlib.sha256(
            _read_regular_bounded(
                Path(codebook_module.__file__),
                maximum=2_097_152,
                label="executing codebook builder/loader source",
            )
        ).hexdigest()
        if executing_builder != CONCRETE_CODEBOOK_BUILDER_SOURCE_SHA256:
            raise LaunchOrderError("executing codebook builder/loader source is not pinned")
        try:
            bundle = validate_codebook_construction_artifacts(
                manifest_path=root / "codebook-manifest.json",
                expected_manifest_sha256=CONCRETE_CODEBOOK_MANIFEST_SHA256,
                private_codebook_root=root / "private",
                report_path=root / "construction-report.json",
                expected_report_sha256=CONCRETE_CODEBOOK_REPORT_SHA256,
                checksums_path=root / "SHA256SUMS",
                expected_builder_source_sha256=CONCRETE_CODEBOOK_BUILDER_SOURCE_SHA256,
                expected_construction_loader_source_sha256=(
                    CONCRETE_CONSTRUCTION_CORPUS_LOADER_SOURCE_SHA256
                ),
            )
        except (CodebookBuildError, HarnessError) as exc:
            raise LaunchOrderError("concrete codebook artifacts failed authentication") from exc
        checksum_raw = _read_regular_bounded(
            root / "SHA256SUMS", maximum=MAX_SCHEDULE_BYTES, label="codebook SHA256SUMS"
        )
        if hashlib.sha256(checksum_raw).hexdigest() != CONCRETE_CODEBOOK_CHECKSUMS_SHA256:
            raise LaunchOrderError("codebook SHA256SUMS differs from the concrete pin")
        if (
            bundle.manifest_id != CONCRETE_CODEBOOK_MANIFEST_ID
            or bundle.manifest_sha256 != CONCRETE_CODEBOOK_MANIFEST_SHA256
            or bundle.builder_source_sha256
            != CONCRETE_CODEBOOK_BUILDER_SOURCE_SHA256
            or len(bundle.templates) != CONCRETE_TEMPLATE_COUNT
            or len(bundle._private_entries) != CONCRETE_PRIVATE_CODEBOOK_COUNT
        ):
            raise LaunchOrderError("concrete codebook population is inconsistent")
        self._bundle = bundle
        self._events.append("codebook_artifacts_authenticated")
        self._stage = LaunchStage.CODEBOOKS_AUTHENTICATED

    def seal_domain_and_compile_policy(self) -> None:
        self._require(LaunchStage.CODEBOOKS_AUTHENTICATED)
        assert self._public_row is not None and self._bundle is not None
        template_code = _identifier(
            "public schedule template_code", self._public_row["template_code"]
        )
        binding = self._bundle.template(template_code)
        registrations = tuple(
            RouteRegistration.from_manifest(route) for route in binding.routes
        )
        codebooks = seal_template_codebooks(
            bundle=self._bundle,
            template_code=template_code,
            registrations=registrations,
        )
        if len(codebooks.binding.routes) != 7:
            raise LaunchOrderError("sealed launch domain does not contain exact C1--C7")
        self._codebooks = codebooks
        self._events.append("codebook_domain_sealed")
        self._stage = LaunchStage.DOMAIN_SEALED
        public_scenario = {
            "scenario_id": self._public_row["scenario_id"],
            "objective": self._public_row["objective"],
            "agents": self._public_row["agents"],
            "tools": self._public_row["tools"],
            "allowed_set": {"fields": self._public_row["allowed_field_names"]},
        }
        policy = build_policy_author_input(public_scenario, codebooks=codebooks)
        if policy.template_code != template_code or policy.scenario_id != self.scenario_id:
            raise LaunchOrderError("compiled public policy differs from the launch schedule")
        self._policy_input = policy
        self._events.append("public_policy_compiled")
        self._stage = LaunchStage.PUBLIC_POLICY_COMPILED

    def attach_protected_corpus(self) -> None:
        self._require(LaunchStage.PUBLIC_POLICY_COMPILED)
        assert self._codebooks is not None and self._policy_input is not None
        corpus = load_pinned_corpus(self.corpus_path)
        if corpus.sha256 != CORPUS_SHA256 or len(corpus.scenarios) != CORPUS_ROWS:
            raise LaunchOrderError("protected corpus identity is inconsistent")
        self._events.append("protected_corpus_authenticated")
        matches = tuple(
            scenario
            for scenario in corpus.scenarios
            if scenario["scenario_id"] == self.scenario_id
        )
        if len(matches) != 1:
            raise LaunchOrderError("protected corpus scenario binding is ambiguous")
        scenario = matches[0]
        rebound = build_policy_author_input(scenario, codebooks=self._codebooks)
        if rebound != self._policy_input:
            raise LaunchOrderError("protected scenario public projection differs from frozen policy")
        self._events.append("scenario_public_projection_rebound")
        projection = canonical_allowed_projection(scenario)
        handler = self._codebooks.attach_private_state(allowed_projection=projection)
        self._scenario = scenario
        self._post_seal_handler = handler
        self._events.append("protected_state_attached")
        self._stage = LaunchStage.PROTECTED_STATE_ATTACHED

    def finalize(self) -> LaunchedScenario:
        self._require(LaunchStage.PROTECTED_STATE_ATTACHED)
        assert (
            self._public_row is not None
            and self._bundle is not None
            and self._codebooks is not None
            and self._policy_input is not None
            and self._scenario is not None
            and self._post_seal_handler is not None
        )
        source_raw = _read_regular_bounded(
            Path(__file__), maximum=2_097_152, label="isolated launcher source"
        )
        corpus_loader_raw = _read_regular_bounded(
            Path(agentleak_module.__file__),
            maximum=2_097_152,
            label="AgentLeak corpus loader source",
        )
        harness_raw = _read_regular_bounded(
            Path(fullstack_module.__file__),
            maximum=2_097_152,
            label="AgentLeak harness source",
        )
        policy_digest = hashlib.sha256(
            _canonical_json_bytes(
                self._policy_input.to_wire(), maximum=MAX_POLICY_JSON_BYTES
            )
        ).hexdigest()
        binding = self._codebooks.binding
        body = {
            "schema_version": ATTESTATION_SCHEMA_VERSION,
            "execution_mode": EXECUTION_MODE,
            "scenario_id": self.scenario_id,
            "template_code": binding.template_code,
            "public_schedule_sha256": CONCRETE_PUBLIC_SCHEDULE_SHA256,
            "public_schedule_builder_source_sha256": CONCRETE_PUBLIC_SCHEDULE_BUILDER_SOURCE_SHA256,
            "construction_corpus_loader_source_sha256": CONCRETE_CONSTRUCTION_CORPUS_LOADER_SOURCE_SHA256,
            "corpus_sha256": CORPUS_SHA256,
            "codebook_manifest_id": self._bundle.manifest_id,
            "codebook_manifest_sha256": self._bundle.manifest_sha256,
            "construction_report_sha256": CONCRETE_CODEBOOK_REPORT_SHA256,
            "checksums_sha256": CONCRETE_CODEBOOK_CHECKSUMS_SHA256,
            "codebook_builder_source_sha256": self._bundle.builder_source_sha256,
            "observer_spec_id": binding.observer_spec_id,
            "observer_spec_sha256": binding.observer_spec_sha256,
            "template_count": len(self._bundle.templates),
            "private_codebook_count": len(self._bundle._private_entries),
            "route_count": len(binding.routes),
            "policy_input_sha256": policy_digest,
            "launcher_source_sha256": hashlib.sha256(source_raw).hexdigest(),
            "corpus_loader_source_sha256": hashlib.sha256(corpus_loader_raw).hexdigest(),
            "harness_source_sha256": hashlib.sha256(harness_raw).hexdigest(),
            "events": tuple(self._events),
        }
        digest = hashlib.sha256(
            _canonical_json_bytes(body, maximum=MAX_POLICY_JSON_BYTES)
        ).hexdigest()
        attestation = LaunchOrderAttestation(
            **body,
            attestation_sha256=digest,
            _attestation_token=_ATTESTATION_TOKEN,
        )
        launched = LaunchedScenario(
            scenario=self._scenario,
            codebooks=self._codebooks,
            policy_input=self._policy_input,
            post_seal_handler=self._post_seal_handler,
            attestation=attestation,
            _launched_token=_LAUNCHED_TOKEN,
        )
        self._stage = LaunchStage.FINALIZED
        return launched


def launch_pinned_scenario(
    *,
    public_schedule_path: str | Path,
    codebook_root: str | Path,
    corpus_path: str | Path,
    scenario_id: str,
) -> LaunchedScenario:
    session = IsolatedLaunchSession.create(
        public_schedule_path=public_schedule_path,
        codebook_root=codebook_root,
        corpus_path=corpus_path,
        scenario_id=scenario_id,
    )
    session.authenticate_public_schedule()
    session.authenticate_codebooks()
    session.seal_domain_and_compile_policy()
    session.attach_protected_corpus()
    return session.finalize()


def _main() -> int:
    parser = argparse.ArgumentParser(description="Attest the CPU-only AgentLeak launch order")
    parser.add_argument("--repository-root", required=True)
    parser.add_argument("--scenario-id", required=True)
    arguments = parser.parse_args()
    repository_root = Path(arguments.repository_root).resolve()
    benchmark_root = repository_root / "source" / "artifact" / "benchmarks" / "agentleak"
    launched = launch_pinned_scenario(
        public_schedule_path=benchmark_root / "public_schedule_full_1000_v1.json",
        codebook_root=benchmark_root / "codebooks_full_1000_v1",
        corpus_path=benchmark_root / "scenarios_full_1000.jsonl",
        scenario_id=arguments.scenario_id,
    )
    print(
        _canonical_json_bytes(
            launched.attestation.to_wire(), maximum=MAX_POLICY_JSON_BYTES
        ).decode("ascii")
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())


__all__ = [
    "ATTESTATION_SCHEMA_VERSION",
    "CONCRETE_CODEBOOK_CHECKSUMS_SHA256",
    "CONCRETE_CODEBOOK_MANIFEST_SHA256",
    "CONCRETE_CODEBOOK_REPORT_SHA256",
    "CONCRETE_CONSTRUCTION_CORPUS_LOADER_SOURCE_SHA256",
    "CONCRETE_CORPUS_LOADER_SOURCE_SHA256",
    "CONCRETE_HARNESS_SOURCE_SHA256",
    "CONCRETE_PUBLIC_SCHEDULE_SHA256",
    "IsolatedLaunchSession",
    "LaunchedScenario",
    "LaunchOrderAttestation",
    "LaunchOrderError",
    "LaunchStage",
    "launch_pinned_scenario",
]
