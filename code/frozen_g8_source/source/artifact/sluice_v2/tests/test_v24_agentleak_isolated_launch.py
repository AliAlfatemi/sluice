from __future__ import annotations

import ast
from collections.abc import Mapping
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys

import pytest

import sluice_v2.evaluation.agentleak_isolated_launch as launch_module
import sluice_v2.evaluation.agentleak_public_schedule as schedule_module
from sluice_v2.evaluation.agentleak import load_pinned_corpus
from sluice_v2.evaluation.agentleak_construction_corpus import (
    construction_loader_source_sha256,
    load_public_schedule_construction_corpus,
    project_public_schedule_row as project_construction_public_schedule_row,
)
from sluice_v2.evaluation.agentleak_isolated_launch import (
    CONCRETE_CODEBOOK_CHECKSUMS_SHA256,
    CONCRETE_CODEBOOK_MANIFEST_SHA256,
    CONCRETE_CODEBOOK_REPORT_SHA256,
    CONCRETE_CONSTRUCTION_CORPUS_LOADER_SOURCE_SHA256,
    CONCRETE_CORPUS_LOADER_SOURCE_SHA256,
    CONCRETE_HARNESS_SOURCE_SHA256,
    CONCRETE_PUBLIC_SCHEDULE_SHA256,
    IsolatedLaunchSession,
    LaunchOrderError,
    LaunchStage,
    launch_pinned_scenario,
)
from sluice_v2.evaluation.agentleak_public_schedule import (
    PublicScheduleBuildError,
    build_public_schedule,
    build_public_schedule_document,
    project_public_schedule_row,
)


ARTIFACT_ROOT = Path(__file__).resolve().parents[2]
REPOSITORY_ROOT = ARTIFACT_ROOT.parents[1]
BENCHMARK_ROOT = ARTIFACT_ROOT / "benchmarks" / "agentleak"
CORPUS_PATH = BENCHMARK_ROOT / "scenarios_full_1000.jsonl"
SCHEDULE_PATH = BENCHMARK_ROOT / "public_schedule_full_1000_v1.json"
CODEBOOK_ROOT = BENCHMARK_ROOT / "codebooks_full_1000_v1"
EXPECTED_EVENTS = (
    "public_schedule_authenticated",
    "codebook_artifacts_authenticated",
    "codebook_domain_sealed",
    "public_policy_compiled",
    "protected_corpus_authenticated",
    "scenario_public_projection_rebound",
    "protected_state_attached",
)


def _scenario_id() -> str:
    return json.loads(SCHEDULE_PATH.read_text(encoding="utf-8"))["rows"][0][
        "scenario_id"
    ]


def _session() -> IsolatedLaunchSession:
    return IsolatedLaunchSession.create(
        public_schedule_path=SCHEDULE_PATH,
        codebook_root=CODEBOOK_ROOT,
        corpus_path=CORPUS_PATH,
        scenario_id=_scenario_id(),
    )


def test_concrete_bundle_launch_is_exact_cpu_only_and_attested() -> None:
    launched = launch_pinned_scenario(
        public_schedule_path=SCHEDULE_PATH,
        codebook_root=CODEBOOK_ROOT,
        corpus_path=CORPUS_PATH,
        scenario_id=_scenario_id(),
    )
    attestation = launched.attestation
    assert attestation.execution_mode == "cpu_order_attestation_only"
    assert attestation.events == EXPECTED_EVENTS
    assert attestation.codebook_manifest_sha256 == CONCRETE_CODEBOOK_MANIFEST_SHA256
    assert attestation.construction_report_sha256 == CONCRETE_CODEBOOK_REPORT_SHA256
    assert attestation.checksums_sha256 == CONCRETE_CODEBOOK_CHECKSUMS_SHA256
    assert attestation.public_schedule_sha256 == CONCRETE_PUBLIC_SCHEDULE_SHA256
    assert (
        attestation.construction_corpus_loader_source_sha256
        == CONCRETE_CONSTRUCTION_CORPUS_LOADER_SOURCE_SHA256
    )
    assert attestation.template_count == 16
    assert attestation.private_codebook_count == 112
    assert attestation.route_count == 7
    assert attestation.corpus_loader_source_sha256 == CONCRETE_CORPUS_LOADER_SOURCE_SHA256
    assert attestation.harness_source_sha256 == CONCRETE_HARNESS_SOURCE_SHA256
    assert CONCRETE_CONSTRUCTION_CORPUS_LOADER_SOURCE_SHA256 == hashlib.sha256(
        Path(
            sys.modules[
                "sluice_v2.evaluation.agentleak_construction_corpus"
            ].__file__
        ).read_bytes()
    ).hexdigest()
    assert launched.policy_input.scenario_id == launched.scenario["scenario_id"]
    assert launched.policy_input.observer_spec_sha256 == attestation.observer_spec_sha256


def test_reversed_repeated_and_ambiguous_launch_order_fails_closed() -> None:
    session = _session()
    with pytest.raises(LaunchOrderError, match="PUBLIC_SCHEDULE_AUTHENTICATED"):
        session.authenticate_codebooks()
    with pytest.raises(LaunchOrderError, match="PUBLIC_POLICY_COMPILED"):
        session.attach_protected_corpus()
    session.authenticate_public_schedule()
    with pytest.raises(LaunchOrderError, match="CREATED"):
        session.authenticate_public_schedule()
    session.authenticate_codebooks()
    with pytest.raises(LaunchOrderError, match="PUBLIC_SCHEDULE_AUTHENTICATED"):
        session.authenticate_codebooks()
    session.seal_domain_and_compile_policy()
    session.attach_protected_corpus()
    with pytest.raises(LaunchOrderError, match="PUBLIC_POLICY_COMPILED"):
        session.attach_protected_corpus()
    session.finalize()
    with pytest.raises(LaunchOrderError, match="PROTECTED_STATE_ATTACHED"):
        session.finalize()


def test_secret_corpus_is_not_opened_until_domain_and_policy_are_compiled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _session()
    original = launch_module.load_pinned_corpus
    observed = []

    def guarded_open(path):
        observed.append(session.stage)
        assert session.stage is LaunchStage.PUBLIC_POLICY_COMPILED
        return original(path)

    monkeypatch.setattr(launch_module, "load_pinned_corpus", guarded_open)
    session.authenticate_public_schedule()
    session.authenticate_codebooks()
    session.seal_domain_and_compile_policy()
    assert observed == []
    session.attach_protected_corpus()
    assert observed == [LaunchStage.PUBLIC_POLICY_COMPILED]


def test_public_schedule_projection_has_no_secret_or_outcome_data_path() -> None:
    scenario = {
            "scenario_id": "public-schedule-poison",
            "objective": {
                "user_request": "summarize allowed records",
                "privacy_instruction": "exclude secrets",
                "success_criteria": ["summary_complete"],
            },
            "agents": [{"agent_id": "A1", "role": "coordinator"}],
            "tools": [
                {
                    "tool_name": "private_lookup",
                    "capabilities": ["read"],
                    "requires_clearance": "restricted",
                }
            ],
            "allowed_set": {"fields": ["name"], "forbidden_fields": ["secret"]},
            "private_vault": object(),
            "attack": object(),
            "evaluation": object(),
            "condition": object(),
    }
    row = project_public_schedule_row(scenario)
    rendered = json.dumps(row, sort_keys=True)
    assert "vault" not in rendered.lower()
    assert "attack" not in rendered.lower()
    assert "evaluation" not in rendered.lower()
    assert "forbidden" not in rendered.lower()
    assert "condition" not in rendered.lower()


class AccessPoisonMapping(Mapping):
    def __init__(self, permitted, forbidden=()):
        self._permitted = dict(permitted)
        self._forbidden = frozenset(forbidden)
        self.accessed = []

    def __getitem__(self, key):
        self.accessed.append(key)
        if key in self._forbidden:
            raise AssertionError(f"forbidden schedule-construction access: {key}")
        return self._permitted[key]

    def __iter__(self):
        raise AssertionError("schedule projector must not enumerate a source mapping")

    def __len__(self):
        return len(self._permitted)


def test_construction_schedule_projection_never_touches_protected_or_outcome_subobjects() -> None:
    source = AccessPoisonMapping(
        {
            "scenario_id": "public-schedule-construction-poison",
            "objective": AccessPoisonMapping(
                {
                    "user_request": "summarize allowed records",
                    "privacy_instruction": "exclude secrets",
                    "success_criteria": ["summary_complete"],
                },
                forbidden={"outcome"},
            ),
            "agents": [
                AccessPoisonMapping(
                    {"agent_id": "A1", "role": "coordinator"},
                    forbidden={"private_state"},
                )
            ],
            "tools": [
                AccessPoisonMapping(
                    {
                        "tool_name": "private_lookup",
                        "capabilities": ["read"],
                        "requires_clearance": "restricted",
                    },
                    forbidden={"runtime_secret"},
                )
            ],
            "allowed_set": AccessPoisonMapping(
                {"fields": ["name"]}, forbidden={"forbidden_fields"}
            ),
        },
        forbidden={
            "private_vault",
            "attack",
            "evaluation",
            "condition",
            "target_channels",
            "detector",
            "outcome",
        },
    )
    projected = project_construction_public_schedule_row(source)
    assert projected == {
        "scenario_id": "public-schedule-construction-poison",
        "objective": {
            "user_request": "summarize allowed records",
            "privacy_instruction": "exclude secrets",
            "success_criteria": ["summary_complete"],
        },
        "agents": [{"agent_id": "A1", "role": "coordinator"}],
        "tools": [
            {
                "tool_name": "private_lookup",
                "capabilities": ["read"],
                "requires_clearance": "restricted",
            }
        ],
        "allowed_set": {"fields": ["name"]},
    }
    assert not (
        set(source.accessed)
        & {
            "private_vault",
            "attack",
            "evaluation",
            "condition",
            "target_channels",
            "detector",
            "outcome",
        }
    )


def test_concrete_public_schedule_exactly_rebuilds_from_pinned_corpus() -> None:
    source_digest = hashlib.sha256(Path(schedule_module.__file__).read_bytes()).hexdigest()
    rebuilt = build_public_schedule_document(
        load_public_schedule_construction_corpus(CORPUS_PATH).rows,
        builder_source_sha256=source_digest,
        construction_loader_source_sha256=construction_loader_source_sha256(),
    )
    assert rebuilt == SCHEDULE_PATH.read_bytes()
    assert hashlib.sha256(rebuilt).hexdigest() == CONCRETE_PUBLIC_SCHEDULE_SHA256


@pytest.mark.parametrize("replacement_kind", ("symlink", "directory"))
def test_public_schedule_parent_replacement_fails_without_redirection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    replacement_kind: str,
) -> None:
    parent = tmp_path / "parent"
    parent.mkdir()
    moved = tmp_path / "moved"
    redirect = tmp_path / "redirect"
    redirect.mkdir()
    output = parent / "schedule.json"
    original_open = schedule_module.os.open
    swapped = False

    def racing_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal swapped
        if (
            not swapped
            and dir_fd is not None
            and Path(path) == Path(output.name)
            and flags & os.O_CREAT
        ):
            swapped = True
            parent.rename(moved)
            if replacement_kind == "symlink":
                parent.symlink_to(redirect, target_is_directory=True)
            else:
                parent.mkdir()
        if dir_fd is None:
            return original_open(path, flags, mode)
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(schedule_module.os, "open", racing_open)
    with pytest.raises(PublicScheduleBuildError, match="parent identity changed"):
        build_public_schedule(corpus_path=CORPUS_PATH, output_path=output)
    assert swapped
    assert (moved / output.name).is_file()
    assert not (redirect / output.name).exists()
    if replacement_kind == "directory":
        assert not (parent / output.name).exists()


def test_public_schedule_rejects_preexisting_output_and_requires_mode_0600(
    tmp_path: Path,
) -> None:
    output = tmp_path / "schedule.json"
    digest = build_public_schedule(corpus_path=CORPUS_PATH, output_path=output)
    original = output.read_bytes()
    assert hashlib.sha256(original).hexdigest() == digest
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    with pytest.raises(PublicScheduleBuildError, match="already exists"):
        build_public_schedule(corpus_path=CORPUS_PATH, output_path=output)
    assert output.read_bytes() == original


def test_public_schedule_rejects_output_path_replacement_without_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "schedule.json"
    displaced = tmp_path / "displaced.json"
    replacement = b"attacker replacement"
    original_fsync = schedule_module.os.fsync
    swapped = False

    def racing_fsync(descriptor):
        nonlocal swapped
        original_fsync(descriptor)
        if not swapped and stat.S_ISREG(os.fstat(descriptor).st_mode):
            swapped = True
            output.rename(displaced)
            output.write_bytes(replacement)

    monkeypatch.setattr(schedule_module.os, "fsync", racing_fsync)
    with pytest.raises(PublicScheduleBuildError, match="output file identity"):
        build_public_schedule(corpus_path=CORPUS_PATH, output_path=output)
    assert swapped
    assert output.read_bytes() == replacement
    assert displaced.is_file()


def test_public_schedule_rejects_hardlinked_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "schedule.json"
    alias = tmp_path / "schedule-hardlink.json"
    original_fsync = schedule_module.os.fsync
    linked = False

    def racing_fsync(descriptor):
        nonlocal linked
        original_fsync(descriptor)
        if not linked and stat.S_ISREG(os.fstat(descriptor).st_mode):
            linked = True
            os.link(output, alias)

    monkeypatch.setattr(schedule_module.os, "fsync", racing_fsync)
    with pytest.raises(PublicScheduleBuildError, match="output file identity"):
        build_public_schedule(corpus_path=CORPUS_PATH, output_path=output)
    assert linked
    assert output.is_file() and alias.is_file()
    assert os.stat(output).st_ino == os.stat(alias).st_ino


def test_public_schedule_fails_when_required_secure_primitive_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "schedule.json"
    monkeypatch.delattr(schedule_module.os, "O_CLOEXEC")
    with pytest.raises(PublicScheduleBuildError, match="primitives are unavailable"):
        build_public_schedule(corpus_path=CORPUS_PATH, output_path=output)
    assert not output.exists()


def test_schedule_source_has_no_secret_projection_reference_and_launcher_has_one_gated_open() -> None:
    schedule_tree = ast.parse(Path(schedule_module.__file__).read_text(encoding="utf-8"))
    projector = next(
        node
        for node in schedule_tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "project_public_schedule_row"
    )
    forbidden = {
        "private_vault",
        "attack",
        "evaluation",
        "condition",
        "forbidden_fields",
        "target_channels",
        "canaries",
    }
    observed = set()
    for node in ast.walk(projector):
        if isinstance(node, ast.Name):
            observed.add(node.id)
        elif isinstance(node, ast.Attribute):
            observed.add(node.attr)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            observed.add(node.value)
    assert not (forbidden & observed)
    assert "load_pinned_corpus" not in Path(schedule_module.__file__).read_text(
        encoding="utf-8"
    )

    launcher_tree = ast.parse(Path(launch_module.__file__).read_text(encoding="utf-8"))
    calls = []
    for node in ast.walk(launcher_tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id == "load_pinned_corpus":
                calls.append(node)
    assert len(calls) == 1
    attach = next(
        node
        for node in ast.walk(launcher_tree)
        if isinstance(node, ast.FunctionDef) and node.name == "attach_protected_corpus"
    )
    assert calls[0] in tuple(ast.walk(attach))


def test_public_schedule_and_codebook_hash_drift_fail_before_corpus_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tampered = tmp_path / "public-schedule.json"
    tampered.write_bytes(SCHEDULE_PATH.read_bytes() + b"\n")
    session = IsolatedLaunchSession.create(
        public_schedule_path=tampered,
        codebook_root=CODEBOOK_ROOT,
        corpus_path=CORPUS_PATH,
        scenario_id=_scenario_id(),
    )
    monkeypatch.setattr(
        launch_module,
        "load_pinned_corpus",
        lambda path: pytest.fail("protected corpus opened before public pin rejection"),
    )
    with pytest.raises(LaunchOrderError, match="public schedule SHA-256"):
        session.authenticate_public_schedule()

    tampered_codebooks = tmp_path / "codebooks"
    shutil.copytree(CODEBOOK_ROOT, tampered_codebooks)
    manifest = tampered_codebooks / "codebook-manifest.json"
    manifest.write_bytes(manifest.read_bytes() + b"\n")
    codebook_session = IsolatedLaunchSession.create(
        public_schedule_path=SCHEDULE_PATH,
        codebook_root=tampered_codebooks,
        corpus_path=CORPUS_PATH,
        scenario_id=_scenario_id(),
    )
    codebook_session.authenticate_public_schedule()
    with pytest.raises(LaunchOrderError, match="codebook artifacts"):
        codebook_session.authenticate_codebooks()


def test_cli_attestation_is_independent_process_deterministic() -> None:
    command = [
        sys.executable,
        "-m",
        "sluice_v2.evaluation.agentleak_isolated_launch",
        "--repository-root",
        str(REPOSITORY_ROOT),
        "--scenario-id",
        _scenario_id(),
    ]
    environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONHASHSEED="8675309")
    first = subprocess.run(
        command,
        cwd=ARTIFACT_ROOT,
        env=environment,
        text=True,
        capture_output=True,
        check=True,
    )
    second = subprocess.run(
        command,
        cwd=ARTIFACT_ROOT,
        env=environment,
        text=True,
        capture_output=True,
        check=True,
    )
    assert first.stdout == second.stdout
    body = json.loads(first.stdout)
    assert tuple(body["events"]) == EXPECTED_EVENTS
