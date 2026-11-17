"""Independent fail-first probes for the live-isolation and formal gates.

This file is intentionally tests-only.  Each test states a security property
that is not established by the original focused green suites.
"""

from __future__ import annotations

from dataclasses import replace
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import sys
import time

import pytest

from sluice_v2.formal_trace import (
    MAX_INTEGER,
    AbstractTransitionV1,
    FormalManifest,
    FormalTraceChecker,
    FormalTraceError,
    canonical_json_line,
)
from sluice_v2.linux_isolation import (
    LinuxIsolationConfig,
    ProtectedCanaries,
    _close_unneeded_fds,
    _descriptor_allowlist_exact,
    _harden_process,
)


ARTIFACT_ROOT = Path(__file__).resolve().parents[2]
FROZEN_MANIFEST = ARTIFACT_ROOT / "formal" / "SluiceSecureTraceManifest.json"
ATTESTATION_DRIVER = ARTIFACT_ROOT / "experiments" / "attest_linux_isolation.py"
TRACE_ID = "formalAudit_20260820_AA"


def _manifest() -> FormalManifest:
    return FormalManifest.from_bytes(FROZEN_MANIFEST.read_bytes())


def _continue(
    manifest: FormalManifest,
    *,
    step: int,
    attempts_before: int,
    attempts_after: int,
    visible_after: int | None = None,
) -> AbstractTransitionV1:
    if visible_after is None:
        visible_after = attempts_after
    before_spent = attempts_before
    after_spent = attempts_after
    return AbstractTransitionV1(
        schema_version=1,
        config_sha256=manifest.config_sha256,
        trace_id=TRACE_ID,
        step=step,
        action="continue",
        outcome="continued",
        domain_slot=0,
        scope_slot=None,
        gate_slot=None,
        agent_slot=None,
        nonce_slot=None,
        delegation_slot=None,
        reauth_grant_slot=None,
        capability_slot=None,
        redeemer_slot=None,
        predecessor_gate_slot=None,
        epoch_before=0,
        epoch_after=0,
        epoch_spent_before=(before_spent, 0),
        epoch_spent_after=(after_spent, 0),
        attempts_before=attempts_before,
        attempts_after=attempts_after,
        horizon_before=3,
        horizon_after=3,
        lifetime_spent_before=before_spent,
        lifetime_spent_after=after_spent,
        lifetime_budget_before=3,
        lifetime_budget_after=3,
        visible_events_before=attempts_before,
        visible_events_after=visible_after,
        closed_before=False,
        closed_after=False,
        gate_claim_delta=0,
        nonce_use_delta=0,
        delegation_use_delta=0,
        reauth_use_delta=0,
        capability_use_delta=0,
        audit_start_delta=0,
        padding_event_delta=0,
        authorization_version_before=0,
        authorization_version_after=0,
    )


def _isolation_config(tmp_path: Path) -> LinuxIsolationConfig:
    public = tmp_path / "public"
    private = tmp_path / "private"
    public.mkdir()
    private.mkdir()
    probe = public / "model.bin"
    probe.write_bytes(b"public")
    protected = {}
    for name in ("ledger", "signing_key", "tool_credential", "raw_audit"):
        path = private / name
        path.write_bytes(("canary-" + name).encode("ascii"))
        protected[name] = path
    return LinuxIsolationConfig.strict(
        model_readonly_paths=(public,),
        model_allowed_read_probe=probe,
        protected_canaries=ProtectedCanaries(
            ledger=protected["ledger"],
            signing_key=protected["signing_key"],
            tool_credential=protected["tool_credential"],
            raw_audit=protected["raw_audit"],
        ),
        model_environment_allowlist=frozenset({"LANG", "PATH"}),
    )


def test_standard_input_is_not_an_implicit_landlock_bypass(tmp_path: Path):
    """An arbitrary inherited fd 0 must not be called an exact safe inventory."""

    secret = tmp_path / "ledger-secret"
    secret.write_bytes(b"RAW-LEDGER-CONTENT")
    result_read, result_write = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(result_read)
            source = os.open(secret, os.O_RDONLY)
            os.dup2(source, 0)
            if source != 0:
                os.close(source)
            _close_unneeded_fds(frozenset({result_write}))
            leaked = os.read(0, 64) == b"RAW-LEDGER-CONTENT"
            called_exact = _descriptor_allowlist_exact(frozenset({result_write}))
            os.write(result_write, bytes((int(leaked), int(called_exact))))
        finally:
            os._exit(0)
    os.close(result_write)
    result = os.read(result_read, 2)
    os.close(result_read)
    waited, status = os.waitpid(pid, 0)
    assert waited == pid and os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
    assert result == b"\x00\x00", (
        "the model bootstrap retains a readable private fd on stdin and its "
        "descriptor attestation still reports an exact allowlist"
    )


def test_strict_exec_environment_rejects_dynamic_loader_injection(tmp_path: Path):
    """The trusted pre-sandbox bootstrap cannot permit LD_PRELOAD injection."""

    config = _isolation_config(tmp_path)
    with pytest.raises(ValueError, match="environment|LD_PRELOAD|loader"):
        replace(config, model_environment_allowlist=frozenset({"LD_PRELOAD"}))


def test_parent_death_before_pdeathsig_registration_cannot_orphan_a_role():
    """PR_SET_PDEATHSIG is racy unless the original parent is rechecked."""

    pid_read, pid_write = os.pipe()
    status_read, status_write = os.pipe()
    launcher = os.fork()
    if launcher == 0:
        os.close(pid_read)
        os.close(status_read)
        child = os.fork()
        if child == 0:
            os.close(pid_write)
            original_parent = os.getppid()
            deadline = time.monotonic() + 5.0
            while os.getppid() == original_parent and time.monotonic() < deadline:
                time.sleep(0.005)
            _harden_process()
            os.write(status_write, b"orphan-survived")
            time.sleep(5.0)
            os._exit(0)
        os.write(pid_write, str(child).encode("ascii"))
        os._exit(0)

    os.close(pid_write)
    os.close(status_write)
    child_pid = int(os.read(pid_read, 64).decode("ascii"))
    os.close(pid_read)
    os.waitpid(launcher, 0)
    try:
        readable, _, _ = select.select([status_read], [], [], 2.0)
        evidence = os.read(status_read, 64) if readable else b""
        assert evidence != b"orphan-survived", (
            "a role survives when its launcher dies immediately before "
            "PR_SET_PDEATHSIG registration"
        )
    finally:
        os.close(status_read)
        try:
            os.kill(child_pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def _load_attestation_driver():
    spec = importlib.util.spec_from_file_location(
        "sluice_attestation_driver_under_audit", ATTESTATION_DRIVER
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_attestation_binds_preexecution_sources_and_all_local_trust_dependencies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """A post-run hash can name bytes different from those that were executed."""

    module = _load_attestation_driver()
    fake_artifact = tmp_path / "artifact"
    fake_experiments = fake_artifact / "experiments"
    fake_package = fake_artifact / "sluice_v2"
    fake_tests = fake_package / "tests"
    fake_experiments.mkdir(parents=True)
    fake_tests.mkdir(parents=True)
    fake_driver = fake_experiments / "attest_linux_isolation.py"
    fake_driver.write_bytes(b"driver-before\n")
    sources = {
        "sluice_v2/linux_isolation.py": b"implementation-before\n",
        "sluice_v2/isolation.py": b"schema-before\n",
        "sluice_v2/observer.py": b"observer-before\n",
        "sluice_v2/tests/test_v10_live_linux_isolation.py": b"contract-before\n",
        "experiments/attest_linux_isolation.py": b"driver-before\n",
    }
    for relative, content in sources.items():
        path = fake_artifact / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    pre_hashes = {
        name: hashlib.sha256(content).hexdigest() for name, content in sources.items()
    }

    class FakeAttestation:
        def to_wire(self):
            return {"synthetic": True}

    class FakeRun:
        attestation = FakeAttestation()

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            # This models a source replacement while the attested run is in
            # flight.  A sound binder either hashes first and checks again or
            # executes an already-hashed immutable copy.
            (fake_package / "linux_isolation.py").write_bytes(
                b"implementation-after\n"
            )

        def live_pids(self):
            return ()

    output = tmp_path / "attestation.json"
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.setattr(module, "__file__", str(fake_driver))
    monkeypatch.setattr(module, "launch_live_isolation", lambda _config: FakeRun())
    monkeypatch.setattr(
        sys,
        "argv",
        [str(fake_driver), "--work-dir", str(work), "--output", str(output)],
    )

    assert module.main() == 0
    evidence = json.loads(output.read_text(encoding="ascii"))
    assert evidence["source_sha256"] == pre_hashes


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", 2),
        ("trace_id", "x"),
        ("step", True),
        ("domain_slot", False),
    ],
)
def test_incremental_accept_revalidates_direct_transition_objects(field, value):
    """The exported object API must enforce the same schema as JSONL parsing."""

    manifest = _manifest()
    transition = replace(_continue(manifest, step=1, attempts_before=0, attempts_after=1), **{field: value})
    with pytest.raises(FormalTraceError):
        FormalTraceChecker(manifest).accept(transition)


def test_rejected_incremental_transition_cannot_leave_hidden_checker_state():
    manifest = _manifest()
    checker = FormalTraceChecker(manifest)
    invalid = _continue(
        manifest,
        step=1,
        attempts_before=0,
        attempts_after=1,
        visible_after=0,
    )
    with pytest.raises(FormalTraceError, match="visible_events_after"):
        checker.accept(invalid)

    # This one-line trace is only valid from attempts=1.  It must not pass by
    # inheriting the uncommitted mutation made while rejecting ``invalid``.
    hidden_suffix = _continue(
        manifest,
        step=1,
        attempts_before=1,
        attempts_after=2,
    )
    with pytest.raises(FormalTraceError):
        checker.check_bytes(hidden_suffix.to_wire())


def test_manifest_epoch_dimension_has_a_finite_allocation_bound():
    """A tiny manifest must not amplify into a 2^63-element state vector."""

    mapping = json.loads(FROZEN_MANIFEST.read_text(encoding="utf-8"))
    mapping["max_epoch"] = MAX_INTEGER
    with pytest.raises(FormalTraceError, match="max_epoch|dimension|bound"):
        FormalManifest.from_bytes(canonical_json_line(mapping))
