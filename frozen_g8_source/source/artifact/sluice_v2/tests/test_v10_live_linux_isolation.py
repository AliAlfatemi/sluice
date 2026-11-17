"""Live, fail-closed Linux isolation contract for the evaluated topology.

These tests require actual kernel evidence.  A host without the required
primitives may skip the positive launch, but it must still reject strict
startup; configuration intent is never accepted as an attestation.
"""

from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
import signal

import pytest

from sluice_v2.isolation import (
    IsolationStartupError,
    ProcessRole,
    validate_startup,
)
from sluice_v2.linux_isolation import (
    LANDLOCK_REQUIRED_ABI,
    LinuxIsolationConfig,
    ProtectedCanaries,
    launch_live_isolation,
    probe_linux_capabilities,
    validate_linux_capabilities,
)


def _config(tmp_path: Path) -> LinuxIsolationConfig:
    allowed = tmp_path / "model-public"
    private = tmp_path / "trusted-private"
    allowed.mkdir(mode=0o700)
    private.mkdir(mode=0o700)
    public_model = allowed / "model.bin"
    public_model.write_bytes(b"public-model-bytes")

    canary_paths = {}
    for name in ("ledger", "signing_key", "tool_credential", "raw_audit"):
        path = private / name
        path.write_bytes(("owner-readable-" + name).encode("ascii"))
        path.chmod(0o600)
        canary_paths[name] = path

    return LinuxIsolationConfig.strict(
        model_readonly_paths=(allowed,),
        model_allowed_read_probe=public_model,
        protected_canaries=ProtectedCanaries(
            ledger=canary_paths["ledger"],
            signing_key=canary_paths["signing_key"],
            tool_credential=canary_paths["tool_credential"],
            raw_audit=canary_paths["raw_audit"],
        ),
        model_environment_allowlist=frozenset({"LANG", "PATH"}),
    )


def test_strict_capability_validation_refuses_every_missing_kernel_control():
    detected = probe_linux_capabilities()

    for field in (
        "linux",
        "user_namespace",
        "network_namespace",
        "landlock_abi",
        "no_new_privileges",
        "unix_seqpacket",
        "unix_peer_credentials",
    ):
        missing_value = 0 if field == "landlock_abi" else False
        with pytest.raises(IsolationStartupError, match=field):
            validate_linux_capabilities(replace(detected, **{field: missing_value}))


def test_live_launcher_attests_enforced_three_process_boundary(tmp_path: Path):
    capabilities = probe_linux_capabilities()
    if not capabilities.supports_strict:
        pytest.skip("host lacks strict Linux isolation controls")

    config = _config(tmp_path)
    expected_environment = tuple(
        sorted(set(os.environ).intersection(config.model_environment_allowlist))
    )
    with launch_live_isolation(config) as run:
        attestation = run.attestation

        assert capabilities.landlock_abi >= LANDLOCK_REQUIRED_ABI
        validate_startup(config.manifest, attestation.enforcement_report)
        attestation.topology.validate_live_and_distinct()
        assert len(set(attestation.topology.pids.values())) == 3
        assert os.getpid() not in attestation.topology.pids.values()

        assert attestation.model_net_namespace != attestation.parent_net_namespace
        assert attestation.broker_net_namespace != attestation.parent_net_namespace
        assert attestation.model_user_namespace != attestation.parent_user_namespace
        assert attestation.broker_user_namespace != attestation.parent_user_namespace
        assert attestation.model_landlock_abi >= LANDLOCK_REQUIRED_ABI
        assert attestation.broker_landlock_abi >= LANDLOCK_REQUIRED_ABI
        assert attestation.model_no_new_privileges
        assert attestation.broker_no_new_privileges

        assert attestation.model_environment_names == expected_environment
        assert attestation.environment_exact
        assert attestation.model_allowed_read_succeeded
        assert attestation.model_allowed_write_denied
        assert attestation.model_network_probe_denied
        assert attestation.model_direct_broker_probe_denied
        assert attestation.protected_canary_denials == {
            "ledger": True,
            "raw_audit": True,
            "signing_key": True,
            "tool_credential": True,
        }

        assert attestation.model_ipc_schema_verified
        assert attestation.broker_ipc_schema_verified
        assert attestation.broker_allowlist_denial_observed
        assert attestation.broker_allowed_command_observed
        assert attestation.broker_replay_denial_observed
        assert attestation.model_descriptor_allowlist_exact
        assert attestation.broker_descriptor_allowlist_exact
        assert attestation.peer_pid_checks == {
            "broker_observed_monitor": attestation.topology.pids[ProcessRole.MONITOR],
            "model_observed_monitor": attestation.topology.pids[ProcessRole.MONITOR],
            "monitor_observed_broker": attestation.topology.pids[ProcessRole.EFFECT_BROKER],
            "monitor_observed_model": attestation.topology.pids[ProcessRole.MODEL],
        }
        assert set(attestation.peer_uid_gid_checks.values()) == {
            (os.getuid(), os.getgid())
        }

        # Attestation is public evidence.  It contains denial booleans, not
        # canary locations, contents, private capability tokens, or raw IPC.
        public_evidence = json.dumps(attestation.to_wire(), sort_keys=True)
        for path in config.protected_canaries.as_mapping().values():
            assert str(path) not in public_evidence
            assert path.read_text() not in public_evidence
        assert "launch-cap-" not in public_evidence


def test_config_rejects_a_protected_canary_under_a_model_read_root(tmp_path: Path):
    config = _config(tmp_path)

    with pytest.raises(ValueError, match="protected|allowed"):
        replace(config, model_readonly_paths=(tmp_path,))


@pytest.mark.parametrize(
    "loader_name",
    [
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "LD_AUDIT",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "LIBPATH",
        "SHLIB_PATH",
        "LDR_PRELOAD",
        "_RLD_LIST",
    ],
)
def test_config_rejects_cross_platform_dynamic_loader_environment(
    tmp_path: Path, loader_name: str
):
    config = _config(tmp_path)

    with pytest.raises(ValueError, match="dynamic-loader|environment"):
        replace(config, model_environment_allowlist=frozenset({loader_name}))


def test_unexpected_child_crash_reaps_the_remaining_topology(tmp_path: Path):
    capabilities = probe_linux_capabilities()
    if not capabilities.supports_strict:
        pytest.skip("host lacks strict Linux isolation controls")

    run = launch_live_isolation(_config(tmp_path))
    pids = dict(run.attestation.topology.pids)
    try:
        os.kill(pids[ProcessRole.MODEL], signal.SIGKILL)
        crashed = run.wait_for_crash_cleanup(timeout=10.0)
        assert crashed is ProcessRole.MODEL
        assert run.live_pids() == ()
        for pid in pids.values():
            with pytest.raises(ProcessLookupError):
                os.kill(pid, 0)
    finally:
        run.close()
