"""Adversarial contracts for the Rocky-8 rootless GPU isolation fallback.

The positive contracts are intended to run on the Rocky GPU nodes.  Pure
configuration and wire-schema contracts also run on hosts where user
namespaces or NVIDIA character devices are unavailable.
"""

from __future__ import annotations

import ctypes
from copy import deepcopy
from dataclasses import replace
import errno
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import sys

import pytest

import sluice_v2.rocky_gpu_isolation as isolation

from sluice_v2.rocky_gpu_isolation import (
    AuthenticatedBind,
    GPUDevice,
    ProtectedHostPaths,
    RockyGPUIsolationConfig,
    RockyIsolationError,
    RockyIsolationUnavailable,
    RockyLiveCapabilityReport,
    canonical_config_sha256,
    launch_rocky_gpu_isolation,
    sha256_file,
    sha256_tree,
    validate_live_capabilities,
)


_LIBC = ctypes.CDLL(None, use_errno=True)
_LIBC.shmget.argtypes = (ctypes.c_int, ctypes.c_size_t, ctypes.c_int)
_LIBC.shmget.restype = ctypes.c_int
_LIBC.shmat.argtypes = (ctypes.c_int, ctypes.c_void_p, ctypes.c_int)
_LIBC.shmat.restype = ctypes.c_void_p
_LIBC.shmdt.argtypes = (ctypes.c_void_p,)
_LIBC.shmdt.restype = ctypes.c_int
_LIBC.shmctl.argtypes = (ctypes.c_int, ctypes.c_int, ctypes.c_void_p)
_LIBC.shmctl.restype = ctypes.c_int
_IPC_PRIVATE = 0
_IPC_CREAT = 0o1000
_IPC_RMID = 0
_SHMAT_FAILED = ctypes.c_void_p(-1).value


def _worker_sha256() -> str:
    import sluice_v2.rocky_gpu_isolation as module

    return sha256_file(Path(module.__file__))


def _interpreter_sha256() -> str:
    return sha256_file(Path(os.readlink("/proc/self/exe")))


def _device_sources() -> tuple[Path, ...]:
    required = (Path("/dev/nvidiactl"), Path("/dev/nvidia-uvm"), Path("/dev/nvidia0"))
    if not all(path.exists() for path in required):
        pytest.skip("the strict Rocky GPU contract requires nvidiactl, UVM, and GPU 0")
    return required


def _fixture_config(tmp_path: Path) -> RockyGPUIsolationConfig:
    runtime = tmp_path / "runtime"
    source = tmp_path / "source"
    cache = tmp_path / "cache"
    private = tmp_path / "private"
    home = tmp_path / "shared-home"
    for directory in (runtime, source, cache, private, home):
        directory.mkdir(mode=0o700)
    (runtime / "runtime.probe").write_bytes(b"runtime-public")
    (source / "source.probe").write_bytes(b"source-public")
    (cache / "cache.probe").write_bytes(b"cache-public")
    canaries = {}
    for name in ("ledger", "signing_key", "tool_credential", "raw_audit"):
        path = private / name
        path.write_bytes(("private-" + name).encode("ascii"))
        path.chmod(0o600)
        canaries[name] = path
    home_canary = home / "private-home-canary"
    home_canary.write_bytes(b"private-home")
    home_canary.chmod(0o600)

    binds = (
        AuthenticatedBind(
            label="runtime",
            category="runtime",
            source=runtime,
            target="/opt/sluice/runtime",
            expected_sha256=sha256_tree(runtime),
            probe_relative="runtime.probe",
            allow_exec=True,
        ),
        AuthenticatedBind(
            label="model_source",
            category="model_source",
            source=source,
            target="/opt/sluice/model_source",
            expected_sha256=sha256_tree(source),
            probe_relative="source.probe",
            allow_exec=False,
        ),
        AuthenticatedBind(
            label="model_cache",
            category="model_cache",
            source=cache,
            target="/opt/sluice/model_cache",
            expected_sha256=sha256_tree(cache),
            probe_relative="cache.probe",
            allow_exec=False,
        ),
    )
    devices = tuple(GPUDevice.from_host(path) for path in _device_sources())
    return RockyGPUIsolationConfig.strict(
        binds=binds,
        devices=devices,
        protected_host_paths=ProtectedHostPaths(
            shared_home=home_canary,
            ledger=canaries["ledger"],
            signing_key=canaries["signing_key"],
            tool_credential=canaries["tool_credential"],
            raw_audit=canaries["raw_audit"],
        ),
        worker_source_sha256=_worker_sha256(),
        interpreter_sha256=_interpreter_sha256(),
        workload_environment={
            "CUDA_VISIBLE_DEVICES": "0",
            "HF_HUB_OFFLINE": "1",
            "HOME": "/nonexistent",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": "/opt/sluice/runtime/bin",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONHASHSEED": "0",
            "PYTHONPYCACHEPREFIX": "/tmp/sluice-pycache-v24fixture",
            "TOKENIZERS_PARALLELISM": "false",
            "TRANSFORMERS_OFFLINE": "1",
        },
        root_parent=Path("/tmp"),
    )


def test_capability_validator_rejects_each_missing_kernel_control():
    valid = RockyLiveCapabilityReport(
        linux=True,
        x86_64=True,
        user_namespace=True,
        mount_namespace=True,
        network_namespace=True,
        ipc_namespace=True,
        pid_namespace=True,
        namespace_pid_one=True,
        private_mount_propagation=True,
        tmpfs_root=True,
        chroot=True,
        no_new_privileges=True,
        capabilities_empty=True,
        seccomp_filter=True,
        unix_seqpacket=True,
        unix_peer_credentials=True,
        exact_gpu_devices=True,
    )
    validate_live_capabilities(valid)
    for field in valid.__dataclass_fields__:
        with pytest.raises(RockyIsolationUnavailable, match=field):
            validate_live_capabilities(replace(valid, **{field: False}))


def test_public_config_and_capability_gates_reject_subclasses() -> None:
    class BindSubclass(AuthenticatedBind):
        pass

    class DeviceSubclass(GPUDevice):
        pass

    class ProtectedSubclass(ProtectedHostPaths):
        pass

    class ConfigSubclass(RockyGPUIsolationConfig):
        pass

    class CapabilitySubclass(RockyLiveCapabilityReport):
        pass

    common = {
        "interpreter_sha256": "1" * 64,
        "root_parent": Path("/tmp"),
        "worker_source_sha256": "0" * 64,
        "workload_environment": {},
    }
    exact_bind = object.__new__(AuthenticatedBind)
    exact_protected = object.__new__(ProtectedHostPaths)
    with pytest.raises(TypeError, match="binds"):
        RockyGPUIsolationConfig(
            binds=(object.__new__(BindSubclass),),
            devices=(),
            protected_host_paths=exact_protected,
            **common,
        )
    with pytest.raises(TypeError, match="devices"):
        RockyGPUIsolationConfig(
            binds=(exact_bind,),
            devices=(object.__new__(DeviceSubclass),),
            protected_host_paths=exact_protected,
            **common,
        )
    with pytest.raises(TypeError, match="protected_host_paths"):
        RockyGPUIsolationConfig(
            binds=(exact_bind,),
            devices=(),
            protected_host_paths=object.__new__(ProtectedSubclass),
            **common,
        )

    config_subclass = object.__new__(ConfigSubclass)
    with pytest.raises(TypeError, match="config"):
        canonical_config_sha256(config_subclass)
    with pytest.raises(TypeError, match="config"):
        launch_rocky_gpu_isolation(config_subclass)
    with pytest.raises(TypeError, match="report"):
        validate_live_capabilities(object.__new__(CapabilitySubclass))


def _minimal_config_wire() -> dict[str, object]:
    return {
        "allow_cuda_diagnostic": False,
        "binds": [],
        "cuda_preload_paths": [],
        "devices": [],
        "interpreter_sha256": "1" * 64,
        "protected_host_paths": {},
        "root_parent": "/tmp",
        "root_tmpfs_bytes": 268435456,
        "schema_version": isolation.SCHEMA_VERSION,
        "startup_timeout_seconds": 180.0,
        "worker_source_sha256": "0" * 64,
        "workload_environment": {},
    }


@pytest.mark.parametrize("alias", (2.0, "2"))
def test_config_wire_rejects_schema_version_type_aliases(alias: object) -> None:
    wire = _minimal_config_wire()
    wire["schema_version"] = alias
    with pytest.raises(ValueError, match="schema"):
        RockyGPUIsolationConfig.from_wire(wire)


def test_wire_paths_reject_aliases_before_path_normalization() -> None:
    bind_wire = {
        "allow_exec": False,
        "category": "support",
        "expected_sha256": "0" * 64,
        "label": "support",
        "probe_relative": ".",
        "source": "/tmp/./support",
        "source_chain_identity": [],
        "source_fd": 3,
        "source_identity": {},
        "target": "/opt/sluice/support/item",
    }
    with pytest.raises(ValueError, match="canonical|source"):
        AuthenticatedBind.from_wire(bind_wire)

    with pytest.raises(ValueError, match="canonical|source"):
        GPUDevice.from_wire(
            {
                "major": 195,
                "minor": 0,
                "source": "/dev/./nvidia0",
                "target": "/dev/nvidia0",
            }
        )

    for target_alias in ("/dev/./nvidia0", "/dev//nvidia0"):
        with pytest.raises(ValueError, match="canonical|target"):
            GPUDevice.from_wire(
                {
                    "major": 195,
                    "minor": 0,
                    "source": "/dev/nvidia0",
                    "target": target_alias,
                }
            )

    protected = {
        "shared_home": "/home/./canary",
        "ledger": "/private/ledger",
        "signing_key": "/private/signing_key",
        "tool_credential": "/private/tool_credential",
        "raw_audit": "/private/raw_audit",
    }
    with pytest.raises(ValueError, match="canonical|shared_home"):
        ProtectedHostPaths.from_wire(protected)

    config_wire = _minimal_config_wire()
    config_wire["root_parent"] = "/tmp/./"
    with pytest.raises(ValueError, match="root_parent|canonical"):
        RockyGPUIsolationConfig.from_wire(config_wire)

    config_wire = _minimal_config_wire()
    config_wire["cuda_preload_paths"] = [
        "/opt/sluice/support/./libcuda.so.1"
    ]
    with pytest.raises(ValueError, match="preload|canonical"):
        RockyGPUIsolationConfig.from_wire(config_wire)


def test_recursive_json_equality_rejects_bool_and_float_aliases() -> None:
    expected = {"flag": True, "nested": [{"count": 1}]}
    assert isolation._exact_json_equal(deepcopy(expected), expected)
    assert not isolation._exact_json_equal(
        {"flag": 1, "nested": [{"count": 1}]}, expected
    )
    assert not isolation._exact_json_equal(
        {"flag": True, "nested": [{"count": 1.0}]}, expected
    )


def test_strict_config_requires_every_gpu_control_device(tmp_path: Path):
    config = _fixture_config(tmp_path)
    for required in ("nvidiactl", "nvidia-uvm", "nvidia0"):
        retained = tuple(device for device in config.devices if device.target.name != required)
        with pytest.raises(ValueError, match=required):
            replace(config, devices=retained)


def test_config_rejects_secret_or_loader_environment(tmp_path: Path):
    config = _fixture_config(tmp_path)
    for name in ("HF_TOKEN", "AWS_SECRET_ACCESS_KEY", "LD_PRELOAD", "PYTHONPATH"):
        environment = dict(config.workload_environment)
        environment[name] = "attacker-controlled"
        with pytest.raises(ValueError, match="environment|loader|secret"):
            replace(config, workload_environment=environment)


def test_config_rejects_broad_or_host_namespace_targets(tmp_path: Path):
    config = _fixture_config(tmp_path)
    original = config.binds[0]
    for target in ("/", "/u", "/home", "/proc", "/sys", "/dev", "/etc"):
        with pytest.raises(ValueError, match="target|category"):
            replace(config, binds=(replace(original, target=target),) + config.binds[1:])


def test_config_rejects_a_bind_covering_any_protected_host_path(tmp_path: Path):
    config = _fixture_config(tmp_path)
    private_root = config.protected_host_paths.ledger.parent
    dangerous = AuthenticatedBind(
        label="dangerous_support",
        category="support",
        source=private_root,
        target="/opt/sluice/support/private",
        expected_sha256=sha256_tree(private_root),
        probe_relative="ledger",
        allow_exec=False,
    )
    with pytest.raises(ValueError, match="protected"):
        replace(config, binds=config.binds + (dangerous,))


def test_config_rejects_a_hardlink_alias_of_a_protected_file(tmp_path: Path):
    config = _fixture_config(tmp_path)
    alias = config.binds[1].source / "apparently-public"
    os.link(config.protected_host_paths.ledger, alias)
    aliased_source = replace(
        config.binds[1],
        expected_sha256=sha256_tree(config.binds[1].source),
    )
    with pytest.raises(ValueError, match="protected|alias"):
        replace(config, binds=(config.binds[0], aliased_source, config.binds[2]))


def test_tree_digest_is_path_and_content_bound_and_refuses_escaping_symlinks(tmp_path: Path):
    tree = tmp_path / "tree"
    tree.mkdir()
    item = tree / "item"
    item.write_bytes(b"before")
    before = sha256_tree(tree)
    item.write_bytes(b"after")
    assert sha256_tree(tree) != before

    outside = tmp_path / "outside"
    outside.write_bytes(b"private")
    (tree / "escape").symlink_to(outside)
    with pytest.raises(ValueError, match="symlink|escape"):
        sha256_tree(tree)


def test_authenticated_bind_rejects_same_bytes_root_replacement(tmp_path: Path):
    source = tmp_path / "runtime"
    source.mkdir(mode=0o700)
    probe = source / "probe"
    probe.write_bytes(b"same-bytes")
    probe.chmod(0o600)
    expected = sha256_tree(source)
    bind = AuthenticatedBind(
        label="runtime",
        category="runtime",
        source=source,
        target="/opt/sluice/runtime",
        expected_sha256=expected,
        probe_relative="probe",
        allow_exec=True,
    )
    detached = tmp_path / "detached-original"
    source.rename(detached)
    source.mkdir(mode=0o700)
    replacement = source / "probe"
    replacement.write_bytes(b"same-bytes")
    replacement.chmod(0o600)
    assert sha256_tree(source) == expected
    with pytest.raises(RockyIsolationError, match="identity|pinned"):
        isolation._digest_source_fd(bind)


def test_mount_uses_lexical_source_then_immediately_crossbinds_retained_fd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "runtime-file"
    source.write_bytes(b"retained-mount-source")
    source.chmod(0o600)
    bind = AuthenticatedBind(
        label="runtime_file",
        category="support",
        source=source,
        target="/opt/sluice/support/runtime-file",
        expected_sha256=sha256_file(source),
        probe_relative=".",
        allow_exec=False,
    )
    calls: list[tuple[str | None, str, int]] = []

    def emulate_bind(
        source_text: str | None,
        target_text: str,
        filesystem: str | None,
        flags: int,
        data: str | None = None,
    ) -> None:
        del data
        calls.append((source_text, filesystem or "", flags))
        target = Path(target_text)
        target.unlink()
        os.link(source, target)

    monkeypatch.setattr(isolation, "_mount", emulate_bind)
    try:
        target = isolation._mount_authenticated_source(tmp_path / "root", bind)
        assert (target.stat().st_dev, target.stat().st_ino) == (
            os.fstat(bind.source_fd).st_dev,
            os.fstat(bind.source_fd).st_ino,
        )
        assert calls == [(os.fspath(source), "", isolation._MS_BIND)]
        assert "/proc/self/fd/" not in calls[0][0]
        assert not (calls[0][2] & isolation._MS_REC)
    finally:
        os.close(bind.source_fd)


def test_mount_window_same_bytes_replacement_fails_before_remount_or_use(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "runtime-file"
    source.write_bytes(b"identical-content")
    source.chmod(0o600)
    expected = sha256_file(source)
    bind = AuthenticatedBind(
        label="runtime_file",
        category="support",
        source=source,
        target="/opt/sluice/support/runtime-file",
        expected_sha256=expected,
        probe_relative=".",
        allow_exec=False,
    )
    calls: list[tuple[str | None, int]] = []

    def replace_during_mount(
        source_text: str | None,
        target_text: str,
        filesystem: str | None,
        flags: int,
        data: str | None = None,
    ) -> None:
        del filesystem, data
        calls.append((source_text, flags))
        detached = tmp_path / "detached-original"
        source.rename(detached)
        source.write_bytes(b"identical-content")
        source.chmod(0o600)
        assert sha256_file(source) == expected
        target = Path(target_text)
        target.unlink()
        os.link(source, target)

    monkeypatch.setattr(isolation, "_mount", replace_during_mount)
    try:
        with pytest.raises(RockyIsolationError, match="retained|identity|cross-bound"):
            isolation._mount_authenticated_source(tmp_path / "root", bind)
        assert calls == [(os.fspath(source), isolation._MS_BIND)]
    finally:
        os.close(bind.source_fd)


def test_namespaced_rebound_accepts_only_uid_gid_translation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "runtime"
    source.mkdir(mode=0o700)
    probe = source / "probe"
    probe.write_bytes(b"namespace-stable")
    expected = sha256_tree(source)
    bind = AuthenticatedBind(
        label="runtime",
        category="runtime",
        source=source,
        target="/opt/sluice/runtime",
        expected_sha256=expected,
        probe_relative="probe",
        allow_exec=True,
    )
    original_open = isolation._open_source_chain

    def remapped_open(path: Path, name: str):
        descriptor, chain, identity = original_open(path, name)
        remapped_chain = tuple(
            dict(item, uid=item["uid"] + 1000, gid=item["gid"] + 1000)
            for item in chain
        )
        remapped_identity = dict(
            identity,
            uid=identity["uid"] + 1000,
            gid=identity["gid"] + 1000,
        )
        return descriptor, remapped_chain, remapped_identity

    monkeypatch.setattr(isolation, "_open_source_chain", remapped_open)
    try:
        assert isolation._digest_source_fd_after_unshare(bind) == expected
        detached = tmp_path / "detached-original"
        source.rename(detached)
        source.mkdir(mode=0o700)
        replacement = source / "probe"
        replacement.write_bytes(b"namespace-stable")
        replacement_fd, _replacement_chain, _replacement_identity = original_open(
            source, "replacement source"
        )
        try:
            assert isolation._sha256_tree_fd(replacement_fd) == expected
        finally:
            os.close(replacement_fd)
        with pytest.raises(RockyIsolationError, match="identity|pinned"):
            isolation._digest_source_fd_after_unshare(bind)
    finally:
        os.close(bind.source_fd)


def test_namespaced_execution_identity_accepts_only_uid_gid_translation() -> None:
    expected = [11, 22, 200, 200, 0o755, 1, 4096]
    mapped = [11, 22, 0, 0, 0o755, 1, 4096]
    assert not isolation._verified_execution_identity_equal(
        expected, mapped, after_unshare=False
    )
    assert isolation._verified_execution_identity_equal(
        expected, mapped, after_unshare=True
    )
    for index in (0, 1, 4, 5, 6):
        changed = list(mapped)
        changed[index] += 1
        assert not isolation._verified_execution_identity_equal(
            expected, changed, after_unshare=True
        )


def test_authenticated_bind_closes_new_descriptor_on_late_validation_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    source = tmp_path / "runtime"
    source.mkdir(mode=0o700)
    probe = source / "probe"
    probe.write_bytes(b"descriptor-lifetime")
    expected = sha256_tree(source)
    observed: dict[str, int] = {}
    original = isolation._open_source_chain

    def capture(path: Path, name: str):
        descriptor, chain, identity = original(path, name)
        observed["descriptor"] = descriptor
        return descriptor, chain, identity

    monkeypatch.setattr(isolation, "_open_source_chain", capture)
    with pytest.raises(ValueError, match="target"):
        AuthenticatedBind(
            label="runtime",
            category="runtime",
            source=source,
            target="/forbidden",
            expected_sha256=expected,
            probe_relative="probe",
            allow_exec=True,
        )
    with pytest.raises(OSError) as error:
        os.fstat(observed["descriptor"])
    assert error.value.errno == errno.EBADF


@pytest.mark.skipif(os.name != "posix" or not Path("/proc/self/exe").exists(), reason="requires Linux procfs")
def test_proc_self_exe_pin_has_exact_shared_schema_and_revalidates() -> None:
    descriptor, wire = isolation._pin_proc_self_exe(_interpreter_sha256())
    try:
        assert isolation._revalidate_proc_self_exe(descriptor, wire) == wire
    finally:
        os.close(descriptor)
    assert set(wire) == {"identity", "path", "procfs_mount", "sha256"}
    assert wire["sha256"] == _interpreter_sha256()
    assert wire["procfs_mount"]["filesystem"] == "proc"
    assert wire["procfs_mount"]["mountpoint"] == "/proc"
    for mutation in (
        "extra",
        "bool_mount_id",
        "wrong_filesystem",
        "dot_path",
        "double_root_path",
    ):
        changed = deepcopy(wire)
        if mutation == "extra":
            changed["procfs_mount"]["extra"] = False
        elif mutation == "bool_mount_id":
            changed["procfs_mount"]["mount_id"] = True
        elif mutation == "wrong_filesystem":
            changed["procfs_mount"]["filesystem"] = "sysfs"
        elif mutation == "dot_path":
            original = Path(changed["path"])
            changed["path"] = f"{original.parent}/./{original.name}"
        else:
            changed["path"] = "//" + str(changed["path"]).lstrip("/")
        with pytest.raises(ValueError):
            isolation._exact_interpreter_pin_wire(changed)


def test_proc_magic_link_exception_does_not_allow_ordinary_source_symlink(
    tmp_path: Path,
) -> None:
    source = tmp_path / "worker.py"
    source.write_bytes(b"VALUE = 1\n")
    alias = tmp_path / "worker-alias.py"
    alias.symlink_to(source)
    with pytest.raises(OSError) as error:
        isolation._open_source_chain(alias, "ordinary project source")
    assert error.value.errno == errno.ELOOP


def test_worker_preimport_loader_uses_only_posix_seek_primitives() -> None:
    source = isolation._worker_inline_source("0" * 64, "1" * 64)
    assert source.startswith("import posix as os,sys\n")
    assert "os.SEEK_SET" not in source
    assert source.count("os.lseek(fd,0,0)") == 1
    assert source.count("os.lseek(interpreter_fd,0,0)") == 1
    compile(source, "<rocky-worker-inline-loader>", "exec", dont_inherit=True)


def test_canonical_config_hash_binds_order_paths_digests_devices_and_environment(tmp_path: Path):
    config = _fixture_config(tmp_path)
    baseline = canonical_config_sha256(config)
    assert len(baseline) == 64
    changed_env = dict(config.workload_environment)
    changed_env["PYTHONHASHSEED"] = "1"
    assert canonical_config_sha256(replace(config, workload_environment=changed_env)) != baseline
    assert canonical_config_sha256(replace(config, binds=tuple(reversed(config.binds)))) != baseline


def test_live_worker_enforces_root_filesystem_network_device_env_fd_and_seccomp_contracts(
    tmp_path: Path,
):
    config = _fixture_config(tmp_path)
    with launch_rocky_gpu_isolation(config) as run:
        evidence = run.attestation.to_wire()
        validate_live_capabilities(run.attestation.capabilities)
        assert evidence["config_sha256"] == canonical_config_sha256(config)
        assert evidence["worker_source_sha256"] == config.worker_source_sha256
        assert evidence["interpreter_sha256"] == config.interpreter_sha256
        assert evidence["interpreter_pin"]["sha256"] == config.interpreter_sha256
        assert evidence["interpreter_pin"]["procfs_mount"]["filesystem"] == "proc"
        assert evidence["environment"] == dict(sorted(config.workload_environment.items()))
        assert evidence["descriptors_exact"]
        assert evidence["standard_descriptors_null"]
        assert evidence["network_connect_denied"]
        assert evidence["socket_creation_denied"]
        assert evidence["mount_after_drop_denied"]
        assert evidence["pdeathsig_change_denied"]
        assert evidence["pdeathsig_kill"]
        assert evidence["dumpable_change_denied"]
        assert evidence["ptrace_denied"]
        assert evidence["pidfd_open_denied"]
        assert evidence["proc_absent"]
        assert evidence["etc_passwd_absent"]
        assert evidence["protected_denials"] == {
            "ledger": True,
            "raw_audit": True,
            "shared_home": True,
            "signing_key": True,
            "tool_credential": True,
        }
        assert all(item["readonly"] and item["read_probe"] for item in evidence["binds"])
        assert {item["target"] for item in evidence["devices"]} == {
            str(device.target) for device in config.devices
        }
        assert evidence["device_directory_exact"]
        assert evidence["challenge_sha256"] == hashlib.sha256(run.challenge).hexdigest()
        assert set(evidence["namespace_before"]) == {"user", "mnt", "net", "ipc", "pid"}
        assert set(evidence["namespace_after"]) == {"user", "mnt", "net", "ipc", "pid"}
        assert all(
            evidence["namespace_before"][name] != evidence["namespace_after"][name]
            for name in evidence["namespace_before"]
        )
        assert evidence["pid"] == 1
        assert evidence["namespace_init"]["namespace_pid"] == 1
        assert evidence["namespace_init"]["nspid"][-1] == 1
        assert run.init_host_pid in evidence["namespace_init"]["nspid"]
        assert evidence["namespace_init"]["supervisor_host_pid"] == run.process.pid
        assert run.process.pid != run.init_host_pid

        serialized = json.dumps(evidence, sort_keys=True)
        for path in config.protected_host_paths.as_mapping().values():
            assert str(path) not in serialized
            assert path.read_text() not in serialized

    final = run.final_attestation
    assert final is not None
    assert final["config_sha256"] == canonical_config_sha256(config)
    assert final["bind_end_sha256"] == {
        bind.label: bind.expected_sha256 for bind in config.binds
    }
    assert run.namespace_cleanup_confirmed


def test_ready_attestation_rejects_numeric_and_boolean_aliases(tmp_path: Path):
    config = _fixture_config(tmp_path)
    with launch_rocky_gpu_isolation(config) as run:
        evidence = run.attestation.to_wire()
        arguments = {
            "expected_interpreter_pin": evidence["interpreter_pin"],
            "expected_init_host_pid": run.init_host_pid,
            "expected_supervisor_host_pid": run.process.pid,
            "expected_launcher_pid": evidence["peer"]["pid"],
            "expected_namespaces": evidence["namespace_after"],
            "challenge": run.challenge,
        }
        isolation._validate_ready_packet(
            {"attestation": deepcopy(evidence), "type": "ready"},
            config,
            **arguments,
        )
        mutations = []
        changed = deepcopy(evidence)
        changed["schema_version"] = float(isolation.SCHEMA_VERSION)
        mutations.append(changed)
        changed = deepcopy(evidence)
        changed["worker_bootstrap_flags"]["isolated"] = 1
        mutations.append(changed)
        changed = deepcopy(evidence)
        changed["root"]["tmpfs"] = 1
        mutations.append(changed)
        changed = deepcopy(evidence)
        changed["rlimits"]["core"][0] = False
        mutations.append(changed)
        changed = deepcopy(evidence)
        changed["rlimits"]["nofile"][0] = float(
            changed["rlimits"]["nofile"][0]
        )
        mutations.append(changed)
        changed = deepcopy(evidence)
        changed["namespace_init"]["namespace_pid"] = True
        mutations.append(changed)
        changed = deepcopy(evidence)
        changed["namespace_init"]["supervisor_host_pid"] = float(
            changed["namespace_init"]["supervisor_host_pid"]
        )
        mutations.append(changed)
        changed = deepcopy(evidence)
        changed["peer"]["pid"] = float(changed["peer"]["pid"])
        mutations.append(changed)
        changed = deepcopy(evidence)
        changed["binds"][0]["read_probe"] = 1
        mutations.append(changed)
        changed = deepcopy(evidence)
        changed["devices"][0]["major"] = float(changed["devices"][0]["major"])
        mutations.append(changed)

        for aliased in mutations:
            with pytest.raises(RockyIsolationError):
                isolation._validate_ready_packet(
                    {"attestation": aliased, "type": "ready"},
                    config,
                    **arguments,
                )


def test_live_launch_fails_closed_on_authenticated_source_drift(tmp_path: Path):
    config = _fixture_config(tmp_path)
    changed = config.binds[1].source / "source.probe"
    changed.write_bytes(b"source-changed-after-freeze")
    with pytest.raises(RockyIsolationError, match="authentication|digest|bootstrap"):
        launch_rocky_gpu_isolation(config)


def test_final_attestation_fails_if_host_side_bind_changes_during_run(tmp_path: Path):
    config = _fixture_config(tmp_path)
    run = launch_rocky_gpu_isolation(config)
    (config.binds[2].source / "cache.probe").write_bytes(b"host-side-mutation")
    with pytest.raises(RockyIsolationError, match="failed closed|digest|channel"):
        run.close()
    assert run.final_attestation is None


def test_final_attestation_rejects_boolean_integer_alias(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Channel:
        @staticmethod
        def close() -> None:
            return None

    class Process:
        returncode = 0

        @staticmethod
        def poll() -> int:
            return 0

        @staticmethod
        def wait(timeout: float) -> int:
            assert timeout == 10.0
            return 0

    root_path = tmp_path / "root"
    pycache_path = tmp_path / "pycache"
    root_path.mkdir()
    pycache_path.mkdir()
    config = type(
        "SyntheticConfig",
        (),
        {
            "binds": (),
            "interpreter_sha256": "1" * 64,
            "worker_source_sha256": "2" * 64,
        },
    )()
    run = object.__new__(isolation.RockySandboxRun)
    run._closed = False
    run._channel = Channel()
    run._root_path = root_path
    run._bootstrap_pycache_path = pycache_path
    run.config = config
    run.challenge = b"exact-final-packet"
    run.process = Process()
    run.init_host_pid = 4321
    run.final_attestation = None
    run.namespace_cleanup_confirmed = False
    run._wait_pid_absent = lambda _pid: True
    monkeypatch.setattr(isolation, "send_packet", lambda _channel, _wire: None)
    monkeypatch.setattr(
        isolation, "canonical_config_sha256", lambda _config: "3" * 64
    )
    monkeypatch.setattr(
        isolation,
        "recv_packet",
        lambda _channel: {
            "bind_end_sha256": {},
            "challenge_sha256": hashlib.sha256(run.challenge).hexdigest(),
            "config_sha256": "3" * 64,
            "interpreter_end_sha256": "1" * 64,
            "pycache_prefix_empty": 1,
            "type": "final",
            "worker_source_end_sha256": "2" * 64,
        },
    )
    with pytest.raises(RockyIsolationError, match="final digest"):
        run.close()
    assert run._closed
    assert run.final_attestation is None


@pytest.mark.skipif(
    sys.platform != "linux", reason="requires Linux AF_UNIX SOCK_SEQPACKET"
)
def test_wire_transport_rejects_oversize_or_noncanonical_payloads(tmp_path: Path):
    # This public helper exercises the same bounded canonical packet schema as
    # the launcher without creating namespaces.
    from sluice_v2.rocky_gpu_isolation import recv_packet, send_packet

    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        with pytest.raises(ValueError, match="finite|canonical|object"):
            send_packet(left, {"value": float("nan")})
        left.send(b"[]")
        with pytest.raises(ValueError, match="object"):
            recv_packet(right)
    finally:
        left.close()
        right.close()


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("posix_shm_errno", True),
        ("posix_shm_errno", 0),
        ("same_uid_signal_errno", False),
        ("same_uid_signal_errno", errno.EACCES),
        ("sysv_shm_errno", 1.0),
        ("sysv_shm_errno", -1),
    ),
)
def test_host_isolation_result_rejects_errno_aliases_and_unlisted_values(
    monkeypatch: pytest.MonkeyPatch, field: str, value: object
) -> None:
    result = {
        "host_pid_invisible": True,
        "posix_shm_denied": True,
        "posix_shm_errno": errno.ENOENT,
        "same_uid_signal_denied": True,
        "same_uid_signal_errno": errno.ESRCH,
        "sysv_shm_denied": True,
        "sysv_shm_errno": errno.EINVAL,
    }
    result[field] = value
    run = object.__new__(isolation.RockySandboxRun)
    run._closed = False
    run._channel = object()
    monkeypatch.setattr(isolation, "send_packet", lambda _channel, _wire: None)
    monkeypatch.setattr(
        isolation,
        "recv_packet",
        lambda _channel: {"result": result, "type": "host_isolation_result"},
    )
    with pytest.raises(RockyIsolationError, match="errno"):
        run.host_isolation_probe(
            victim_pid=12345,
            sysv_shmid=678,
            posix_shm_name="/sluice-hostile",
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("supervisor_host_pid", True),
        ("supervisor_host_pid", 4321.0),
        ("init_host_pid", False),
        ("init_host_pid", 4322.0),
    ),
)
def test_supervisor_topology_rejects_pid_type_aliases(
    field: str, value: object
) -> None:
    topology = {
        "init_host_pid": 4322,
        "namespace_expected": {
            name: f"{name}:[1]" for name in isolation._NAMESPACE_NAMES
        },
        "supervisor_host_pid": 4321,
        "type": "namespace_supervisor",
    }
    topology[field] = value
    with pytest.raises(RockyIsolationError, match="PID"):
        isolation._validate_supervisor_topology_packet(
            topology,
            (4321, os.getuid(), os.getgid()),
            expected_supervisor_pid=4321,
        )


def _descendant_reap_result() -> dict[str, object]:
    return {
        "direct_namespace_pid": 2,
        "direct_status": {"exit_code": 17, "signal": 0},
        "grandchild_namespace_pid": 3,
        "grandchild_status": {"exit_code": 23, "signal": 0},
        "namespace_init_pid": 1,
        "no_children_remaining": True,
    }


def _run_descendant_reap_result(
    monkeypatch: pytest.MonkeyPatch, result: dict[str, object]
) -> dict[str, object]:
    run = object.__new__(isolation.RockySandboxRun)
    run._closed = False
    run._channel = object()
    monkeypatch.setattr(isolation, "send_packet", lambda _channel, _wire: None)
    monkeypatch.setattr(
        isolation,
        "recv_packet",
        lambda _channel: {"result": result, "type": "descendant_reap_result"},
    )
    return run.descendant_reap_diagnostic()


def test_descendant_reap_result_accepts_only_the_frozen_exact_schema(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = _descendant_reap_result()
    assert _run_descendant_reap_result(monkeypatch, expected) == expected


@pytest.mark.parametrize(
    "mutation",
    (
        "extra",
        "init_bool",
        "direct_float",
        "grandchild_bool",
        "direct_status_float",
        "grandchild_status_bool",
        "status_extra",
        "remaining_int",
    ),
)
def test_descendant_reap_result_rejects_aliases_and_extra_keys(
    monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    result = _descendant_reap_result()
    if mutation == "extra":
        result["unexpected"] = False
    elif mutation == "init_bool":
        result["namespace_init_pid"] = True
    elif mutation == "direct_float":
        result["direct_namespace_pid"] = 2.0
    elif mutation == "grandchild_bool":
        result["grandchild_namespace_pid"] = True
    elif mutation == "direct_status_float":
        result["direct_status"]["exit_code"] = 17.0
    elif mutation == "grandchild_status_bool":
        result["grandchild_status"]["signal"] = False
    elif mutation == "status_extra":
        result["direct_status"]["unexpected"] = 0
    else:
        result["no_children_remaining"] = 1
    with pytest.raises(RockyIsolationError, match="descendant reaping"):
        _run_descendant_reap_result(monkeypatch, result)


def test_lingering_descendant_packet_rejects_numeric_alias(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = object.__new__(isolation.RockySandboxRun)
    run._channel = object()
    run.init_host_pid = 5000
    run.process = type("Process", (), {"pid": 5001})()
    monkeypatch.setattr(
        isolation,
        "_recv_packet_with_credentials",
        lambda _channel: (
            {
                "mode": "crash",
                "namespace_pid": 2.0,
                "type": "lingering_descendant",
            },
            (5002, os.getuid(), os.getgid()),
        ),
    )
    with pytest.raises(RockyIsolationError, match="packet"):
        run._receive_lingering_descendant("crash")


def test_namespace_crash_armed_packet_rejects_numeric_alias(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = object.__new__(isolation.RockySandboxRun)
    run._closed = False
    run._channel = object()
    run.init_host_pid = 5000
    run._receive_lingering_descendant = lambda _mode: 5002
    monkeypatch.setattr(isolation, "send_packet", lambda _channel, _wire: None)
    monkeypatch.setattr(
        isolation,
        "_recv_packet_with_credentials",
        lambda _channel: (
            {"child_namespace_pid": 2.0, "type": "namespace_crash_armed"},
            (5000, os.getuid(), os.getgid()),
        ),
    )
    with pytest.raises(RockyIsolationError, match="arming packet"):
        run.crash_cleanup_diagnostic()


@pytest.mark.skipif(
    sys.platform != "linux", reason="requires Linux PID and SysV IPC namespaces"
)
def test_live_pid_and_ipc_namespaces_hide_dedicated_host_probes(tmp_path: Path):
    """Regression for the preserved same-UID signal and SysV attach failures."""

    victim = subprocess.Popen(
        ["/bin/sleep", "300"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
    )
    secret = secrets.token_bytes(32)
    ctypes.set_errno(0)
    shmid = _LIBC.shmget(_IPC_PRIVATE, 4096, _IPC_CREAT | 0o600)
    if shmid < 0:
        raise OSError(ctypes.get_errno(), "test shmget failed")
    address = _LIBC.shmat(shmid, None, 0)
    if address == _SHMAT_FAILED:
        _LIBC.shmctl(shmid, _IPC_RMID, None)
        raise OSError(ctypes.get_errno(), "test shmat failed")
    ctypes.memmove(address, secret, len(secret))
    _LIBC.shmdt(address)
    posix_name = "/sluice-" + secrets.token_hex(16)
    posix_path = Path("/dev/shm") / posix_name.removeprefix("/")
    descriptor = os.open(
        posix_path,
        os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_CLOEXEC,
        0o600,
    )
    try:
        os.write(descriptor, secret)
    finally:
        os.close(descriptor)

    try:
        config = _fixture_config(tmp_path)
        with launch_rocky_gpu_isolation(config) as run:
            result = run.host_isolation_probe(
                victim_pid=victim.pid,
                sysv_shmid=shmid,
                posix_shm_name=posix_name,
            )
            assert result["host_pid_invisible"]
            assert result["same_uid_signal_denied"]
            assert result["same_uid_signal_errno"] == errno.ESRCH
            assert result["sysv_shm_denied"]
            assert result["posix_shm_denied"]
            assert victim.poll() is None
            assert posix_path.read_bytes() == secret
        assert run.namespace_cleanup_confirmed
    finally:
        if victim.poll() is None:
            victim.terminate()
            victim.wait(timeout=5.0)
        _LIBC.shmctl(shmid, _IPC_RMID, None)
        posix_path.unlink(missing_ok=True)


def test_namespace_pid_one_reaps_direct_and_orphaned_descendants(tmp_path: Path):
    config = _fixture_config(tmp_path)
    with launch_rocky_gpu_isolation(config) as run:
        result = run.descendant_reap_diagnostic()
        assert result["namespace_init_pid"] == 1
        assert result["direct_namespace_pid"] == 2
        assert result["grandchild_namespace_pid"] == 3
        assert result["direct_status"] == {"exit_code": 17, "signal": 0}
        assert result["grandchild_status"] == {"exit_code": 23, "signal": 0}
        assert result["no_children_remaining"]
    assert run.namespace_cleanup_confirmed


def test_namespace_init_crash_force_kills_lingering_descendant(tmp_path: Path):
    config = _fixture_config(tmp_path)
    run = launch_rocky_gpu_isolation(config)
    try:
        result = run.crash_cleanup_diagnostic()
        # Namespace PID 1 ignores an internally generated fatal signal; the
        # diagnostic therefore reaches its explicit abrupt _exit(129).  The
        # security assertion is that the kernel also removes PID 1's lingering
        # descendant, which is checked independently below.
        assert result["supervisor_return_code"] == 129
        assert result["init_absent"]
        assert result["descendant_absent"]
        assert run.namespace_cleanup_confirmed
    finally:
        if not run._closed:
            run.close()


def test_outer_supervisor_death_triggers_pdeathsig_namespace_teardown(tmp_path: Path):
    config = _fixture_config(tmp_path)
    run = launch_rocky_gpu_isolation(config)
    try:
        result = run.parent_death_cleanup_diagnostic()
        assert result["supervisor_return_code"] == -signal.SIGKILL
        assert result["init_absent"]
        assert result["descendant_absent"]
        assert run.namespace_cleanup_confirmed
    finally:
        if not run._closed:
            run.close()


@pytest.mark.parametrize("iteration", range(3))
def test_outer_watchdog_reaps_hung_namespace_and_descendant(tmp_path: Path, iteration: int):
    del iteration
    config = _fixture_config(tmp_path)
    run = launch_rocky_gpu_isolation(config)
    try:
        result = run.watchdog_cleanup_diagnostic()
        assert result["supervisor_return_code"] == 128 + signal.SIGKILL
        assert result["init_absent"]
        assert result["descendant_absent"]
        assert run.namespace_cleanup_confirmed
    finally:
        if not run._closed:
            run.close()


def test_malformed_worker_command_fails_closed_without_descendants(tmp_path: Path):
    config = _fixture_config(tmp_path)
    run = launch_rocky_gpu_isolation(config)
    try:
        result = run.malformed_cleanup_diagnostic()
        assert result["phase"] == "command_loop"
        assert result["supervisor_return_code"] != 0
        assert result["init_absent"]
        assert run.namespace_cleanup_confirmed
    finally:
        if not run._closed:
            run.close()


@pytest.mark.parametrize(
    "packet,credentials",
    (
        (
            {
                "errno": 0,
                "extra": False,
                "phase": "command_loop",
                "reason": "ValueError",
                "type": "error",
            },
            None,
        ),
        (
            {
                "errno": False,
                "phase": "command_loop",
                "reason": "ValueError",
                "type": "error",
            },
            None,
        ),
        (
            {
                "errno": 0,
                "phase": "command_loop",
                "reason": 1,
                "type": "error",
            },
            None,
        ),
        (
            {
                "errno": 0,
                "phase": "command_loop",
                "reason": "ValueError",
                "type": "error",
            },
            "numeric_alias",
        ),
    ),
)
def test_malformed_cleanup_rejects_nonexact_error_packet_after_reaping(
    monkeypatch: pytest.MonkeyPatch,
    packet: dict[str, object],
    credentials: object,
) -> None:
    init_pid = 43210

    class ExitedProcess:
        @staticmethod
        def wait(timeout: float) -> int:
            assert timeout == 10.0
            return 128

    run = object.__new__(isolation.RockySandboxRun)
    run._closed = False
    run._channel = object()
    run.init_host_pid = init_pid
    run.process = ExitedProcess()
    run._cleanup_local_state = lambda: None
    run._wait_pid_absent = lambda pid: pid == init_pid
    expected_credentials: tuple[object, object, object]
    if credentials == "numeric_alias":
        expected_credentials = (float(init_pid), os.getuid(), os.getgid())
    else:
        expected_credentials = (init_pid, os.getuid(), os.getgid())
    monkeypatch.setattr(isolation, "send_packet", lambda _channel, _wire: None)
    monkeypatch.setattr(
        isolation,
        "_recv_packet_with_credentials",
        lambda _channel: (packet, expected_credentials),
    )
    with pytest.raises(RockyIsolationError, match="failure packet"):
        run.malformed_cleanup_diagnostic()
    assert run.namespace_cleanup_confirmed
