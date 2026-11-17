"""Adversarial unit contracts for create-only node-local runtime staging."""

from __future__ import annotations

import json
import os
from pathlib import Path
import secrets
import shutil
import stat
import sys
import ctypes

import pytest

import sluice_v2.runtime_staging as runtime_staging
from sluice_v2.rocky_gpu_isolation import sha256_tree
from sluice_v2.runtime_staging import (
    DescriptorFilesystemIdentity,
    MountIdentity,
    RuntimeStagingError,
    _Statfs,
    _Statx,
    assert_path_absent_authenticated,
    audit_runtime_execution,
    inspect_runtime_tree,
    mount_for_path,
    read_json_authenticated,
    runtime_timestamps_match,
    stage_authenticated_runtime,
    write_json_create_only,
)


COMMIT = "1" * 40
_REAL_DESCRIPTOR_FILESYSTEM = runtime_staging._descriptor_filesystem


@pytest.fixture(autouse=True)
def _fake_descriptor_filesystem_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    def identity(descriptor: int, role: str) -> DescriptorFilesystemIdentity:
        del descriptor
        if role == "runtime source":
            return DescriptorFilesystemIdentity("00006969", (11, 12), 31, 13)
        return DescriptorFilesystemIdentity("58465342", (21, 22), 32, 23)

    monkeypatch.setattr(
        "sluice_v2.runtime_staging._descriptor_filesystem", identity
    )


def test_linux_stat_struct_abi_sizes_are_frozen() -> None:
    assert ctypes.sizeof(_Statx) == 256
    assert ctypes.sizeof(_Statfs) == 120


@pytest.mark.skipif(
    "SLUICE_NFS_REGRESSION_DIR" not in os.environ
    or "SLUICE_XFS_REGRESSION_DIR" not in os.environ,
    reason="requires explicit preserved NFS and XFS regression directories",
)
def test_descriptor_filesystem_identities_match_real_nfs_and_xfs() -> None:
    for environment, expected in (
        ("SLUICE_NFS_REGRESSION_DIR", "00006969"),
        ("SLUICE_XFS_REGRESSION_DIR", "58465342"),
    ):
        descriptor = os.open(
            os.environ[environment], os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
        )
        try:
            observed = _REAL_DESCRIPTOR_FILESYSTEM(descriptor, environment)
        finally:
            os.close(descriptor)
        assert observed.filesystem_magic == expected


def _fixture(source: Path) -> None:
    (source / "bin").mkdir(parents=True)
    (source / "lib").mkdir()
    executable = source / "bin" / "python"
    executable.write_bytes(b"synthetic-python")
    executable.chmod(0o755)
    library = source / "lib" / "library.so"
    library.write_bytes(b"synthetic-library")
    library.chmod(0o644)
    (source / "bin" / "library-link").symlink_to("../lib/library.so")


def _fake_mount(path: Path) -> MountIdentity:
    resolved = Path(path).resolve(strict=True)
    filesystem = "nfs" if resolved.name == "source" else "xfs"
    if filesystem == "nfs":
        mountpoint = resolved
    else:
        mountpoint = next(
            (
                candidate
                for candidate in (resolved, *resolved.parents)
                if candidate.name == "destination"
            ),
            resolved,
        )
    return MountIdentity(
        filesystem=filesystem,
        mount_id=31 if filesystem == "nfs" else 32,
        mountpoint=os.fspath(mountpoint),
        source="synthetic",
        mount_options=("rw",),
        super_options=("rw",),
    )


@pytest.mark.skipif(sys.platform != "linux", reason="publication requires Linux renameat2")
def test_stage_preserves_tree_hash_inventory_modes_and_relative_symlinks(tmp_path: Path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    _fixture(source)
    base = tmp_path / "destination"
    monkeypatch.setattr("sluice_v2.runtime_staging.mount_for_path", _fake_mount)
    result = stage_authenticated_runtime(
        source=source,
        destination_base=base,
        label="qwnccr",
        source_commit=COMMIT,
    )
    published = Path(result["published_path"])
    assert published.name == f"qwnccr-sha256-{sha256_tree(source)}"
    assert sha256_tree(published) == sha256_tree(source)
    assert inspect_runtime_tree(published) == inspect_runtime_tree(source)
    assert runtime_timestamps_match(source, published)
    assert (published / "bin" / "library-link").is_symlink()
    assert os.readlink(published / "bin" / "library-link") == "../lib/library.so"
    assert (published / "bin" / "python").stat().st_mode & 0o777 == 0o755
    for relative in (".", "bin", "bin/python", "bin/library-link", "lib/library.so"):
        assert (source / relative).lstat().st_mtime_ns == (published / relative).lstat().st_mtime_ns
    assert result["atomic_rename_noreplace"] is True
    assert result["source_treated_read_only"] is True
    assert result["source_timestamps_preserved"] is True
    assert result["reused_existing"] is False
    expected_regular_bytes = sum(
        (source / relative).stat().st_size
        for relative in ("bin/python", "lib/library.so")
    )
    assert result["copy_counts"]["regular_bytes"] == expected_regular_bytes
    assert inspect_runtime_tree(source)["regular_bytes"] == expected_regular_bytes
    assert not list(base.glob(".staging-*"))


@pytest.mark.skipif(sys.platform != "linux", reason="publication requires Linux renameat2")
def test_repeat_validates_and_reuses_authenticated_digest_path(tmp_path: Path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    _fixture(source)
    base = tmp_path / "destination"
    monkeypatch.setattr("sluice_v2.runtime_staging.mount_for_path", _fake_mount)
    first = stage_authenticated_runtime(
        source=source, destination_base=base, label="qwnccr", source_commit=COMMIT
    )
    second = stage_authenticated_runtime(
        source=source, destination_base=base, label="qwnccr", source_commit=COMMIT
    )
    assert second["reused_existing"] is True
    assert second["published_path"] == first["published_path"]


def test_existing_digest_path_is_never_overwritten(tmp_path: Path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    _fixture(source)
    base = tmp_path / "destination"
    base.mkdir(mode=0o700)
    final = base / f"qwnccr-sha256-{sha256_tree(source)}"
    final.mkdir()
    sentinel = final / "sentinel"
    sentinel.write_bytes(b"existing")
    monkeypatch.setattr("sluice_v2.runtime_staging.mount_for_path", _fake_mount)
    with pytest.raises(FileExistsError, match="fails authentication"):
        stage_authenticated_runtime(
            source=source, destination_base=base, label="qwnccr", source_commit=COMMIT
        )
    assert sentinel.read_bytes() == b"existing"


@pytest.mark.parametrize("target", ("/etc/passwd", "../../outside"))
def test_absolute_or_escaping_symlink_fails_closed(tmp_path: Path, monkeypatch, target: str):
    source = tmp_path / "source"
    source.mkdir()
    outside = tmp_path / "outside"
    outside.write_bytes(b"private")
    (source / "unsafe").symlink_to(target)
    base = tmp_path / "destination"
    monkeypatch.setattr("sluice_v2.runtime_staging.mount_for_path", _fake_mount)
    with pytest.raises(ValueError, match="symlink|escape"):
        stage_authenticated_runtime(
            source=source, destination_base=base, label="qwnccr", source_commit=COMMIT
        )
    assert not list(base.glob("qwnccr-sha256-*"))


def test_special_file_fails_closed(tmp_path: Path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    os.mkfifo(source / "fifo", 0o600)
    base = tmp_path / "destination"
    monkeypatch.setattr("sluice_v2.runtime_staging.mount_for_path", _fake_mount)
    with pytest.raises(ValueError, match="special"):
        stage_authenticated_runtime(
            source=source, destination_base=base, label="qwnccr", source_commit=COMMIT
        )


def test_destination_base_symlink_is_rejected(tmp_path: Path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    _fixture(source)
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    monkeypatch.setattr("sluice_v2.runtime_staging.mount_for_path", _fake_mount)
    with pytest.raises(ValueError, match="symbolic link|canonical"):
        stage_authenticated_runtime(
            source=source, destination_base=alias, label="qwnccr", source_commit=COMMIT
        )


def test_filesystem_type_mismatch_fails_before_copy(tmp_path: Path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    _fixture(source)
    base = tmp_path / "destination"

    def wrong_mount(path: Path) -> MountIdentity:
        resolved = Path(path).resolve(strict=True)
        return MountIdentity("ext4", os.fspath(resolved), "synthetic", ("rw",), ("rw",), 31)

    monkeypatch.setattr("sluice_v2.runtime_staging.mount_for_path", wrong_mount)
    with pytest.raises(RuntimeStagingError, match="source filesystem"):
        stage_authenticated_runtime(
            source=source, destination_base=base, label="qwnccr", source_commit=COMMIT
        )


@pytest.mark.skipif(sys.platform != "linux", reason="publication requires Linux renameat2")
def test_descriptor_filesystem_drift_fails_closed(tmp_path: Path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    _fixture(source)
    base = tmp_path / "destination"
    monkeypatch.setattr("sluice_v2.runtime_staging.mount_for_path", _fake_mount)
    source_calls = 0

    def drifting(descriptor: int, role: str) -> DescriptorFilesystemIdentity:
        nonlocal source_calls
        del descriptor
        if role == "runtime source":
            source_calls += 1
            fsid = (11, 12) if source_calls == 1 else (11, 99)
            return DescriptorFilesystemIdentity("00006969", fsid, 31, 13)
        return DescriptorFilesystemIdentity("58465342", (21, 22), 32, 23)

    monkeypatch.setattr("sluice_v2.runtime_staging._descriptor_filesystem", drifting)
    with pytest.raises(RuntimeStagingError, match="descriptor filesystem identity changed"):
        stage_authenticated_runtime(
            source=source,
            destination_base=base,
            label="qwnccr",
            source_commit=COMMIT,
        )


def test_fdinfo_mount_id_must_match_exact_mountinfo_record(tmp_path: Path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    _fixture(source)
    base = tmp_path / "destination"

    def mismatched(path: Path) -> MountIdentity:
        observed = _fake_mount(path)
        if observed.filesystem == "nfs":
            return MountIdentity(
                filesystem=observed.filesystem,
                mount_id=99,
                mountpoint=observed.mountpoint,
                source=observed.source,
                mount_options=observed.mount_options,
                super_options=observed.super_options,
            )
        return observed

    monkeypatch.setattr("sluice_v2.runtime_staging.mount_for_path", mismatched)
    with pytest.raises(RuntimeStagingError, match="mount ID"):
        stage_authenticated_runtime(
            source=source,
            destination_base=base,
            label="qwnccr",
            source_commit=COMMIT,
        )


def test_json_publication_is_create_only_and_hashed(tmp_path: Path):
    output = tmp_path / "manifest.json"
    digest = write_json_create_only(output, {"boundary": "diagnostic-only", "schema": 1})
    assert len(digest) == 64
    assert json.loads(output.read_text(encoding="ascii"))["boundary"] == "diagnostic-only"
    with pytest.raises(FileExistsError):
        write_json_create_only(output, {"replacement": True})
    assert "replacement" not in output.read_text(encoding="ascii")


def test_execution_digest_binds_timestamp_without_changing_content_digest(tmp_path: Path):
    root = tmp_path / "runtime"
    root.mkdir()
    item = root / "module.py"
    item.write_bytes(b"VALUE = 1\n")
    before = audit_runtime_execution(root)
    observed = item.stat().st_mtime_ns
    os.utime(item, ns=(observed + 1_000_000_000, observed + 1_000_000_000))
    after = audit_runtime_execution(root)
    assert after["tree_sha256"] == before["tree_sha256"]
    assert after["timestamp_sha256"] != before["timestamp_sha256"]
    assert after["execution_sha256"] != before["execution_sha256"]


def test_json_publication_uses_atomic_link_fallback_without_replacement(tmp_path: Path, monkeypatch):
    def unsupported(source_fd: int, source: str, destination_fd: int, destination: str) -> None:
        del source_fd, source, destination_fd, destination
        raise OSError(22, "renameat2 unsupported by filesystem")

    monkeypatch.setattr("sluice_v2.runtime_staging._rename_noreplace_at", unsupported)
    output = tmp_path / "manifest.json"
    digest = write_json_create_only(output, {"filesystem": "nfs", "status": "published"})
    assert len(digest) == 64
    assert output.stat().st_nlink == 1
    assert not list(tmp_path.glob(".manifest.json.*.tmp"))
    with pytest.raises(FileExistsError):
        write_json_create_only(output, {"replacement": True})
    assert json.loads(output.read_text(encoding="ascii"))["status"] == "published"


def test_json_parent_replacement_cannot_redirect_publication(tmp_path: Path, monkeypatch):
    parent = tmp_path / "evidence"
    parent.mkdir(mode=0o700)
    moved = tmp_path / "evidence-pinned"
    attacker = tmp_path / "attacker"
    output = parent / "manifest.json"

    def replace_parent(parent_fd: int, destination: str) -> None:
        del parent_fd, destination
        parent.rename(moved)
        attacker.mkdir(mode=0o700)
        parent.symlink_to(attacker, target_is_directory=True)

    monkeypatch.setattr(
        "sluice_v2.runtime_staging._json_post_publish_test_hook", replace_parent
    )
    with pytest.raises(RuntimeStagingError, match="path identity changed"):
        write_json_create_only(output, {"authenticated": True})
    assert (moved / "manifest.json").is_file()
    assert not (attacker / "manifest.json").exists()


def test_json_post_write_hardlink_drift_fails_closed(tmp_path: Path, monkeypatch):
    output = tmp_path / "manifest.json"
    alias = tmp_path / "unexpected-link"

    def add_hardlink(parent_fd: int, destination: str) -> None:
        os.link(
            destination,
            alias.name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
            follow_symlinks=False,
        )

    monkeypatch.setattr(
        "sluice_v2.runtime_staging._json_post_publish_test_hook", add_hardlink
    )
    with pytest.raises(RuntimeStagingError, match="metadata"):
        write_json_create_only(output, {"authenticated": True})
    assert output.stat().st_nlink == 2
    assert alias.stat().st_ino == output.stat().st_ino


def test_json_post_write_mode_drift_fails_closed(tmp_path: Path, monkeypatch):
    output = tmp_path / "manifest.json"

    def change_mode(parent_fd: int, destination: str) -> None:
        descriptor = os.open(destination, os.O_RDONLY | os.O_CLOEXEC, dir_fd=parent_fd)
        try:
            os.fchmod(descriptor, 0o640)
        finally:
            os.close(descriptor)

    monkeypatch.setattr(
        "sluice_v2.runtime_staging._json_post_publish_test_hook", change_mode
    )
    with pytest.raises(RuntimeStagingError, match="metadata"):
        write_json_create_only(output, {"authenticated": True})
    assert stat.S_IMODE(output.stat().st_mode) == 0o640


def test_authenticated_json_read_rejects_leaf_replacement(tmp_path: Path, monkeypatch):
    manifest = tmp_path / "manifest.json"
    displaced = tmp_path / "manifest-original.json"
    write_json_create_only(manifest, {"identity": "original"})

    def replace_leaf(parent_fd: int, destination: str) -> None:
        os.rename(
            destination,
            displaced.name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            0o600,
            dir_fd=parent_fd,
        )
        try:
            os.write(descriptor, b'{"identity":"replacement"}\n')
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    monkeypatch.setattr(
        "sluice_v2.runtime_staging._json_post_read_test_hook", replace_leaf
    )
    with pytest.raises(RuntimeStagingError, match="identity changed"):
        read_json_authenticated(manifest)
    assert json.loads(displaced.read_text(encoding="ascii"))["identity"] == "original"
    assert json.loads(manifest.read_text(encoding="ascii"))["identity"] == "replacement"


def test_authenticated_json_read_hashes_exact_same_descriptor_bytes(tmp_path: Path):
    manifest = tmp_path / "manifest.json"
    expected = write_json_create_only(manifest, {"identity": "same-fd"})
    wire, observed = read_json_authenticated(manifest)
    assert wire == {"identity": "same-fd"}
    assert observed == expected


def test_authenticated_absence_rejects_explicit_failure_marker(tmp_path: Path):
    failure = tmp_path / "manifest.json.failure.json"
    assert_path_absent_authenticated(failure)
    write_json_create_only(failure, {"status": "failed_closed"})
    with pytest.raises(RuntimeStagingError, match="exists"):
        assert_path_absent_authenticated(failure)


@pytest.mark.parametrize(
    "payload",
    (
        b'{"identity":"first","identity":"second"}\n',
        b'{"identity": "noncanonical"}\n',
        b'{"identity":"noncanonical"}\n',
        b'{"number":NaN}\n',
    ),
)
def test_authenticated_json_read_rejects_duplicate_or_noncanonical_bytes(
    tmp_path: Path, payload: bytes
):
    manifest = tmp_path / "manifest.json"
    descriptor = os.open(
        manifest,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
        0o600,
    )
    try:
        os.write(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    with pytest.raises(ValueError, match="canonical"):
        read_json_authenticated(manifest)


@pytest.mark.skipif(
    "SLUICE_NFS_REGRESSION_DIR" not in os.environ,
    reason="requires an explicit preserved NFS regression directory",
)
def test_nfs_link_fallback_closes_temp_and_converges_to_one_link(monkeypatch):
    root = Path(os.environ["SLUICE_NFS_REGRESSION_DIR"])
    if mount_for_path(root).filesystem not in {"nfs", "nfs4"}:
        pytest.fail("SLUICE_NFS_REGRESSION_DIR is not NFS/NFS4")
    work = root / f"nfs-json-link-{os.getpid()}-{secrets.token_hex(8)}"
    os.mkdir(work, 0o700)
    try:
        def unsupported(source_fd: int, source: str, destination_fd: int, destination: str) -> None:
            del source_fd, source, destination_fd, destination
            raise OSError(22, "force the exact NFS hard-link fallback")

        monkeypatch.setattr("sluice_v2.runtime_staging._rename_noreplace_at", unsupported)
        output = work / "manifest.json"
        expected = write_json_create_only(output, {"filesystem": "nfs4", "status": "committed"})
        wire, observed = read_json_authenticated(output)
        assert wire == {"filesystem": "nfs4", "status": "committed"}
        assert observed == expected
        assert output.stat().st_nlink == 1
        assert not list(work.glob(".sluice-json-*.tmp"))
    finally:
        shutil.rmtree(work)


def _force_link_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    def unsupported(source_fd: int, source: str, destination_fd: int, destination: str) -> None:
        del source_fd, source, destination_fd, destination
        raise OSError(22, "force the exact NFS hard-link fallback")

    monkeypatch.setattr("sluice_v2.runtime_staging._rename_noreplace_at", unsupported)


class _SillyRenameFilesystem:
    """Model the exact NFS ``nfs_unlink`` rule on any local filesystem.

    A real NFS client turns ``unlink`` of a name that is still referenced by an
    open descriptor into a rename to a hidden ``.nfsXXXX`` entry, so the second
    hard link -- and therefore ``st_nlink == 2`` -- survives until that
    descriptor is closed.  ``hold_open`` reproduces the ordering that failed on
    node001; the default reproduces a server-side delay that later clears.
    """

    def __init__(self, *, hold_open: bool) -> None:
        self.hold_open = hold_open
        self.real_unlink = os.unlink
        self.sillied: list[str] = []
        self.hidden: tuple[str, int] | None = None

    def _held_by_this_process(self, name: str, dir_fd: int) -> bool:
        directory = os.readlink(f"/proc/self/fd/{dir_fd}")
        target = os.path.join(directory, name)
        for entry in os.listdir("/proc/self/fd"):
            try:
                if os.readlink(os.path.join("/proc/self/fd", entry)) == target:
                    return True
            except OSError:
                continue
        return False

    def unlink(self, name, *, dir_fd=None):  # noqa: ANN001
        silly = (
            dir_fd is not None
            and isinstance(name, str)
            and name.startswith(".sluice-json-")
            and (not self.hold_open or self._held_by_this_process(name, dir_fd))
        )
        if not silly:
            return self.real_unlink(name, dir_fd=dir_fd)
        hidden = f".nfs{secrets.token_hex(8)}"
        os.rename(name, hidden, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        self.sillied.append(name)
        self.hidden = (hidden, dir_fd)
        return None

    def release(self) -> None:
        if self.hidden is not None:
            hidden, dir_fd = self.hidden
            self.real_unlink(hidden, dir_fd=dir_fd)
            self.hidden = None


class _StepClock:
    """Deterministic replacement for the module's bounded-deadline clock."""

    def __init__(self, release_after: int | None) -> None:
        self.now = 1_000.0
        self.sleeps = 0
        self.release_after = release_after
        self.filesystem: _SillyRenameFilesystem | None = None

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        del seconds
        self.sleeps += 1
        self.now += 1.0
        if (
            self.release_after is not None
            and self.sleeps >= self.release_after
            and self.filesystem is not None
        ):
            self.filesystem.release()


@pytest.mark.skipif(sys.platform != "linux", reason="requires /proc/self/fd descriptor introspection")
def test_json_link_fallback_never_unlinks_a_still_open_temporary(tmp_path: Path, monkeypatch):
    """Regression for the node001 ``temporary-name cleanup failed`` failure.

    Unlinking the temporary while its own descriptor is still open makes an NFS
    client silly-rename it, so the published leaf keeps a second link and the
    create-only publication fails after it has already left a success-looking
    destination behind.  The descriptor must be closed first.
    """

    _force_link_fallback(monkeypatch)
    filesystem = _SillyRenameFilesystem(hold_open=True)
    monkeypatch.setattr(os, "unlink", filesystem.unlink)
    output = tmp_path / "manifest.json"
    digest = write_json_create_only(output, {"filesystem": "nfs", "status": "committed"})
    monkeypatch.undo()
    assert filesystem.sillied == []
    assert len(digest) == 64
    assert output.stat().st_nlink == 1
    assert json.loads(output.read_text(encoding="ascii"))["status"] == "committed"
    assert not list(tmp_path.glob(".sluice-json-*.tmp"))
    assert not list(tmp_path.glob(".nfs*"))


def test_json_link_fallback_tolerates_a_lagging_second_link(tmp_path: Path, monkeypatch):
    """The bounded cleanup poll must actually get to run.

    A second link that is still visible immediately after the unlink must be
    tolerated until the deadline, not rejected by a forced identity assertion
    taken before the poll has had a single chance to observe convergence.
    """

    _force_link_fallback(monkeypatch)
    filesystem = _SillyRenameFilesystem(hold_open=False)
    clock = _StepClock(release_after=2)
    clock.filesystem = filesystem
    monkeypatch.setattr(os, "unlink", filesystem.unlink)
    monkeypatch.setattr("sluice_v2.runtime_staging.time", clock)
    output = tmp_path / "manifest.json"
    digest = write_json_create_only(output, {"filesystem": "nfs", "status": "committed"})
    monkeypatch.undo()
    assert filesystem.sillied  # the lagging second link really was simulated
    assert clock.sleeps >= 2  # the bounded poll really did run
    assert len(digest) == 64
    assert output.stat().st_nlink == 1
    assert json.loads(output.read_text(encoding="ascii"))["status"] == "committed"
    assert not list(tmp_path.glob(".nfs*"))


def test_json_link_fallback_fails_closed_when_the_second_link_never_clears(
    tmp_path: Path, monkeypatch
):
    """A second link that never clears must still fail closed at the deadline."""

    _force_link_fallback(monkeypatch)
    filesystem = _SillyRenameFilesystem(hold_open=False)
    clock = _StepClock(release_after=None)
    clock.filesystem = filesystem
    monkeypatch.setattr(os, "unlink", filesystem.unlink)
    monkeypatch.setattr("sluice_v2.runtime_staging.time", clock)
    output = tmp_path / "manifest.json"
    with pytest.raises(RuntimeStagingError, match="link count did not converge"):
        write_json_create_only(output, {"filesystem": "nfs", "status": "committed"})
    monkeypatch.undo()
    assert clock.sleeps >= 5
    assert output.stat().st_nlink == 2
    assert len(list(tmp_path.glob(".nfs*"))) == 1


@pytest.mark.skipif(sys.platform != "linux", reason="publication requires Linux renameat2")
def test_runtime_base_replacement_cannot_redirect_publication(tmp_path: Path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    _fixture(source)
    base = tmp_path / "destination"
    moved = tmp_path / "destination-pinned"
    attacker = tmp_path / "attacker"
    monkeypatch.setattr("sluice_v2.runtime_staging.mount_for_path", _fake_mount)

    def replace_base(base_fd: int, stage: str, destination: str) -> None:
        del base_fd, stage, destination
        base.rename(moved)
        attacker.mkdir(mode=0o700)
        base.symlink_to(attacker, target_is_directory=True)

    monkeypatch.setattr(
        "sluice_v2.runtime_staging._runtime_pre_publish_test_hook", replace_base
    )
    digest = sha256_tree(source)
    with pytest.raises(RuntimeStagingError, match="path identity changed"):
        stage_authenticated_runtime(
            source=source,
            destination_base=base,
            label="qwnccr",
            source_commit=COMMIT,
        )
    assert (moved / f"qwnccr-sha256-{digest}").is_dir()
    assert not (attacker / f"qwnccr-sha256-{digest}").exists()


@pytest.mark.skipif(sys.platform != "linux", reason="publication requires Linux renameat2")
def test_runtime_post_publish_hardlink_drift_fails_closed(tmp_path: Path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    _fixture(source)
    base = tmp_path / "destination"
    monkeypatch.setattr("sluice_v2.runtime_staging.mount_for_path", _fake_mount)

    def add_hardlink(base_fd: int, destination: str) -> None:
        root_fd = os.open(destination, os.O_RDONLY | os.O_DIRECTORY, dir_fd=base_fd)
        try:
            bin_fd = os.open("bin", os.O_RDONLY | os.O_DIRECTORY, dir_fd=root_fd)
            try:
                os.link(
                    "python",
                    "python-unexpected-link",
                    src_dir_fd=bin_fd,
                    dst_dir_fd=bin_fd,
                    follow_symlinks=False,
                )
            finally:
                os.close(bin_fd)
        finally:
            os.close(root_fd)

    monkeypatch.setattr(
        "sluice_v2.runtime_staging._runtime_post_publish_test_hook", add_hardlink
    )
    digest = sha256_tree(source)
    with pytest.raises(RuntimeStagingError, match="regular-file identity"):
        stage_authenticated_runtime(
            source=source,
            destination_base=base,
            label="qwnccr",
            source_commit=COMMIT,
        )
    published = base / f"qwnccr-sha256-{digest}"
    assert (published / "bin" / "python").stat().st_nlink == 2


@pytest.mark.skipif(sys.platform != "linux", reason="publication requires Linux renameat2")
def test_runtime_post_publish_mode_drift_fails_closed(tmp_path: Path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    _fixture(source)
    base = tmp_path / "destination"
    monkeypatch.setattr("sluice_v2.runtime_staging.mount_for_path", _fake_mount)

    def change_mode(base_fd: int, destination: str) -> None:
        root_fd = os.open(destination, os.O_RDONLY | os.O_DIRECTORY, dir_fd=base_fd)
        try:
            bin_fd = os.open("bin", os.O_RDONLY | os.O_DIRECTORY, dir_fd=root_fd)
            try:
                file_fd = os.open("python", os.O_RDONLY, dir_fd=bin_fd)
                try:
                    os.fchmod(file_fd, 0o700)
                finally:
                    os.close(file_fd)
            finally:
                os.close(bin_fd)
        finally:
            os.close(root_fd)

    monkeypatch.setattr(
        "sluice_v2.runtime_staging._runtime_post_publish_test_hook", change_mode
    )
    digest = sha256_tree(source)
    with pytest.raises(RuntimeStagingError, match="post-rename authentication"):
        stage_authenticated_runtime(
            source=source,
            destination_base=base,
            label="qwnccr",
            source_commit=COMMIT,
        )
    published = base / f"qwnccr-sha256-{digest}"
    assert stat.S_IMODE((published / "bin" / "python").stat().st_mode) == 0o700
