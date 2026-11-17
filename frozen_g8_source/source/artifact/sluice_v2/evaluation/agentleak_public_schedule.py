"""Build the prior-public AgentLeak launch schedule without secret data paths."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
from types import MappingProxyType
from typing import Any, Mapping, Sequence

from .agentleak import CORPUS_ROWS, CORPUS_SHA256
from .agentleak_construction_corpus import (
    ConstructionCorpusError,
    construction_loader_source_sha256,
    load_public_schedule_construction_corpus,
)
from .agentleak_fullstack import (
    MAX_COLLECTION_ITEMS,
    MAX_TEXT_BYTES,
    PolicyAgent,
    PolicyObjective,
    PolicyTool,
    _canonical_json_bytes,
)


SCHEMA_VERSION = "sluice-agentleak-public-launch-schedule-v2"
MAX_SCHEDULE_BYTES = 16 * 1024 * 1024
_MAPPING_PROXY_TYPE = type(MappingProxyType({}))
_PLATFORM_OPEN_SUPPORTS_DIR_FD = (
    hasattr(os, "supports_dir_fd") and os.open in os.supports_dir_fd
)
_PLATFORM_STAT_SUPPORTS_DIR_FD = (
    hasattr(os, "supports_dir_fd") and os.stat in os.supports_dir_fd
)
_PLATFORM_STAT_SUPPORTS_NOFOLLOW = (
    hasattr(os, "supports_follow_symlinks")
    and os.stat in os.supports_follow_symlinks
)


class PublicScheduleBuildError(ValueError):
    """The prior-public schedule construction contract failed."""


def _require_secure_output_primitives() -> None:
    required_flags = (
        "O_CLOEXEC",
        "O_CREAT",
        "O_DIRECTORY",
        "O_EXCL",
        "O_NOFOLLOW",
        "O_RDONLY",
        "O_RDWR",
    )
    if any(not hasattr(os, name) for name in required_flags):
        raise PublicScheduleBuildError("secure schedule output primitives are unavailable")
    if (
        not _PLATFORM_OPEN_SUPPORTS_DIR_FD
        or not _PLATFORM_STAT_SUPPORTS_DIR_FD
        or not _PLATFORM_STAT_SUPPORTS_NOFOLLOW
        or any(
            not hasattr(os, name)
            for name in ("fchmod", "fstat", "fsync", "lseek", "read", "write")
        )
    ):
        raise PublicScheduleBuildError("secure schedule output primitives are unavailable")


def _directory_flags() -> int:
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _directory_identity(metadata: os.stat_result) -> tuple[int, int, int]:
    if not stat.S_ISDIR(metadata.st_mode):
        raise PublicScheduleBuildError("schedule output parent component is not a directory")
    return metadata.st_dev, metadata.st_ino, metadata.st_mode


def _open_directory_chain(path: Path) -> tuple[int, tuple[tuple[int, int, int], ...]]:
    descriptor = -1
    identities: list[tuple[int, int, int]] = []
    try:
        if not path.is_absolute() or not path.anchor:
            raise PublicScheduleBuildError("schedule output parent must be absolute")
        descriptor = os.open(path.anchor, _directory_flags())
        identities.append(_directory_identity(os.fstat(descriptor)))
        for component in path.parts[1:]:
            child = os.open(component, _directory_flags(), dir_fd=descriptor)
            try:
                identity = _directory_identity(os.fstat(child))
            except BaseException:
                os.close(child)
                raise
            os.close(descriptor)
            descriptor = child
            identities.append(identity)
        return descriptor, tuple(identities)
    except PublicScheduleBuildError:
        if descriptor >= 0:
            os.close(descriptor)
        raise
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        raise PublicScheduleBuildError("schedule output parent cannot be pinned") from None


def _reopen_verified_parent(
    path: Path, expected: tuple[tuple[int, int, int], ...]
) -> int:
    try:
        descriptor, observed = _open_directory_chain(path)
    except PublicScheduleBuildError:
        raise PublicScheduleBuildError("schedule output parent identity changed") from None
    if observed != expected:
        os.close(descriptor)
        raise PublicScheduleBuildError("schedule output parent identity changed")
    return descriptor


def _validate_output_file(
    metadata: os.stat_result,
    *,
    expected_identity: tuple[int, int] | None = None,
    expected_size: int | None = None,
) -> tuple[int, int]:
    identity = metadata.st_dev, metadata.st_ino
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or (expected_identity is not None and identity != expected_identity)
        or (expected_size is not None and metadata.st_size != expected_size)
    ):
        raise PublicScheduleBuildError("schedule output file identity is invalid")
    return identity


def _read_opened_schedule(descriptor: int) -> bytes:
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        total = 0
        while total <= MAX_SCHEDULE_BYTES:
            chunk = os.read(
                descriptor, min(65_536, MAX_SCHEDULE_BYTES + 1 - total)
            )
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        if total > MAX_SCHEDULE_BYTES:
            raise PublicScheduleBuildError("schedule output exceeds its bound")
        return b"".join(chunks)
    except PublicScheduleBuildError:
        raise
    except BaseException:
        raise PublicScheduleBuildError("schedule output cannot be re-read") from None


def _write_verified_schedule(output: Path, raw: bytes) -> str:
    absolute_output = Path(os.path.abspath(os.fspath(output)))
    basename = absolute_output.name
    if basename in {"", ".", ".."} or Path(basename).name != basename:
        raise PublicScheduleBuildError("public schedule output basename is unsafe")
    parent = absolute_output.parent
    parent_fd, parent_chain = _open_directory_chain(parent)
    output_fd: int | None = None
    verified_parent_fd: int | None = None
    verified_output_fd: int | None = None
    expected_digest = hashlib.sha256(raw).hexdigest()
    try:
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        try:
            output_fd = os.open(basename, flags, 0o600, dir_fd=parent_fd)
        except FileExistsError as exc:
            raise PublicScheduleBuildError("public schedule output already exists") from exc
        os.fchmod(output_fd, 0o600)
        opened_identity = _validate_output_file(
            os.fstat(output_fd), expected_size=0
        )
        view = memoryview(raw)
        while view:
            written = os.write(output_fd, view)
            if written <= 0:
                raise PublicScheduleBuildError("public schedule write did not progress")
            view = view[written:]
        os.fsync(output_fd)
        reread = _read_opened_schedule(output_fd)
        if reread != raw or hashlib.sha256(reread).hexdigest() != expected_digest:
            raise PublicScheduleBuildError("public schedule re-read hash mismatch")
        _validate_output_file(
            os.fstat(output_fd),
            expected_identity=opened_identity,
            expected_size=len(raw),
        )
        os.fsync(parent_fd)

        verified_parent_fd = _reopen_verified_parent(parent, parent_chain)
        lexical = os.stat(
            basename, dir_fd=verified_parent_fd, follow_symlinks=False
        )
        _validate_output_file(
            lexical, expected_identity=opened_identity, expected_size=len(raw)
        )
        verified_output_fd = os.open(
            basename,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=verified_parent_fd,
        )
        _validate_output_file(
            os.fstat(verified_output_fd),
            expected_identity=opened_identity,
            expected_size=len(raw),
        )
        verified_raw = _read_opened_schedule(verified_output_fd)
        if (
            verified_raw != raw
            or hashlib.sha256(verified_raw).hexdigest() != expected_digest
        ):
            raise PublicScheduleBuildError("public schedule lexical re-read hash mismatch")
        return expected_digest
    except PublicScheduleBuildError:
        raise
    except BaseException:
        raise PublicScheduleBuildError("public schedule output creation failed") from None
    finally:
        if verified_output_fd is not None:
            os.close(verified_output_fd)
        if verified_parent_fd is not None:
            os.close(verified_parent_fd)
        if output_fd is not None:
            os.close(output_fd)
        os.close(parent_fd)


def _mapping(name: str, value: object) -> Mapping[str, Any]:
    if type(value) not in (dict, _MAPPING_PROXY_TYPE):
        raise PublicScheduleBuildError(f"{name} must be an exact object")
    if any(type(key) is not str for key in value):
        raise PublicScheduleBuildError(f"{name} keys must be strings")
    return value


def _sequence(
    name: str, value: object, *, minimum: int = 0, maximum: int = MAX_COLLECTION_ITEMS
) -> tuple[Any, ...]:
    if type(value) not in (tuple, list):
        raise PublicScheduleBuildError(f"{name} must be an exact array")
    values = tuple(value)
    if not minimum <= len(values) <= maximum:
        raise PublicScheduleBuildError(f"{name} has an invalid item count")
    return values


def _source_sha256() -> str:
    source = Path(__file__)
    metadata = source.lstat()
    if not stat.S_ISREG(metadata.st_mode) or source.is_symlink() or metadata.st_size > 2_097_152:
        raise PublicScheduleBuildError("schedule builder source path is unsafe")
    flags = os.O_RDONLY | (os.O_NOFOLLOW if hasattr(os, "O_NOFOLLOW") else 0)
    descriptor = os.open(source, flags)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise PublicScheduleBuildError("schedule builder source changed during hashing")
        raw = b""
        while len(raw) <= 2_097_152:
            chunk = os.read(descriptor, min(65_536, 2_097_153 - len(raw)))
            if not chunk:
                break
            raw += chunk
        if len(raw) > 2_097_152:
            raise PublicScheduleBuildError("schedule builder source exceeds its bound")
    finally:
        os.close(descriptor)
    return hashlib.sha256(raw).hexdigest()


def project_public_schedule_row(scenario: Mapping[str, Any]) -> dict[str, Any]:
    """Project only the fields needed to compile policy before protected attachment."""

    source = _mapping("scenario", scenario)
    scenario_id = source["scenario_id"]
    objective_source = _mapping("objective", source["objective"])
    objective = PolicyObjective(
        user_request=objective_source["user_request"],
        privacy_instruction=objective_source["privacy_instruction"],
        success_criteria=tuple(
            _sequence(
                "success criteria",
                objective_source["success_criteria"],
                minimum=1,
                maximum=32,
            )
        ),
    )
    agents = tuple(
        PolicyAgent(
            agent_id=_mapping("agent", raw_agent)["agent_id"],
            role=raw_agent["role"],
        )
        for raw_agent in _sequence("agents", source["agents"], minimum=1, maximum=32)
    )
    tools = tuple(
        PolicyTool(
            tool_name=_mapping("tool", raw_tool)["tool_name"],
            capabilities=tuple(
                _sequence(
                    "tool capabilities",
                    raw_tool["capabilities"],
                    minimum=1,
                    maximum=32,
                )
            ),
            requires_clearance=raw_tool["requires_clearance"],
        )
        for raw_tool in _sequence("tools", source["tools"], minimum=1, maximum=64)
    )
    allowed_source = _mapping("allowed set", source["allowed_set"])
    allowed_names = tuple(
        _sequence(
            "allowed field names", allowed_source["fields"], minimum=1, maximum=32
        )
    )
    if len(set(allowed_names)) != len(allowed_names) or any(
        type(name) is not str or not name for name in allowed_names
    ):
        raise PublicScheduleBuildError("allowed field names must be unique text")
    criteria_wire = list(objective.success_criteria)
    template_code = "template-" + hashlib.sha256(
        _canonical_json_bytes(criteria_wire, maximum=MAX_TEXT_BYTES)
    ).hexdigest()[:16]
    return {
        "scenario_id": scenario_id,
        "template_code": template_code,
        "objective": {
            "user_request": objective.user_request,
            "privacy_instruction": objective.privacy_instruction,
            "success_criteria": criteria_wire,
        },
        "agents": [
            {"agent_id": agent.agent_id, "role": agent.role} for agent in agents
        ],
        "tools": [
            {
                "tool_name": tool.tool_name,
                "capabilities": list(tool.capabilities),
                "requires_clearance": tool.requires_clearance,
            }
            for tool in tools
        ],
        "allowed_field_names": list(allowed_names),
    }


def build_public_schedule_document(
    scenarios: Sequence[Mapping[str, Any]],
    *,
    builder_source_sha256: str,
    construction_loader_source_sha256: str,
) -> bytes:
    if type(scenarios) is not tuple or len(scenarios) != CORPUS_ROWS:
        raise PublicScheduleBuildError("public schedule requires the exact corpus population")
    if (
        type(builder_source_sha256) is not str
        or len(builder_source_sha256) != 64
        or any(character not in "0123456789abcdef" for character in builder_source_sha256)
    ):
        raise PublicScheduleBuildError("schedule builder source hash is invalid")
    if (
        type(construction_loader_source_sha256) is not str
        or len(construction_loader_source_sha256) != 64
        or any(
            character not in "0123456789abcdef"
            for character in construction_loader_source_sha256
        )
    ):
        raise PublicScheduleBuildError("construction loader source hash is invalid")
    rows = [project_public_schedule_row(scenario) for scenario in scenarios]
    rows.sort(key=lambda row: row["scenario_id"])
    identifiers = [row["scenario_id"] for row in rows]
    if len(set(identifiers)) != CORPUS_ROWS:
        raise PublicScheduleBuildError("public schedule scenario identifiers are not unique")
    document = {
        "schema_version": SCHEMA_VERSION,
        "corpus_sha256": CORPUS_SHA256,
        "corpus_rows": CORPUS_ROWS,
        "schedule_builder_source_sha256": builder_source_sha256,
        "construction_corpus_loader_source_sha256": construction_loader_source_sha256,
        "rows": rows,
    }
    return _canonical_json_bytes(document, maximum=MAX_SCHEDULE_BYTES)


def build_public_schedule(*, corpus_path: str | Path, output_path: str | Path) -> str:
    _require_secure_output_primitives()
    try:
        corpus = load_public_schedule_construction_corpus(corpus_path)
    except ConstructionCorpusError as exc:
        raise PublicScheduleBuildError("construction-only corpus projection failed") from exc
    if corpus.sha256 != CORPUS_SHA256:
        raise PublicScheduleBuildError("public schedule corpus identity is invalid")
    raw = build_public_schedule_document(
        corpus.rows,
        builder_source_sha256=_source_sha256(),
        construction_loader_source_sha256=construction_loader_source_sha256(),
    )
    return _write_verified_schedule(Path(output_path), raw)


def _main() -> int:
    parser = argparse.ArgumentParser(description="Build the prior-public AgentLeak schedule")
    parser.add_argument("--corpus", required=True)
    parser.add_argument("--output", required=True)
    arguments = parser.parse_args()
    digest = build_public_schedule(
        corpus_path=arguments.corpus, output_path=arguments.output
    )
    print(
        json.dumps(
            {
                "schema_version": SCHEMA_VERSION,
                "schedule_sha256": digest,
                "row_count": CORPUS_ROWS,
                "builder_source_sha256": _source_sha256(),
                "construction_corpus_loader_source_sha256": construction_loader_source_sha256(),
            },
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())


__all__ = [
    "MAX_SCHEDULE_BYTES",
    "PublicScheduleBuildError",
    "SCHEMA_VERSION",
    "build_public_schedule",
    "build_public_schedule_document",
    "project_public_schedule_row",
]
