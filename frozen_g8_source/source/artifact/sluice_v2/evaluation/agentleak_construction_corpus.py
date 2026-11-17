"""Authenticated, construction-only projections of the pinned AgentLeak JSONL.

The general evaluation loader deliberately validates and normalizes attack and
evaluation metadata.  Offline policy construction must not do that: Amendment
2 permits the codebook builder to inspect only public template fields and the
allowed-field vault projection, while the launch-schedule builder may inspect
only its declared public fields.  This module authenticates the exact corpus
bytes first and then invokes one of two fixed projectors that never index or
iterate a forbidden subobject.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any, Callable, Mapping

from .agentleak import CORPUS_ROWS, CORPUS_SHA256


MAX_CORPUS_BYTES = 64 * 1024 * 1024
MAX_JSONL_ROW_BYTES = 2 * 1024 * 1024
MAX_PUBLIC_ITEMS = 4_096


class ConstructionCorpusError(ValueError):
    """The authenticated construction projection could not be produced."""


@dataclass(frozen=True, slots=True)
class ConstructionCorpus:
    source_path: Path
    sha256: str
    rows: tuple[Mapping[str, Any], ...]


def _mapping(name: str, value: object) -> Mapping[str, Any]:
    # Do not enumerate keys here: a forbidden sibling may be an access poison.
    if not isinstance(value, Mapping):
        raise ConstructionCorpusError(f"{name} must be an object")
    return value


def _sequence(
    name: str,
    value: object,
    *,
    minimum: int = 0,
    maximum: int = MAX_PUBLIC_ITEMS,
) -> tuple[Any, ...]:
    if type(value) not in (list, tuple):
        raise ConstructionCorpusError(f"{name} must be an array")
    result = tuple(value)
    if not minimum <= len(result) <= maximum:
        raise ConstructionCorpusError(f"{name} has an invalid item count")
    return result


def _text(name: str, value: object, *, allow_none: bool = False) -> str | None:
    if allow_none and value is None:
        return None
    if type(value) is not str or not value or len(value.encode("utf-8")) > 65_536:
        raise ConstructionCorpusError(f"{name} must be bounded nonempty text")
    return value


def _unique_texts(name: str, value: object, *, minimum: int = 1) -> list[str]:
    result = [
        _text(f"{name} item", item)
        for item in _sequence(name, value, minimum=minimum, maximum=64)
    ]
    if len(result) != len(set(result)):
        raise ConstructionCorpusError(f"{name} must be unique")
    return result  # type: ignore[return-value]


def project_codebook_support_row(row: Mapping[str, Any]) -> dict[str, Any]:
    """Project only public template data and complete allowed-field payloads."""

    source = _mapping("scenario", row)
    scenario_id = _text("scenario identifier", source["scenario_id"])
    objective = _mapping("objective", source["objective"])
    criteria = _unique_texts("success criteria", objective["success_criteria"])
    allowed_set = _mapping("allowed set", source["allowed_set"])
    allowed_fields = _unique_texts("allowed field names", allowed_set["fields"])

    # Access to the protected vault is restricted to membership/lookup for the
    # already-declared allowed names.  No record key set or disallowed value is
    # enumerated, copied, normalized, or frozen.
    vault = _mapping("private vault", source["private_vault"])
    records = _sequence(
        "private vault records", vault["records"], minimum=1, maximum=MAX_PUBLIC_ITEMS
    )
    projected_records: list[dict[str, Any]] = []
    for raw_record in records:
        record = _mapping("private vault record", raw_record)
        fields = _mapping("private vault fields", record["fields"])
        projected: dict[str, Any] = {}
        for field_name in allowed_fields:
            if field_name in fields:
                projected[field_name] = fields[field_name]
        projected_records.append({"fields": projected})

    return {
        "scenario_id": scenario_id,
        "objective": {"success_criteria": criteria},
        "allowed_set": {"fields": allowed_fields},
        "private_vault": {"records": projected_records},
    }


def project_public_schedule_row(row: Mapping[str, Any]) -> dict[str, Any]:
    """Project only fields declared prior-public by Amendment 2."""

    source = _mapping("scenario", row)
    scenario_id = _text("scenario identifier", source["scenario_id"])
    raw_objective = _mapping("objective", source["objective"])
    objective = {
        "user_request": _text("trusted user request", raw_objective["user_request"]),
        "privacy_instruction": _text(
            "trusted privacy instruction",
            raw_objective["privacy_instruction"],
            allow_none=True,
        ),
        "success_criteria": _unique_texts(
            "success criteria", raw_objective["success_criteria"]
        ),
    }
    agents: list[dict[str, Any]] = []
    for raw_agent in _sequence("agents", source["agents"], minimum=1, maximum=32):
        agent = _mapping("agent", raw_agent)
        agents.append(
            {
                "agent_id": _text("agent identifier", agent["agent_id"]),
                "role": _text("agent role", agent["role"]),
            }
        )
    tools: list[dict[str, Any]] = []
    for raw_tool in _sequence("tools", source["tools"], minimum=1, maximum=64):
        tool = _mapping("tool", raw_tool)
        tools.append(
            {
                "tool_name": _text("tool name", tool["tool_name"]),
                "capabilities": _unique_texts(
                    "tool capabilities", tool["capabilities"]
                ),
                "requires_clearance": _text(
                    "tool clearance", tool["requires_clearance"], allow_none=True
                ),
            }
        )
    allowed_set = _mapping("allowed set", source["allowed_set"])
    allowed_fields = _unique_texts("allowed field names", allowed_set["fields"])
    return {
        "scenario_id": scenario_id,
        "objective": objective,
        "agents": agents,
        "tools": tools,
        "allowed_set": {"fields": allowed_fields},
    }


def _read_regular(path: Path, *, maximum: int, label: str) -> bytes:
    descriptor = -1
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or path.is_symlink()
            or before.st_size > maximum
        ):
            raise ConstructionCorpusError(f"{label} path is unsafe")
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino, opened.st_size)
            != (before.st_dev, before.st_ino, before.st_size)
        ):
            raise ConstructionCorpusError(f"{label} changed during authentication")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(65_536, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise ConstructionCorpusError(f"{label} exceeds its bound")
        final = os.fstat(descriptor)
        rebound = path.lstat()
        if (
            (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns, final.st_ctime_ns)
            != (
                opened.st_dev,
                opened.st_ino,
                opened.st_size,
                opened.st_mtime_ns,
                opened.st_ctime_ns,
            )
            or (rebound.st_dev, rebound.st_ino, rebound.st_size)
            != (opened.st_dev, opened.st_ino, opened.st_size)
        ):
            raise ConstructionCorpusError(f"{label} changed during authentication")
        return b"".join(chunks)
    except ConstructionCorpusError:
        raise
    except BaseException:
        raise ConstructionCorpusError(f"{label} cannot be authenticated") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def construction_loader_source_sha256() -> str:
    return hashlib.sha256(
        _read_regular(Path(__file__), maximum=2_097_152, label="construction loader source")
    ).hexdigest()


def _strict_json_row(raw: bytes, *, line_number: int) -> Mapping[str, Any]:
    if not raw or len(raw) > MAX_JSONL_ROW_BYTES:
        raise ConstructionCorpusError(f"JSONL row {line_number} has an invalid size")

    try:
        # The whole file has already matched one immutable SHA-256.  Use the
        # standard parser without an object hook: a hook would recursively
        # enumerate even forbidden subobjects.  The fixed projectors below are
        # the only Python code that indexes the authenticated row.
        value = json.loads(raw.decode("utf-8"))
    except BaseException:
        raise ConstructionCorpusError(f"JSONL row {line_number} is malformed") from None
    if type(value) is not dict:
        raise ConstructionCorpusError(f"JSONL row {line_number} is not an object")
    return value


def _load_projected(
    path: str | Path,
    *,
    projector: Callable[[Mapping[str, Any]], dict[str, Any]],
) -> ConstructionCorpus:
    source = Path(path)
    raw = _read_regular(source, maximum=MAX_CORPUS_BYTES, label="AgentLeak corpus")
    digest = hashlib.sha256(raw).hexdigest()
    if digest != CORPUS_SHA256:
        raise ConstructionCorpusError("AgentLeak corpus SHA-256 does not match the pin")
    lines = raw.splitlines()
    if len(lines) != CORPUS_ROWS or any(not line for line in lines):
        raise ConstructionCorpusError("AgentLeak corpus row population is invalid")
    projected: list[Mapping[str, Any]] = []
    identifiers: set[str] = set()
    for line_number, line in enumerate(lines, 1):
        result = projector(_strict_json_row(line, line_number=line_number))
        scenario_id = result["scenario_id"]
        if scenario_id in identifiers:
            raise ConstructionCorpusError("scenario identifiers are not unique")
        identifiers.add(scenario_id)
        projected.append(result)
    return ConstructionCorpus(source_path=source, sha256=digest, rows=tuple(projected))


def load_codebook_construction_corpus(path: str | Path) -> ConstructionCorpus:
    return _load_projected(path, projector=project_codebook_support_row)


def load_public_schedule_construction_corpus(path: str | Path) -> ConstructionCorpus:
    return _load_projected(path, projector=project_public_schedule_row)


__all__ = [
    "ConstructionCorpus",
    "ConstructionCorpusError",
    "construction_loader_source_sha256",
    "load_codebook_construction_corpus",
    "load_public_schedule_construction_corpus",
    "project_codebook_support_row",
    "project_public_schedule_row",
]
