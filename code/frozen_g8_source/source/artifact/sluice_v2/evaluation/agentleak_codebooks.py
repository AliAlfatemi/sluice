"""Deterministic, secret-independent codebooks for the pinned AgentLeak corpus.

This builder is an offline policy-compilation step.  It authenticates the exact
1,000-row corpus, groups rows only by public success criteria and allowed field
names, and commits the union of complete allowed-state projections.  A row
whose projection contains no declared allowed value maps to the precommitted
``ABSTAIN`` symbol; the builder never fabricates missing task data.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
from types import MappingProxyType
from typing import Any, Mapping, Sequence

from .agentleak import CORPUS_ROWS, CORPUS_SHA256
from .agentleak import ALL_CHANNELS
from .agentleak_construction_corpus import (
    ConstructionCorpusError,
    construction_loader_source_sha256,
    load_codebook_construction_corpus,
)
from .agentleak_fullstack import (
    MAX_COLLECTION_ITEMS,
    MAX_MANIFEST_BYTES,
    MAX_RAW_RECORD_BYTES,
    MAX_TEXT_BYTES,
    _canonical_json_bytes,
    _freeze_json,
    load_codebook_bundle,
)


SCHEMA_VERSION = "sluice-agentleak-codebook-builder-report-v2"
MANIFEST_SCHEMA_VERSION = "sluice-agentleak-codebook-manifest-v1"
PRIVATE_SCHEMA_VERSION = "sluice-agentleak-private-codebook-v1"
TEMPLATE_COUNT = 16
HORIZON = 16
ACCOUNTING_UNITS_PER_BIT = 1
ROUTE_NAME = "task_release"
PROTECTED_OBJECT_CODE = "primary_task_state"
CODEBOOK_AMENDMENT_SHA256 = (
    "fc075e9c5ad15cf418ee3d902abe92702a7f8cfdfff5f0da9ca352f76c399164"
)
_MAPPING_PROXY_TYPE = type(MappingProxyType({}))


class CodebookBuildError(ValueError):
    """The pinned policy-codebook construction contract failed."""


@dataclass(frozen=True, slots=True)
class CodebookBuildResult:
    manifest_path: Path
    private_codebook_root: Path
    report_path: Path
    checksums_path: Path
    manifest_sha256: str
    report_sha256: str
    file_sha256: Mapping[str, str]

    def __post_init__(self) -> None:
        if not isinstance(self.file_sha256, _MAPPING_PROXY_TYPE):
            raise CodebookBuildError("result checksum map must be immutable")


def _strict_mapping(name: str, value: object) -> Mapping[str, Any]:
    if type(value) not in (dict, _MAPPING_PROXY_TYPE):
        raise CodebookBuildError(f"{name} must be an exact JSON object")
    if any(type(key) is not str for key in value):
        raise CodebookBuildError(f"{name} keys must be strings")
    return value


def _strict_sequence(
    name: str, value: object, *, minimum: int = 0, maximum: int = MAX_COLLECTION_ITEMS
) -> tuple[Any, ...]:
    if type(value) not in (list, tuple):
        raise CodebookBuildError(f"{name} must be an exact JSON array")
    result = tuple(value)
    if not minimum <= len(result) <= maximum:
        raise CodebookBuildError(f"{name} has an invalid item count")
    return result


def _strict_text(name: str, value: object) -> str:
    if type(value) is not str or not value or len(value.encode("utf-8")) > 65_536:
        raise CodebookBuildError(f"{name} must be bounded nonempty UTF-8 text")
    return value


def _template_code(criteria: tuple[str, ...]) -> str:
    raw = _canonical_json_bytes(criteria, maximum=MAX_TEXT_BYTES)
    return "template-" + hashlib.sha256(raw).hexdigest()[:16]


def canonical_allowed_projection(scenario: Mapping[str, Any]) -> Mapping[str, Any]:
    """Return only literal declared allowed-field values as immutable JSON."""

    source = _strict_mapping("scenario", scenario)
    allowed_source = _strict_mapping("allowed-set", source["allowed_set"])
    allowed_fields = tuple(
        _strict_text("allowed field name", item)
        for item in _strict_sequence(
            "allowed field names", allowed_source["fields"], minimum=1, maximum=32
        )
    )
    if len(set(allowed_fields)) != len(allowed_fields):
        raise CodebookBuildError("allowed field names must be unique")

    vault = _strict_mapping("private vault", source["private_vault"])
    records = _strict_sequence("private vault records", vault["records"], minimum=1)
    projected: list[dict[str, Any]] = []
    for raw_record in records:
        record = _strict_mapping("private vault record", raw_record)
        fields = _strict_mapping("private vault fields", record["fields"])
        selected: dict[str, Any] = {}
        for field_name in allowed_fields:
            if field_name in fields:
                selected[field_name] = fields[field_name]
        projected.append(selected)
    frozen = _freeze_json({"records": projected})
    _canonical_json_bytes(frozen, maximum=MAX_TEXT_BYTES)
    if not isinstance(frozen, _MAPPING_PROXY_TYPE):
        raise CodebookBuildError("allowed projection did not freeze")
    return frozen


def _projection_is_empty(projection: Mapping[str, Any]) -> bool:
    records = projection["records"]
    return all(not record for record in records)


def _source_sha256() -> str:
    return hashlib.sha256(
        _read_regular(
            Path(__file__), maximum=2_097_152, label="builder source"
        )
    ).hexdigest()


def _verify_amendment(path: Path) -> None:
    try:
        metadata = path.lstat()
        if not path.is_file() or path.is_symlink() or metadata.st_size > 262_144:
            raise CodebookBuildError("codebook amendment path is unsafe")
        observed = hashlib.sha256(path.read_bytes()).hexdigest()
    except CodebookBuildError:
        raise
    except BaseException:
        raise CodebookBuildError("codebook amendment cannot be authenticated") from None
    if observed != CODEBOOK_AMENDMENT_SHA256:
        raise CodebookBuildError("codebook amendment SHA-256 does not match the pin")


def _read_regular(path: Path, *, maximum: int, label: str) -> bytes:
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or path.is_symlink() or metadata.st_size > maximum:
            raise CodebookBuildError(f"{label} path is unsafe")
        flags = os.O_RDONLY | (os.O_NOFOLLOW if hasattr(os, "O_NOFOLLOW") else 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                raise CodebookBuildError(f"{label} changed during validation")
            raw = b""
            while len(raw) <= maximum:
                chunk = os.read(descriptor, min(65_536, maximum + 1 - len(raw)))
                if not chunk:
                    break
                raw += chunk
            if len(raw) > maximum:
                raise CodebookBuildError(f"{label} exceeds its bound")
            return raw
        finally:
            os.close(descriptor)
    except CodebookBuildError:
        raise
    except BaseException:
        raise CodebookBuildError(f"{label} cannot be authenticated") from None


def _strict_json_document(raw: bytes, *, maximum: int, label: str) -> dict[str, Any]:
    if len(raw) > maximum:
        raise CodebookBuildError(f"{label} exceeds its bound")

    def reject_constant(value: str) -> None:
        raise CodebookBuildError(f"{label} contains non-finite JSON: {value}")

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise CodebookBuildError(f"{label} contains a duplicate key")
            result[key] = value
        return result

    try:
        body = json.loads(
            raw.decode("utf-8"),
            parse_constant=reject_constant,
            object_pairs_hook=reject_duplicates,
        )
    except CodebookBuildError:
        raise
    except BaseException:
        raise CodebookBuildError(f"{label} is malformed") from None
    if type(body) is not dict or _canonical_json_bytes(body, maximum=maximum) != raw:
        raise CodebookBuildError(f"{label} is not a canonical JSON object")
    return body


def _directory_flags() -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _open_pinned_directory(path: Path, *, label: str) -> tuple[int, tuple[int, int]]:
    descriptor = -1
    try:
        before = path.lstat()
        if not path.is_dir() or path.is_symlink():
            raise CodebookBuildError(f"{label} is missing or unsafe")
        absolute = Path(os.path.abspath(path))
        descriptor = os.open(absolute.anchor, _directory_flags())
        for component in absolute.parts[1:]:
            child = os.open(component, _directory_flags(), dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        opened = os.fstat(descriptor)
    except CodebookBuildError:
        if descriptor >= 0:
            os.close(descriptor)
        raise
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        raise CodebookBuildError(f"{label} cannot be pinned") from None
    identity = (opened.st_dev, opened.st_ino)
    if identity != (before.st_dev, before.st_ino):
        os.close(descriptor)
        raise CodebookBuildError(f"{label} changed during pinning")
    return descriptor, identity


def _write_exclusive_at(directory_fd: int, filename: str, raw: bytes) -> None:
    if Path(filename).name != filename or filename in {"", ".", ".."}:
        raise CodebookBuildError("codebook output filename is unsafe")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(filename, flags, 0o600, dir_fd=directory_fd)
    except FileExistsError as exc:
        raise CodebookBuildError("codebook output already exists") from exc
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise CodebookBuildError("codebook output write did not progress")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _path_has_identity(path: Path, identity: tuple[int, int]) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    return (
        not path.is_symlink()
        and path.is_dir()
        and (metadata.st_dev, metadata.st_ino) == identity
    )


def _build_documents(
    scenarios: Sequence[Mapping[str, Any]],
    *,
    builder_sha256: str,
    construction_loader_sha256: str,
) -> tuple[bytes, dict[str, bytes], bytes]:
    if type(scenarios) is not tuple or len(scenarios) != CORPUS_ROWS:
        raise CodebookBuildError("pinned corpus row count is invalid")

    groups: dict[tuple[str, ...], dict[str, Any]] = {}
    scenario_ids: set[str] = set()
    for scenario in scenarios:
        source = _strict_mapping("scenario", scenario)
        scenario_id = _strict_text("scenario identifier", source["scenario_id"])
        if scenario_id in scenario_ids:
            raise CodebookBuildError("scenario identifiers are not unique")
        scenario_ids.add(scenario_id)
        objective = _strict_mapping("objective", source["objective"])
        criteria = tuple(
            _strict_text("success criterion", item)
            for item in _strict_sequence(
                "success criteria", objective["success_criteria"], minimum=1, maximum=32
            )
        )
        if len(set(criteria)) != len(criteria):
            raise CodebookBuildError("success criteria are not unique")
        allowed_source = _strict_mapping("allowed-set", source["allowed_set"])
        allowed_fields = tuple(
            _strict_text("allowed field name", item)
            for item in _strict_sequence(
                "allowed field names", allowed_source["fields"], minimum=1, maximum=32
            )
        )
        if len(set(allowed_fields)) != len(allowed_fields):
            raise CodebookBuildError("allowed field names are not unique")

        group = groups.get(criteria)
        if group is None:
            group = {
                "allowed_fields": allowed_fields,
                "row_count": 0,
                "policy_abstention_rows": 0,
                "payloads": set(),
                "field_presence_rows": {field_name: 0 for field_name in allowed_fields},
            }
            groups[criteria] = group
        elif group["allowed_fields"] != allowed_fields:
            raise CodebookBuildError(
                "one public template is bound to inconsistent allowed-field schemas"
            )

        projection = canonical_allowed_projection(source)
        group["row_count"] += 1
        if _projection_is_empty(projection):
            group["policy_abstention_rows"] += 1
        else:
            payload = _canonical_json_bytes(projection, maximum=MAX_TEXT_BYTES).decode("ascii")
            group["payloads"].add(payload)

        projection_records = projection["records"]
        for field_name in allowed_fields:
            if any(field_name in record for record in projection_records):
                group["field_presence_rows"][field_name] += 1

    if len(groups) != TEMPLATE_COUNT:
        raise CodebookBuildError("pinned corpus does not contain exactly 16 public templates")

    private_documents: dict[str, bytes] = {}
    public_templates: list[dict[str, Any]] = []
    report_templates: list[dict[str, Any]] = []
    observed_codes: dict[str, tuple[str, ...]] = {}
    for criteria, group in groups.items():
        template_code = _template_code(criteria)
        previous = observed_codes.setdefault(template_code, criteria)
        if previous != criteria:
            raise CodebookBuildError("public template-code collision")
        observer_spec_id = "agentleak-observer-" + template_code.removeprefix("template-")
        payloads = ["ABSTAIN", *sorted(group["payloads"])]
        entries = [
            {"value_code": index, "payload": payload}
            for index, payload in enumerate(payloads)
        ]
        support_cardinality = len(entries)
        routes: list[dict[str, Any]] = []
        for channel in ALL_CHANNELS:
            route_name = f"{ROUTE_NAME}_{channel.value}"
            filename = f"codebook-{template_code}-{channel.value}.json"
            private = {
                "schema_version": PRIVATE_SCHEMA_VERSION,
                "template_code": template_code,
                "observer_spec_id": observer_spec_id,
                "route_name": route_name,
                "channel": channel.value,
                "protected_object_code": PROTECTED_OBJECT_CODE,
                "entries": entries,
            }
            private_raw = _canonical_json_bytes(private, maximum=MAX_RAW_RECORD_BYTES)
            private_sha256 = hashlib.sha256(private_raw).hexdigest()
            private_documents[filename] = private_raw
            routes.append(
                {
                    "template_code": template_code,
                    "observer_spec_id": observer_spec_id,
                    "route_name": route_name,
                    "channel": channel.value,
                    "protected_object_code": PROTECTED_OBJECT_CODE,
                    "requires_capability": False,
                    "ordered_value_codes": list(range(support_cardinality)),
                    "codebook_sha256": private_sha256,
                    "support_cardinality": support_cardinality,
                    "codebook_file": filename,
                }
            )
        conditional_support = 4 + sum(
            route["support_cardinality"] + 5 for route in routes
        )
        event_charge_units = (
            conditional_support - 1
        ).bit_length() * ACCOUNTING_UNITS_PER_BIT
        observer_spec = {
            "schema_version": "sluice-agentleak-observer-spec-v1",
            "template_code": template_code,
            "observer_spec_id": observer_spec_id,
            "accounting_units_per_bit": ACCOUNTING_UNITS_PER_BIT,
            "routes": [
                {
                    key: route[key]
                    for key in (
                        "template_code",
                        "observer_spec_id",
                        "route_name",
                        "channel",
                        "protected_object_code",
                        "requires_capability",
                        "ordered_value_codes",
                        "codebook_sha256",
                        "support_cardinality",
                    )
                }
                for route in routes
            ],
        }
        observer_spec_sha256 = hashlib.sha256(
            _canonical_json_bytes(
                observer_spec,
                maximum=MAX_MANIFEST_BYTES,
            )
        ).hexdigest()
        public_templates.append(
            {
                "template_code": template_code,
                "success_criteria": list(criteria),
                "allowed_field_names": list(group["allowed_fields"]),
                "observer_spec_id": observer_spec_id,
                "observer_spec_sha256": observer_spec_sha256,
                "accounting_units_per_bit": ACCOUNTING_UNITS_PER_BIT,
                "horizon": HORIZON,
                "event_charge_units": event_charge_units,
                "lifetime_budget_units": HORIZON * event_charge_units,
                "routes": routes,
            }
        )
        report_templates.append(
            {
                "template_code": template_code,
                "row_count": group["row_count"],
                "route_support_cardinality": support_cardinality,
                "policy_abstention_rows": group["policy_abstention_rows"],
                "field_presence_rows": dict(group["field_presence_rows"]),
            }
        )

    public_templates.sort(key=lambda item: item["template_code"])
    report_templates.sort(key=lambda item: item["template_code"])
    manifest = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "manifest_id": (
            "agentleak-codebooks-"
            + CORPUS_SHA256[:12]
            + "-"
            + builder_sha256[:12]
        ),
        "corpus_sha256": CORPUS_SHA256,
        "corpus_rows": CORPUS_ROWS,
        "builder_source_sha256": builder_sha256,
        "template_count": TEMPLATE_COUNT,
        "templates": public_templates,
    }
    manifest_raw = _canonical_json_bytes(manifest, maximum=MAX_MANIFEST_BYTES * 16)
    manifest_sha256 = hashlib.sha256(manifest_raw).hexdigest()
    report = {
        "schema_version": SCHEMA_VERSION,
        "builder_source_sha256": builder_sha256,
        "construction_corpus_loader_source_sha256": construction_loader_sha256,
        "codebook_amendment_sha256": CODEBOOK_AMENDMENT_SHA256,
        "corpus_sha256": CORPUS_SHA256,
        "corpus_rows": CORPUS_ROWS,
        "template_count": TEMPLATE_COUNT,
        "manifest_sha256": manifest_sha256,
        "mapped_rows": sum(
            item["row_count"] - item["policy_abstention_rows"]
            for item in report_templates
        ),
        "policy_abstention_rows": sum(
            item["policy_abstention_rows"] for item in report_templates
        ),
        "templates": report_templates,
    }
    report_raw = _canonical_json_bytes(report, maximum=MAX_MANIFEST_BYTES * 16)
    return manifest_raw, private_documents, report_raw


def validate_codebook_construction_artifacts(
    *,
    manifest_path: str | Path,
    expected_manifest_sha256: str,
    private_codebook_root: str | Path,
    report_path: str | Path,
    expected_report_sha256: str,
    checksums_path: str | Path,
    expected_builder_source_sha256: str,
    expected_construction_loader_source_sha256: str,
):
    """Strictly authenticate the consumed manifest, report, and checksum inventory."""

    bundle = load_codebook_bundle(
        manifest_path,
        expected_sha256=expected_manifest_sha256,
        private_codebook_root=private_codebook_root,
    )
    if bundle.builder_source_sha256 != expected_builder_source_sha256:
        raise CodebookBuildError("consumed manifest has the wrong builder source SHA-256")
    output_root = Path(manifest_path).parent
    if (
        Path(report_path).parent != output_root
        or Path(checksums_path).parent != output_root
        or Path(private_codebook_root).parent != output_root
    ):
        raise CodebookBuildError("construction artifacts do not share one output root")
    try:
        output_names = {item.name for item in output_root.iterdir()}
    except BaseException:
        raise CodebookBuildError("construction output inventory cannot be enumerated") from None
    if output_names != {
        Path(manifest_path).name,
        Path(report_path).name,
        Path(checksums_path).name,
        Path(private_codebook_root).name,
    }:
        raise CodebookBuildError("construction output inventory is not exact")
    report_raw = _read_regular(
        Path(report_path), maximum=MAX_MANIFEST_BYTES * 16, label="construction report"
    )
    if hashlib.sha256(report_raw).hexdigest() != expected_report_sha256:
        raise CodebookBuildError("construction report SHA-256 does not match the pin")
    report = _strict_json_document(
        report_raw, maximum=MAX_MANIFEST_BYTES * 16, label="construction report"
    )
    expected_report_keys = {
        "schema_version",
        "builder_source_sha256",
        "construction_corpus_loader_source_sha256",
        "codebook_amendment_sha256",
        "corpus_sha256",
        "corpus_rows",
        "template_count",
        "manifest_sha256",
        "mapped_rows",
        "policy_abstention_rows",
        "templates",
    }
    if set(report) != expected_report_keys:
        raise CodebookBuildError("construction report schema is not exact")
    if (
        report["schema_version"] != SCHEMA_VERSION
        or report["builder_source_sha256"] != expected_builder_source_sha256
        or report["construction_corpus_loader_source_sha256"]
        != expected_construction_loader_source_sha256
        or report["codebook_amendment_sha256"] != CODEBOOK_AMENDMENT_SHA256
        or report["corpus_sha256"] != CORPUS_SHA256
        or type(report["corpus_rows"]) is not int
        or report["corpus_rows"] != CORPUS_ROWS
        or type(report["template_count"]) is not int
        or report["template_count"] != TEMPLATE_COUNT
        or report["manifest_sha256"] != expected_manifest_sha256
        or type(report["mapped_rows"]) is not int
        or type(report["policy_abstention_rows"]) is not int
        or report["mapped_rows"] + report["policy_abstention_rows"] != CORPUS_ROWS
    ):
        raise CodebookBuildError("construction report binding is invalid")
    templates = _strict_sequence(
        "construction report templates", report["templates"], minimum=16, maximum=16
    )
    template_keys = {
        "template_code",
        "row_count",
        "route_support_cardinality",
        "policy_abstention_rows",
        "field_presence_rows",
    }
    for item in templates:
        source = _strict_mapping("construction report template", item)
        if set(source) != template_keys:
            raise CodebookBuildError("construction report template schema is not exact")
        _strict_text("construction report template_code", source["template_code"])
        for name in ("row_count", "route_support_cardinality", "policy_abstention_rows"):
            if type(source[name]) is not int or source[name] < 0:
                raise CodebookBuildError(f"construction report {name} must be an integer")
        presence = _strict_mapping("construction report field presence", source["field_presence_rows"])
        if any(type(value) is not int or value < 0 for value in presence.values()):
            raise CodebookBuildError("construction report field presence is malformed")

    manifest_raw = _read_regular(
        Path(manifest_path), maximum=MAX_MANIFEST_BYTES * 16, label="codebook manifest"
    )
    manifest = _strict_json_document(
        manifest_raw, maximum=MAX_MANIFEST_BYTES * 16, label="codebook manifest"
    )
    expected_files: dict[str, str] = {
        "codebook-manifest.json": expected_manifest_sha256,
        "construction-report.json": expected_report_sha256,
    }
    root = Path(private_codebook_root)
    expected_private_names: set[str] = set()
    for template in manifest["templates"]:
        for route in template["routes"]:
            filename = route["codebook_file"]
            if Path(filename).name != filename:
                raise CodebookBuildError("private codebook inventory path is unsafe")
            relative = f"private/{filename}"
            if relative in expected_files:
                raise CodebookBuildError("private codebook inventory repeats a file")
            expected_private_names.add(filename)
            raw = _read_regular(
                root / filename, maximum=MAX_RAW_RECORD_BYTES, label="private codebook"
            )
            digest = hashlib.sha256(raw).hexdigest()
            if digest != route["codebook_sha256"]:
                raise CodebookBuildError("private codebook inventory hash mismatch")
            expected_files[relative] = digest
    try:
        observed_private_names = {item.name for item in root.iterdir()}
    except BaseException:
        raise CodebookBuildError("private codebook inventory cannot be enumerated") from None
    if observed_private_names != expected_private_names:
        raise CodebookBuildError("private codebook inventory is not exact")
    checksum_raw = _read_regular(
        Path(checksums_path), maximum=MAX_MANIFEST_BYTES, label="SHA256SUMS"
    )
    expected_checksum_raw = "".join(
        f"{digest}  {relative}\n" for relative, digest in sorted(expected_files.items())
    ).encode("ascii")
    if checksum_raw != expected_checksum_raw:
        raise CodebookBuildError("SHA256SUMS is not canonical and complete")
    return bundle


def build_codebook_bundle(
    *,
    corpus_path: str | Path,
    output_directory: str | Path,
    amendment_path: str | Path | None = None,
) -> CodebookBuildResult:
    """Create a verified bundle once; an existing output path is never reused."""

    try:
        corpus = load_codebook_construction_corpus(corpus_path)
    except ConstructionCorpusError as exc:
        raise CodebookBuildError("construction-only corpus projection failed") from exc
    if corpus.sha256 != CORPUS_SHA256:
        raise CodebookBuildError("pinned corpus identity is invalid")
    amendment = (
        Path(amendment_path)
        if amendment_path is not None
        else Path(__file__).resolve().parents[4]
        / "analysis"
        / "AGENTLEAK_EXECUTION_AMENDMENT_2.md"
    )
    _verify_amendment(amendment)
    builder_sha256 = _source_sha256()
    construction_loader_sha256 = construction_loader_source_sha256()
    manifest_raw, private_documents, report_raw = _build_documents(
        corpus.rows,
        builder_sha256=builder_sha256,
        construction_loader_sha256=construction_loader_sha256,
    )

    output = Path(output_directory)
    if output.exists() or output.is_symlink():
        raise CodebookBuildError("codebook output already exists")
    parent = output.parent
    parent_fd, parent_identity = _open_pinned_directory(
        parent, label="codebook output parent"
    )
    root_fd: int | None = None
    private_fd: int | None = None
    try:
        os.mkdir(output.name, 0o700, dir_fd=parent_fd)
        root_fd = os.open(output.name, _directory_flags(), dir_fd=parent_fd)
        root_stat = os.fstat(root_fd)
        root_identity = (root_stat.st_dev, root_stat.st_ino)
        os.mkdir("private", 0o700, dir_fd=root_fd)
        private_fd = os.open("private", _directory_flags(), dir_fd=root_fd)
        private_stat = os.fstat(private_fd)
        private_identity = (private_stat.st_dev, private_stat.st_ino)

        manifest_path = output / "codebook-manifest.json"
        private_root = output / "private"
        report_path = output / "construction-report.json"
        checksums_path = output / "SHA256SUMS"
        _write_exclusive_at(root_fd, manifest_path.name, manifest_raw)
        for filename, raw in sorted(private_documents.items()):
            _write_exclusive_at(private_fd, filename, raw)
        _write_exclusive_at(root_fd, report_path.name, report_raw)

        file_sha256: dict[str, str] = {
            "codebook-manifest.json": hashlib.sha256(manifest_raw).hexdigest(),
            "construction-report.json": hashlib.sha256(report_raw).hexdigest(),
        }
        for filename, raw in sorted(private_documents.items()):
            file_sha256[f"private/{filename}"] = hashlib.sha256(raw).hexdigest()
        checksum_raw = "".join(
            f"{digest}  {relative}\n" for relative, digest in sorted(file_sha256.items())
        ).encode("ascii")
        _write_exclusive_at(root_fd, checksums_path.name, checksum_raw)
        os.fsync(private_fd)
        os.fsync(root_fd)
        os.fsync(parent_fd)
        if not _path_has_identity(parent, parent_identity):
            raise CodebookBuildError("codebook output parent identity changed")
        if not _path_has_identity(output, root_identity):
            raise CodebookBuildError("codebook output root identity changed")
        if not _path_has_identity(private_root, private_identity):
            raise CodebookBuildError("private codebook root identity changed")
    except FileExistsError as exc:
        raise CodebookBuildError("codebook output already exists") from exc
    finally:
        if private_fd is not None:
            os.close(private_fd)
        if root_fd is not None:
            os.close(root_fd)
        os.close(parent_fd)

    manifest_sha256 = file_sha256["codebook-manifest.json"]
    validate_codebook_construction_artifacts(
        manifest_path=manifest_path,
        expected_manifest_sha256=manifest_sha256,
        private_codebook_root=private_root,
        report_path=report_path,
        expected_report_sha256=file_sha256["construction-report.json"],
        checksums_path=checksums_path,
        expected_builder_source_sha256=builder_sha256,
        expected_construction_loader_source_sha256=construction_loader_sha256,
    )
    return CodebookBuildResult(
        manifest_path=manifest_path,
        private_codebook_root=private_root,
        report_path=report_path,
        checksums_path=checksums_path,
        manifest_sha256=manifest_sha256,
        report_sha256=file_sha256["construction-report.json"],
        file_sha256=MappingProxyType(dict(sorted(file_sha256.items()))),
    )


def _main() -> int:
    parser = argparse.ArgumentParser(
        description="Build the pinned AgentLeak secret-independent codebooks"
    )
    parser.add_argument("--corpus", required=True)
    parser.add_argument("--output", required=True)
    arguments = parser.parse_args()
    result = build_codebook_bundle(
        corpus_path=arguments.corpus, output_directory=arguments.output
    )
    summary = {
        "schema_version": SCHEMA_VERSION,
        "manifest_sha256": result.manifest_sha256,
        "report_sha256": result.report_sha256,
        "construction_corpus_loader_source_sha256": construction_loader_source_sha256(),
        "file_count": len(result.file_sha256) + 1,
    }
    print(_canonical_json_bytes(summary, maximum=MAX_TEXT_BYTES).decode("ascii"))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())


__all__ = [
    "CODEBOOK_AMENDMENT_SHA256",
    "CodebookBuildError",
    "CodebookBuildResult",
    "build_codebook_bundle",
    "canonical_allowed_projection",
    "validate_codebook_construction_artifacts",
]
