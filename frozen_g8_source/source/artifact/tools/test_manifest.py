#!/usr/bin/env python3
"""Generate or verify the exact pytest node-ID manifest.

The artifact runner compares collection against this version-controlled list
instead of embedding a stale integer test count.  Collection errors, additions,
deletions, duplicate node IDs, and manifest drift all fail closed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Sequence

import pytest


SCHEMA_VERSION = "sluice.pytest-manifest.v1"
DEFAULT_TESTPATHS = ("tests", "sluice_v2/tests", "integrations")
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_NODEIDS = 100_000
MAX_NODEID_BYTES = 4_096
MAX_TESTPATHS = 64
MAX_TESTPATH_BYTES = 1_024
MANIFEST_KEYS = frozenset(
    {"schema_version", "testpaths", "nodeids", "nodeids_sha256"}
)


class ManifestError(ValueError):
    """The collection or frozen manifest is unsafe or inconsistent."""


def _unique_pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ManifestError(f"duplicate test-manifest key: {key}")
        value[key] = item
    return value


def _reject_json_constant(value: str):
    raise ManifestError(f"non-finite JSON constant is forbidden: {value}")


def nodeids_sha256(nodeids: Sequence[str]) -> str:
    if type(nodeids) not in (list, tuple):
        raise TypeError("nodeids must be a list or tuple")
    body = "".join(f"{nodeid}\n" for nodeid in nodeids).encode("utf-8")
    return hashlib.sha256(body).hexdigest()


def build_manifest(nodeids: Sequence[str], testpaths: Sequence[str]) -> dict[str, object]:
    if type(nodeids) not in (list, tuple):
        raise ManifestError("nodeids must be a list or tuple")
    if len(nodeids) > MAX_NODEIDS:
        raise ManifestError("pytest collection exceeds the supported node-ID bound")
    if any(type(nodeid) is not str or not nodeid for nodeid in nodeids):
        raise ManifestError("every node ID must be a nonempty string")
    if any(
        "\n" in nodeid
        or "\r" in nodeid
        or len(nodeid.encode("utf-8")) > MAX_NODEID_BYTES
        for nodeid in nodeids
    ):
        raise ManifestError("node IDs must be bounded and contain no line breaks")
    ordered = tuple(sorted(nodeids))
    if len(set(ordered)) != len(ordered):
        raise ManifestError("pytest collection contains duplicate node IDs")
    if type(testpaths) not in (list, tuple):
        raise ManifestError("testpaths must be a list or tuple")
    paths = tuple(testpaths)
    if len(paths) > MAX_TESTPATHS:
        raise ManifestError("testpaths exceeds the supported bound")
    if not paths or any(type(path) is not str or not path for path in paths):
        raise ManifestError("testpaths must be nonempty strings")
    if any(
        "\n" in path
        or "\r" in path
        or len(path.encode("utf-8")) > MAX_TESTPATH_BYTES
        for path in paths
    ):
        raise ManifestError("testpaths must be bounded and contain no line breaks")
    if len(set(paths)) != len(paths):
        raise ManifestError("testpaths contains duplicates")
    return {
        "schema_version": SCHEMA_VERSION,
        "testpaths": list(paths),
        "nodeids": list(ordered),
        "nodeids_sha256": nodeids_sha256(ordered),
    }


def validate_manifest(value: object) -> dict[str, object]:
    if type(value) is not dict:
        raise ManifestError("test manifest must be a JSON object")
    if frozenset(value) != MANIFEST_KEYS:
        raise ManifestError("test manifest has missing or unknown fields")
    if value["schema_version"] != SCHEMA_VERSION:
        raise ManifestError("unsupported test-manifest schema")
    nodeids = value["nodeids"]
    testpaths = value["testpaths"]
    if type(nodeids) is not list or type(testpaths) is not list:
        raise ManifestError("testpaths and nodeids must be JSON arrays")
    rebuilt = build_manifest(nodeids, testpaths)
    if rebuilt != value:
        raise ManifestError("test manifest is unsorted, duplicated, or hash-invalid")
    return rebuilt


def load_manifest(path: Path) -> dict[str, object]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ManifestError(f"cannot read test manifest: {path}") from exc
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ManifestError("test manifest exceeds the supported byte bound")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_pairs,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ManifestError("test manifest is not strict UTF-8 JSON") from exc
    canonical = (
        json.dumps(value, ensure_ascii=True, allow_nan=False, indent=2, sort_keys=True)
        + "\n"
    ).encode("utf-8")
    if canonical != raw:
        raise ManifestError("test manifest is not canonical formatted JSON")
    return validate_manifest(value)


class _CollectionPlugin:
    def __init__(self) -> None:
        self.nodeids: tuple[str, ...] | None = None

    def pytest_collection_finish(self, session: pytest.Session) -> None:
        self.nodeids = tuple(item.nodeid for item in session.items)


def collect_nodeids(testpaths: Sequence[str]) -> tuple[str, ...]:
    plugin = _CollectionPlugin()
    status = pytest.main(
        ["--collect-only", "-qq", "--disable-warnings", *testpaths],
        plugins=[plugin],
    )
    if status != pytest.ExitCode.OK or plugin.nodeids is None:
        raise ManifestError(f"pytest collection failed with exit status {int(status)}")
    manifest = build_manifest(plugin.nodeids, testpaths)
    return tuple(manifest["nodeids"])  # type: ignore[arg-type]


def _write_manifest(path: Path, value: dict[str, object]) -> None:
    encoded = (
        json.dumps(value, ensure_ascii=True, allow_nan=False, indent=2, sort_keys=True)
        + "\n"
    ).encode("utf-8")
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(encoded)
    temporary.replace(path)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("test-manifest.json"),
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--verify", action="store_true")
    mode.add_argument("--write", action="store_true")
    arguments = parser.parse_args(argv)

    try:
        if arguments.write:
            nodeids = collect_nodeids(DEFAULT_TESTPATHS)
            value = build_manifest(nodeids, DEFAULT_TESTPATHS)
            _write_manifest(arguments.manifest, value)
            print(
                f"wrote {arguments.manifest}: {len(nodeids)} exact pytest node IDs, "
                f"sha256={value['nodeids_sha256']}"
            )
            return 0

        expected = load_manifest(arguments.manifest)
        paths = tuple(expected["testpaths"])  # type: ignore[arg-type]
        actual_nodeids = collect_nodeids(paths)
        actual = build_manifest(actual_nodeids, paths)
        if actual != expected:
            expected_set = set(expected["nodeids"])  # type: ignore[arg-type]
            actual_set = set(actual["nodeids"])  # type: ignore[arg-type]
            missing = sorted(expected_set - actual_set)
            added = sorted(actual_set - expected_set)
            raise ManifestError(
                "pytest collection differs from the frozen manifest: "
                f"missing={missing[:20]}, added={added[:20]}"
            )
        print(
            f"verified {len(actual_nodeids)} exact pytest node IDs, "
            f"sha256={actual['nodeids_sha256']}"
        )
        return 0
    except ManifestError as exc:
        print(f"FAILED: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
