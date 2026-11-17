"""Unit contract for the generated exact pytest-node manifest."""

from __future__ import annotations

import json

import pytest

from sluice_v2.test_manifest import (
    MAX_MANIFEST_BYTES,
    MAX_NODEID_BYTES,
    ManifestError,
    SCHEMA_VERSION,
    build_manifest,
    execute_manifest,
    load_manifest,
    nodeids_sha256,
    validate_manifest,
)


def test_build_manifest_sorts_and_hashes_exact_node_ids():
    value = build_manifest(("b.py::test_b", "a.py::test_a"), ("tests",))
    assert value["schema_version"] == SCHEMA_VERSION
    assert value["nodeids"] == ["a.py::test_a", "b.py::test_b"]
    assert value["nodeids_sha256"] == nodeids_sha256(value["nodeids"])


def test_manifest_rejects_duplicates_unknown_fields_and_hash_drift():
    with pytest.raises(ManifestError, match="duplicate"):
        build_manifest(("same", "same"), ("tests",))
    valid = build_manifest(("a.py::test_a",), ("tests",))
    unknown = dict(valid, surprise=True)
    with pytest.raises(ManifestError, match="unknown"):
        validate_manifest(unknown)
    drifted = dict(valid, nodeids_sha256="0" * 64)
    with pytest.raises(ManifestError, match="hash-invalid"):
        validate_manifest(drifted)


def test_loader_requires_canonical_format(tmp_path):
    value = build_manifest(("a.py::test_a",), ("tests",))
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ManifestError, match="canonical"):
        load_manifest(path)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    assert load_manifest(path) == value

    path.write_text('{"schema_version":"x","schema_version":"y"}\n', encoding="utf-8")
    with pytest.raises(ManifestError, match="duplicate"):
        load_manifest(path)


def test_loader_rejects_nonfinite_and_oversized_input(tmp_path):
    path = tmp_path / "manifest.json"
    path.write_text('{"value":NaN}\n', encoding="utf-8")
    with pytest.raises(ManifestError, match="non-finite"):
        load_manifest(path)

    path.write_bytes(b" " * (MAX_MANIFEST_BYTES + 1))
    with pytest.raises(ManifestError, match="byte bound"):
        load_manifest(path)


def test_builder_rejects_ambiguous_or_unbounded_sequences():
    with pytest.raises(ManifestError, match="list or tuple"):
        build_manifest("a.py::test_a", ("tests",))
    with pytest.raises(ManifestError, match="bounded"):
        build_manifest(("x" * (MAX_NODEID_BYTES + 1),), ("tests",))
    with pytest.raises(ManifestError, match="list or tuple"):
        build_manifest(("a.py::test_a",), "tests")


def test_execute_manifest_requires_a_validated_manifest():
    with pytest.raises(ManifestError, match="schema"):
        execute_manifest(
            {
                "schema_version": "wrong",
                "testpaths": ["tests"],
                "nodeids": [],
                "nodeids_sha256": nodeids_sha256([]),
            }
        )


@pytest.mark.parametrize("bad", [True, 1, "node", None])
def test_manifest_types_are_strict(bad):
    with pytest.raises((ManifestError, TypeError)):
        validate_manifest(bad)
