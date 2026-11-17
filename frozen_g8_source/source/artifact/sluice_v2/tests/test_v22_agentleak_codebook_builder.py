from __future__ import annotations

import ast
from collections.abc import Mapping
import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
import sys
from types import MappingProxyType

import pytest

from sluice_v2.evaluation.agentleak import CORPUS_SHA256, load_pinned_corpus
from sluice_v2.evaluation.agentleak_construction_corpus import (
    construction_loader_source_sha256,
    project_codebook_support_row,
)
from sluice_v2.evaluation.agentleak_codebooks import (
    CODEBOOK_AMENDMENT_SHA256,
    CodebookBuildError,
    build_codebook_bundle,
    canonical_allowed_projection,
    validate_codebook_construction_artifacts,
)
from sluice_v2.evaluation.agentleak_fullstack import (
    ALL_CHANNELS,
    CodebookSelectionStatus,
    RouteRegistration,
    load_codebook_bundle,
    seal_template_codebooks,
)


ARTIFACT_ROOT = Path(__file__).resolve().parents[2]
REPOSITORY_ROOT = ARTIFACT_ROOT.parents[1]
CORPUS_PATH = ARTIFACT_ROOT / "benchmarks" / "agentleak" / "scenarios_full_1000.jsonl"
BUILDER_PATH = ARTIFACT_ROOT / "sluice_v2" / "evaluation" / "agentleak_codebooks.py"
CONSTRUCTION_LOADER_PATH = (
    ARTIFACT_ROOT / "sluice_v2" / "evaluation" / "agentleak_construction_corpus.py"
)


EXPECTED_TEMPLATE_SUMMARY = {
    "template-235a5182647e334a": (73, 68, 6),
    "template-27a598682d3e39d6": (64, 46, 10),
    "template-33f98fe658a3843e": (64, 52, 13),
    "template-408ac80024575c4a": (56, 57, 0),
    "template-53f147ace8086783": (69, 64, 6),
    "template-5b6d24ab5741bb42": (54, 51, 4),
    "template-856e83086079ebd8": (64, 55, 10),
    "template-85f8ad1c3dc429d8": (59, 60, 0),
    "template-88f7716a3e3b9584": (64, 1, 64),
    "template-944d03d9f226983e": (58, 53, 6),
    "template-9d887e556d971172": (58, 1, 58),
    "template-bd1a65b838297835": (70, 62, 9),
    "template-c6f43775aaeaef1e": (57, 54, 4),
    "template-e06946f5ebcd72e4": (60, 55, 6),
    "template-ecea08ab97bae19f": (66, 67, 0),
    "template-ed8bd06337446201": (64, 65, 0),
}


def _canonical(value) -> bytes:
    return json.dumps(
        _thaw(value),
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _thaw(value):
    if isinstance(value, MappingProxyType) or type(value) is dict:
        return {key: _thaw(item) for key, item in value.items()}
    if type(value) in (tuple, list):
        return [_thaw(item) for item in value]
    return value


def _template_code(scenario) -> str:
    criteria = list(scenario["objective"]["success_criteria"])
    return "template-" + hashlib.sha256(_canonical(criteria)).hexdigest()[:16]


def _is_empty_projection(projection) -> bool:
    return all(not record for record in projection["records"])


def test_exact_corpus_build_is_deterministic_loadable_and_maps_every_row(tmp_path: Path) -> None:
    first = build_codebook_bundle(corpus_path=CORPUS_PATH, output_directory=tmp_path / "a")
    second = build_codebook_bundle(corpus_path=CORPUS_PATH, output_directory=tmp_path / "b")
    assert first.manifest_sha256 == second.manifest_sha256
    assert first.report_sha256 == second.report_sha256
    assert first.file_sha256 == second.file_sha256

    report = json.loads(first.report_path.read_text(encoding="utf-8"))
    assert report["corpus_sha256"] == CORPUS_SHA256
    assert report["construction_corpus_loader_source_sha256"] == hashlib.sha256(
        CONSTRUCTION_LOADER_PATH.read_bytes()
    ).hexdigest()
    assert report["codebook_amendment_sha256"] == CODEBOOK_AMENDMENT_SHA256
    assert report["corpus_rows"] == 1_000
    assert report["template_count"] == 16
    assert report["mapped_rows"] == 804
    assert report["policy_abstention_rows"] == 196
    observed = {
        item["template_code"]: (
            item["row_count"],
            item["route_support_cardinality"],
            item["policy_abstention_rows"],
        )
        for item in report["templates"]
    }
    assert observed == EXPECTED_TEMPLATE_SUMMARY

    bundle = load_codebook_bundle(
        first.manifest_path,
        expected_sha256=first.manifest_sha256,
        private_codebook_root=first.private_codebook_root,
    )
    corpus = load_pinned_corpus(CORPUS_PATH)
    mapped = abstained = 0
    for scenario in corpus.scenarios:
        template_code = _template_code(scenario)
        binding = bundle.template(template_code)
        sealed = seal_template_codebooks(
            bundle=bundle,
            template_code=template_code,
            registrations=tuple(
                RouteRegistration.from_manifest(route) for route in binding.routes
            ),
        )
        projection = canonical_allowed_projection(scenario)
        route_name = next(
            route.route_name
            for route in binding.routes
            if route.channel.value == "C4_tool_output"
        )
        selection = sealed.attach_private_state(
            allowed_projection=projection
        ).select_allowed_projection(route_name=route_name)
        if _is_empty_projection(projection):
            assert selection.status is CodebookSelectionStatus.ABSTAIN
            assert selection.payload == "ABSTAIN"
            abstained += 1
        else:
            assert selection.status is CodebookSelectionStatus.MAPPED
            assert selection.payload.encode("ascii") == _canonical(projection)
            mapped += 1
    assert (mapped, abstained) == (804, 196)


def test_manifest_binds_full_builder_source_and_exact_c1_c7_observer_spec(
    tmp_path: Path,
) -> None:
    result = build_codebook_bundle(
        corpus_path=CORPUS_PATH, output_directory=tmp_path / "complete-observer"
    )
    manifest = json.loads(result.manifest_path.read_text(encoding="utf-8"))
    assert manifest["builder_source_sha256"] == hashlib.sha256(
        BUILDER_PATH.read_bytes()
    ).hexdigest()
    expected_channels = [channel.value for channel in ALL_CHANNELS]
    for template in manifest["templates"]:
        routes = template["routes"]
        assert [route["channel"] for route in routes] == expected_channels
        assert len(routes) == 7
        observer_wire = {
            "schema_version": "sluice-agentleak-observer-spec-v1",
            "template_code": template["template_code"],
            "observer_spec_id": template["observer_spec_id"],
            "accounting_units_per_bit": template["accounting_units_per_bit"],
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
        assert template["observer_spec_sha256"] == hashlib.sha256(
            _canonical(observer_wire)
        ).hexdigest()
        conditional_support = 4 + sum(
            route["support_cardinality"] + 5 for route in routes
        )
        assert template["event_charge_units"] == math.ceil(
            math.log2(conditional_support)
        )
        assert template["lifetime_budget_units"] == 16 * template["event_charge_units"]


def test_output_parent_swap_cannot_redirect_bundle_outside_pinned_parent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = tmp_path / "parent"
    parent.mkdir()
    moved = tmp_path / "moved-parent"
    redirect = tmp_path / "redirect"
    redirect.mkdir()
    output = parent / "bundle"
    original_mkdir = os.mkdir
    swapped = False

    def racing_mkdir(path, mode=0o777, *, dir_fd=None):
        nonlocal swapped
        if not swapped and Path(path).name == "bundle":
            swapped = True
            parent.rename(moved)
            parent.symlink_to(redirect, target_is_directory=True)
        if dir_fd is None:
            return original_mkdir(path, mode)
        return original_mkdir(path, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "mkdir", racing_mkdir)
    with pytest.raises(CodebookBuildError):
        build_codebook_bundle(corpus_path=CORPUS_PATH, output_directory=output)
    assert swapped
    assert not (redirect / "bundle").exists()


def test_output_path_rejects_symlinked_ancestor(tmp_path: Path) -> None:
    real_parent = tmp_path / "real-parent"
    nested = real_parent / "nested"
    nested.mkdir(parents=True)
    alias = tmp_path / "alias"
    alias.symlink_to(real_parent, target_is_directory=True)
    with pytest.raises(CodebookBuildError, match="pin|unsafe"):
        build_codebook_bundle(
            corpus_path=CORPUS_PATH,
            output_directory=alias / "nested" / "bundle",
        )
    assert not (nested / "bundle").exists()


def test_private_payloads_are_injective_canonical_and_allowed_field_only(tmp_path: Path) -> None:
    result = build_codebook_bundle(corpus_path=CORPUS_PATH, output_directory=tmp_path / "out")
    manifest = json.loads(result.manifest_path.read_text(encoding="utf-8"))
    expected_payloads: dict[str, set[str]] = {}
    for scenario in load_pinned_corpus(CORPUS_PATH).scenarios:
        projection = canonical_allowed_projection(scenario)
        template_code = _template_code(scenario)
        expected_payloads.setdefault(template_code, {"ABSTAIN"})
        if not _is_empty_projection(projection):
            expected_payloads[template_code].add(_canonical(projection).decode("ascii"))
    for template in manifest["templates"]:
        allowed = set(template["allowed_field_names"])
        route = template["routes"][0]
        private_path = result.private_codebook_root / route["codebook_file"]
        raw = private_path.read_bytes()
        assert hashlib.sha256(raw).hexdigest() == route["codebook_sha256"]
        private = json.loads(raw)
        assert raw == _canonical(private)
        payloads = [entry["payload"] for entry in private["entries"]]
        assert len(payloads) == len(set(payloads)) == route["support_cardinality"]
        assert set(payloads) == expected_payloads[template["template_code"]]
        assert payloads[0] == "ABSTAIN"
        for payload in payloads[1:]:
            projection = json.loads(payload)
            assert projection["records"]
            assert any(record for record in projection["records"])
            assert all(set(record).issubset(allowed) for record in projection["records"])


def test_report_and_checksum_inventory_are_strictly_consumed(tmp_path: Path) -> None:
    result = build_codebook_bundle(corpus_path=CORPUS_PATH, output_directory=tmp_path / "valid")
    validate_codebook_construction_artifacts(
        manifest_path=result.manifest_path,
        expected_manifest_sha256=result.manifest_sha256,
        private_codebook_root=result.private_codebook_root,
        report_path=result.report_path,
        expected_report_sha256=result.report_sha256,
        checksums_path=result.checksums_path,
        expected_builder_source_sha256=hashlib.sha256(BUILDER_PATH.read_bytes()).hexdigest(),
        expected_construction_loader_source_sha256=construction_loader_source_sha256(),
    )
    result.checksums_path.write_bytes(result.checksums_path.read_bytes() + b"0" * 64 + b"  extra\n")
    with pytest.raises(CodebookBuildError, match="SHA256SUMS"):
        validate_codebook_construction_artifacts(
            manifest_path=result.manifest_path,
            expected_manifest_sha256=result.manifest_sha256,
            private_codebook_root=result.private_codebook_root,
            report_path=result.report_path,
            expected_report_sha256=result.report_sha256,
            checksums_path=result.checksums_path,
            expected_builder_source_sha256=hashlib.sha256(BUILDER_PATH.read_bytes()).hexdigest(),
            expected_construction_loader_source_sha256=construction_loader_source_sha256(),
        )


def test_report_rejects_bool_integer_duplicate_key_nonfinite_and_noncanonical_json(
    tmp_path: Path,
) -> None:
    result = build_codebook_bundle(corpus_path=CORPUS_PATH, output_directory=tmp_path / "strict")
    valid_raw = result.report_path.read_bytes()
    body = json.loads(valid_raw)
    boolean_body = dict(body, corpus_rows=True)
    first_comma = valid_raw.index(b",") + 1
    duplicate_raw = b"{" + valid_raw[1:first_comma] + valid_raw[1:]
    mutations = (
        _canonical(boolean_body),
        duplicate_raw,
        b'{"schema_version":NaN}',
        valid_raw + b"\n",
    )
    for raw in mutations:
        result.report_path.write_bytes(raw)
        with pytest.raises(CodebookBuildError):
            validate_codebook_construction_artifacts(
                manifest_path=result.manifest_path,
                expected_manifest_sha256=result.manifest_sha256,
                private_codebook_root=result.private_codebook_root,
                report_path=result.report_path,
                expected_report_sha256=hashlib.sha256(raw).hexdigest(),
                checksums_path=result.checksums_path,
                expected_builder_source_sha256=hashlib.sha256(BUILDER_PATH.read_bytes()).hexdigest(),
                expected_construction_loader_source_sha256=construction_loader_source_sha256(),
            )
    result.report_path.write_bytes(valid_raw)


def test_builder_is_process_and_hashseed_deterministic(tmp_path: Path) -> None:
    program = """
from pathlib import Path
from sluice_v2.evaluation.agentleak_codebooks import build_codebook_bundle
import sys
r = build_codebook_bundle(corpus_path=Path(sys.argv[1]), output_directory=Path(sys.argv[2]))
print(r.manifest_sha256 + ' ' + r.report_sha256)
"""
    observed = []
    for seed in ("1", "8675309"):
        output = tmp_path / f"seed-{seed}"
        environment = dict(os.environ, PYTHONHASHSEED=seed, PYTHONDONTWRITEBYTECODE="1")
        completed = subprocess.run(
            [sys.executable, "-c", program, str(CORPUS_PATH), str(output)],
            cwd=ARTIFACT_ROOT,
            env=environment,
            text=True,
            capture_output=True,
            check=True,
        )
        observed.append(completed.stdout.strip())
    assert observed[0] == observed[1]


def test_builder_is_create_only_and_uses_private_file_modes(tmp_path: Path) -> None:
    first = build_codebook_bundle(
        corpus_path=CORPUS_PATH, output_directory=tmp_path / "ordered"
    )
    assert first.manifest_path.stat().st_mode & 0o777 == 0o600
    assert first.report_path.stat().st_mode & 0o777 == 0o600
    assert first.checksums_path.stat().st_mode & 0o777 == 0o600
    assert first.private_codebook_root.stat().st_mode & 0o777 == 0o700
    with pytest.raises(CodebookBuildError, match="already exists"):
        build_codebook_bundle(corpus_path=CORPUS_PATH, output_directory=tmp_path / "ordered")


def test_builder_source_has_no_attack_evaluation_or_forbidden_value_data_path() -> None:
    tree = ast.parse(BUILDER_PATH.read_text(encoding="utf-8"))
    forbidden = {"attack", "evaluation", "forbidden_fields", "target_channels", "canaries"}
    observed = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }
    assert not (forbidden & observed)
    assert "load_pinned_corpus" not in BUILDER_PATH.read_text(encoding="utf-8")


class AccessPoisonMapping(Mapping):
    def __init__(self, permitted, forbidden=()):
        self._permitted = dict(permitted)
        self._forbidden = frozenset(forbidden)
        self.accessed = []

    def __getitem__(self, key):
        self.accessed.append(key)
        if key in self._forbidden:
            raise AssertionError(f"forbidden construction access: {key}")
        return self._permitted[key]

    def __iter__(self):
        raise AssertionError("construction projector must not enumerate a source mapping")

    def __len__(self):
        return len(self._permitted)


def test_codebook_construction_projection_never_touches_forbidden_subobjects() -> None:
    protected_fields = AccessPoisonMapping(
        {"allowed_name": "PERMITTED-VALUE"}, forbidden={"secret", "canary"}
    )
    source = AccessPoisonMapping(
        {
            "scenario_id": "poison-codebook-row",
            "objective": AccessPoisonMapping(
                {"success_criteria": ["complete_summary"]},
                forbidden={"user_request", "privacy_instruction"},
            ),
            "allowed_set": AccessPoisonMapping(
                {"fields": ["allowed_name"]}, forbidden={"forbidden_fields"}
            ),
            "private_vault": AccessPoisonMapping(
                {
                    "records": [
                        AccessPoisonMapping(
                            {"fields": protected_fields},
                            forbidden={"record_id", "classification"},
                        )
                    ]
                }
            ),
        },
        forbidden={
            "attack",
            "evaluation",
            "condition",
            "target_channels",
            "detector",
            "outcome",
        },
    )
    projected = project_codebook_support_row(source)
    assert projected == {
        "scenario_id": "poison-codebook-row",
        "objective": {"success_criteria": ["complete_summary"]},
        "allowed_set": {"fields": ["allowed_name"]},
        "private_vault": {
            "records": [{"fields": {"allowed_name": "PERMITTED-VALUE"}}]
        },
    }
    assert not (
        set(source.accessed)
        & {
            "attack",
            "evaluation",
            "condition",
            "target_channels",
            "detector",
            "outcome",
        }
    )
    assert protected_fields.accessed == ["allowed_name", "allowed_name"]


def test_tampered_corpus_fails_closed_before_output_creation(tmp_path: Path) -> None:
    tampered = tmp_path / "tampered.jsonl"
    tampered.write_bytes(CORPUS_PATH.read_bytes() + b"\n")
    with pytest.raises(Exception, match="construction-only corpus projection failed"):
        build_codebook_bundle(corpus_path=tampered, output_directory=tmp_path / "tampered-out")
    assert not (tmp_path / "tampered-out").exists()
