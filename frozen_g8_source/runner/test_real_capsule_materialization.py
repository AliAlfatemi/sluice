#!/usr/bin/env python3
"""Prove the general fix on the ACTUAL capsule that terminated C11 and C12.

The synthetic tests in test_sluice_tree_seal.py establish the mechanism. This
one establishes that the mechanism handles the real thing: the C10 failure
capsule at

  runs/sluice_definitive_587d3fa_20260824_c11/c10_failure_provenance/capsule

which on disk is 229 files at mode 0444, 36 directories at mode 0555, and
exactly one Git-omitted empty directory
(evidence/run/policy_preflight/artifacts/c4full_qwen25-3b_s196613_s1of6) --
precisely the constants C14's checkout helper hand-pinned.

The real capsule is READ-ONLY EVIDENCE belonging to another lineage. This test
never writes to it: it copies the tree into a scratch directory first and does
all work there. It also derives the seal by scanning rather than reading any
hand-written constant, which is the whole point.
"""
from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SEAL_TOOL = HERE / "sluice_tree_seal.py"
DEFAULT_CAPSULE = (
    "/srv/review/USENIX27_SLUICE/sluice_usenix_revision/runs/"
    "sluice_definitive_587d3fa_20260824_c11/c10_failure_provenance/capsule")
DULWICH = ("/srv/review/USENIX27_SLUICE/sluice_usenix_revision/"
           "tools/dulwich")

FAILURES: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"  {'PASS' if ok else 'FAIL'} {name}" + (f" {detail}" if not ok else ""))
    if not ok:
        FAILURES.append(name)


def run_seal(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-B", str(SEAL_TOOL), *args],
                          capture_output=True, text=True)


def relax(root: Path) -> None:
    for dirpath, _, filenames in os.walk(root):
        os.chmod(dirpath, 0o755)
        for name in filenames:
            os.chmod(Path(dirpath) / name, 0o644)


def main() -> int:
    source = Path(sys.argv[1] if len(sys.argv) > 1 else DEFAULT_CAPSULE)
    if not source.is_dir():
        print(f"SKIP: capsule not found at {source}")
        return 77
    work = Path(tempfile.mkdtemp(prefix="real_capsule_test_"))
    try:
        print(f"\nReal capsule: {source}")
        staged = work / "capsule"
        shutil.copytree(source, staged)
        # copytree preserves modes; make writable so we can seal + stage it.
        n_files = sum(1 for _ in staged.rglob("*") if _.is_file())
        n_dirs = sum(1 for p in staged.rglob("*") if p.is_dir())
        n_empty = sum(1 for p in staged.rglob("*") if p.is_dir() and not any(p.iterdir()))
        print(f"  copied: files={n_files} dirs={n_dirs} empty_dirs={n_empty}")
        check("capsule has read-only sealed files",
              any(stat.S_IMODE(p.lstat().st_mode) == 0o444
                  for p in staged.rglob("*") if p.is_file()))
        check("capsule has at least one Git-omitted empty directory", n_empty >= 1)

        result = run_seal("seal", str(staged))
        check("seal derives the capsule's state by scanning",
              result.returncode == 0, result.stderr[:200])
        seal_bytes = (staged / "TREE_SEAL.json").read_bytes()

        result = run_seal("verify", str(staged))
        check("sealed capsule verifies against its own derived seal",
              result.returncode == 0, result.stdout[:200])

        # --- real dulwich commit + checkout round trip ---
        sys.path.insert(0, DULWICH)
        from dulwich.repo import Repo  # noqa: PLC0415
        from dulwich import porcelain  # noqa: PLC0415

        origin = work / "origin"
        origin.mkdir()
        repo = Repo.init(str(origin))
        tracked = origin / "capsule"
        shutil.copytree(staged, tracked)
        relax(tracked)
        paths = [str(p) for p in tracked.rglob("*") if p.is_file()]
        porcelain.add(repo, paths=paths)
        porcelain.commit(repo, message=b"capsule", author=b"t <t@t>",
                         committer=b"t <t@t>")
        checkout = work / "checkout"
        porcelain.clone(str(origin), str(checkout), checkout=True)
        repo.close()
        out = checkout / "capsule"

        (out / "TREE_SEAL.json").write_bytes(seal_bytes)
        os.chmod(out / "TREE_SEAL.json", 0o444)

        n_empty_after = sum(1 for p in out.rglob("*") if p.is_dir() and not any(p.iterdir()))
        check("the checkout LOST the empty directory (the real bug)",
              n_empty_after < n_empty, f"before={n_empty} after={n_empty_after}")
        # Exclude the seal sidecar itself: it is written at 0444 deliberately
        # just above, so counting it here would measure this test, not the
        # checkout.
        n444 = sum(1 for p in out.rglob("*")
                   if p.is_file() and p.name != "TREE_SEAL.json"
                   and stat.S_IMODE(p.lstat().st_mode) == 0o444)
        check("the checkout LOST every one of the 229 0444 modes (the real bug)",
              n444 == 0, f"still 0444: {n444}")

        result = run_seal("verify", str(out))
        check("naive checkout of the REAL capsule fails verification",
              result.returncode == 1, f"rc={result.returncode}")

        result = run_seal("materialize", str(out))
        check("materialize succeeds on the REAL capsule", result.returncode == 0,
              result.stderr[:300])
        result = run_seal("verify", str(out))
        check("materialized REAL capsule passes the same verifier",
              result.returncode == 0, result.stdout[:400])

        # and the restored tree must equal the original, mode for mode
        mismatches = []
        for path in sorted(staged.rglob("*")):
            rel = path.relative_to(staged)
            if rel.name == "TREE_SEAL.json":
                continue
            other = out / rel
            if not other.exists():
                mismatches.append(f"missing {rel}")
            elif stat.S_IMODE(path.lstat().st_mode) != stat.S_IMODE(other.lstat().st_mode):
                mismatches.append(f"mode {rel}")
        check("every path's mode matches the original capsule exactly",
              not mismatches, f"{len(mismatches)} mismatch(es): {mismatches[:3]}")
    finally:
        for dirpath, dirnames, filenames in os.walk(work, topdown=False):
            for name in dirnames + filenames:
                try:
                    os.chmod(Path(dirpath) / name, 0o700)
                except (FileNotFoundError, PermissionError):
                    pass
            try:
                os.chmod(dirpath, 0o700)
            except (FileNotFoundError, PermissionError):
                pass
        shutil.rmtree(work, ignore_errors=True)

    print(f"\n{'ALL PASS' if not FAILURES else 'FAILURES: ' + ', '.join(FAILURES)}")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.dont_write_bytecode = True
    raise SystemExit(main())
