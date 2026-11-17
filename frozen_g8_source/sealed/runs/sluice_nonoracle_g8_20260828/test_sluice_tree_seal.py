#!/usr/bin/env python3
"""Regression tests for the checkout-materialization bug class.

These tests encode the failure that terminated C11, C12, C13, C14 and C15
before a single experimental arm executed, and they prove the fix is general
rather than specific to whichever capsule a given attempt tripped over first.

Test 1 establishes the premise empirically: a real dulwich commit + checkout of
a sealed tree loses 0444 file modes, 0555 directory modes, and empty
directories, so a correct verifier MUST reject the checkout.

Test 2 proves the fix: materializing from the scanned seal makes the same
checkout pass the same verifier.

Test 3 is the one that actually closes the *class*.  It builds N independent
sealed capsules with different shapes and materializes them all through one
unchanged code path with zero per-capsule constants.  The C-series helper
needed a hand-written SealedTreeSpec (files=, directories=, digest=) per
capsule, and needed one for every capsule of every previous attempt, which is
why its table grew 2, 6, 10, 15 across C12..C15.  Here, N is a loop bound.

Run:  python3 test_sluice_tree_seal.py
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

FAILURES: list[str] = []
PASSES: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    if condition:
        PASSES.append(name)
        print(f"  PASS {name}")
    else:
        FAILURES.append(f"{name}: {detail}")
        print(f"  FAIL {name} {detail}")


def run_seal(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-B", str(SEAL_TOOL), *args],
        capture_output=True, text=True,
    )


def build_capsule(root: Path, *, files: int, depth: int, empty_dirs: int) -> None:
    """Create a sealed-style capsule: read-only files, read-only dirs, empties."""
    root.mkdir(parents=True)
    here = root
    for level in range(depth):
        here = here / f"level{level}"
        here.mkdir()
    for index in range(files):
        target = root if index % 2 == 0 else here
        path = target / f"evidence_{index}.json"
        path.write_text(f'{{"index": {index}}}\n', encoding="ascii")
    for index in range(empty_dirs):
        (root / f"artifacts_{index}").mkdir()
    # Seal it the way the real capsules are sealed: 0444 files, 0555 dirs.
    for dirpath, dirnames, filenames in os.walk(root, topdown=False):
        for name in filenames:
            os.chmod(Path(dirpath) / name, 0o444)
        os.chmod(dirpath, 0o555)


def unseal_for_git(root: Path) -> None:
    """Make a tree writable so dulwich can read/stage it without fighting modes."""
    for dirpath, _, filenames in os.walk(root):
        os.chmod(dirpath, 0o755)
        for name in filenames:
            os.chmod(Path(dirpath) / name, 0o644)


def dulwich_roundtrip(dulwich_path: Path, source: Path, work: Path) -> Path:
    """Commit `source` into a real repo and check it out into a fresh tree.

    Returns the checkout path.  This is a genuine Git object-store round trip,
    not a simulation: it is what actually loses the modes and empty dirs.
    """
    sys.path.insert(0, str(dulwich_path))
    from dulwich.repo import Repo  # noqa: PLC0415
    from dulwich import porcelain  # noqa: PLC0415

    repo_dir = work / "origin"
    repo_dir.mkdir()
    repo = Repo.init(str(repo_dir))
    staged = repo_dir / "capsule"
    shutil.copytree(source, staged)
    unseal_for_git(staged)

    rel_paths = []
    for dirpath, _, filenames in os.walk(staged):
        for name in filenames:
            full = Path(dirpath) / name
            rel_paths.append(str(full.relative_to(repo_dir)))
    porcelain.add(repo, paths=[str(repo_dir / p) for p in rel_paths])
    porcelain.commit(repo, message=b"seal capsule", author=b"t <t@t>",
                     committer=b"t <t@t>")

    checkout = work / "checkout"
    porcelain.clone(str(repo_dir), str(checkout), checkout=True)
    repo.close()
    return checkout / "capsule"


def main() -> int:
    dulwich_path = Path(
        os.environ.get(
            "SLUICE_DULWICH",
            "/srv/review/USENIX27_SLUICE/sluice_usenix_revision/tools/dulwich",
        )
    )
    if not (dulwich_path / "dulwich").is_dir():
        print(f"SKIP: vendored dulwich not found at {dulwich_path}")
        return 77

    work = Path(tempfile.mkdtemp(prefix="sluice_seal_test_"))
    try:
        # ---------------------------------------------------------- Test 1
        print("\nTest 1: a real Git checkout loses sealed modes and empty dirs")
        source = work / "source_capsule"
        build_capsule(source, files=6, depth=2, empty_dirs=1)
        result = run_seal("seal", str(source))
        check("seal derives a seal by scanning", result.returncode == 0,
              result.stderr.strip()[:200])
        result = run_seal("verify", str(source))
        check("the original sealed tree verifies", result.returncode == 0,
              result.stdout.strip()[:200])

        checkout = dulwich_roundtrip(dulwich_path, source, work)
        # Carry the seal across the way a committed sidecar would travel.
        shutil.copy2(source / "TREE_SEAL.json", checkout / "TREE_SEAL.json")
        os.chmod(checkout / "TREE_SEAL.json", 0o444)

        result = run_seal("verify", str(checkout))
        check("naive checkout FAILS verification (the real bug)",
              result.returncode == 1, f"rc={result.returncode}")
        combined = result.stdout
        check("failure names a lost file mode", "mode 0o644" in combined,
              combined[:300])
        check("failure names a lost empty directory",
              "missing empty directory" in combined, combined[:300])

        # ---------------------------------------------------------- Test 2
        print("\nTest 2: materialization repairs exactly what the checkout lost")
        result = run_seal("materialize", str(checkout))
        check("materialize succeeds", result.returncode == 0,
              result.stderr.strip()[:300])
        result = run_seal("verify", str(checkout))
        check("materialized checkout PASSES the same verifier",
              result.returncode == 0, result.stdout.strip()[:300])

        result = run_seal("materialize", str(checkout))
        rerun = run_seal("verify", str(checkout))
        check("materialize is idempotent",
              result.returncode == 0 and rerun.returncode == 0,
              rerun.stdout.strip()[:200])

        # ---------------------------------------------------------- Test 3
        print("\nTest 3: N capsules through one code path, zero per-capsule constants")
        capsule_count = 8
        roots = []
        for index in range(capsule_count):
            root = work / f"multi_{index}"
            build_capsule(root, files=2 + index, depth=1 + (index % 3),
                          empty_dirs=index % 3)
            run_seal("seal", str(root))
            roots.append(root)

        multi_work = work / "multi_git"
        multi_work.mkdir()
        checkouts = []
        for index, root in enumerate(roots):
            sub = multi_work / f"w{index}"
            sub.mkdir()
            out = dulwich_roundtrip(dulwich_path, root, sub)
            shutil.copy2(root / "TREE_SEAL.json", out / "TREE_SEAL.json")
            os.chmod(out / "TREE_SEAL.json", 0o444)
            checkouts.append(out)

        naive_failures = sum(
            1 for path in checkouts if run_seal("verify", str(path)).returncode != 0
        )
        check(f"all {capsule_count} naive checkouts fail",
              naive_failures == capsule_count, f"failed={naive_failures}")

        result = run_seal("materialize", *[str(path) for path in checkouts])
        check("one materialize call handles every capsule",
              result.returncode == 0, result.stderr.strip()[:300])
        result = run_seal("verify", *[str(path) for path in checkouts])
        check(f"all {capsule_count} capsules verify after materialization",
              result.returncode == 0, result.stdout.strip()[:400])

        # ---------------------------------------------------------- Test 4
        print("\nTest 4: materialization refuses to invent missing evidence")
        broken = work / "broken"
        shutil.copytree(checkouts[0], broken)
        for dirpath, _, filenames in os.walk(broken):
            os.chmod(dirpath, 0o755)
            for name in filenames:
                os.chmod(Path(dirpath) / name, 0o644)
        victim = next(
            path for path in sorted(broken.rglob("evidence_*.json"))
        )
        victim.unlink()
        result = run_seal("materialize", str(broken))
        check("materialize fails closed when a sealed file is absent",
              result.returncode != 0,
              f"rc={result.returncode} (must not silently succeed)")
        check("failure explains the missing file",
              "sealed file(s) absent" in (result.stdout + result.stderr),
              (result.stdout + result.stderr)[:300])
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

    print(f"\n{len(PASSES)} passed, {len(FAILURES)} failed")
    for line in FAILURES:
        print(f"  FAILED: {line}")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.dont_write_bytecode = True
    raise SystemExit(main())
