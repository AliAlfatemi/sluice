#!/usr/bin/env bash
# One clean-environment command for the artifact's full regression suite:
# installs the package and its dev/integration dependencies into an
# isolated virtualenv -- not the shared user/global site-packages, where
# an editable install of this same-named package from a second checkout
# of this project would silently overwrite which copy's source is
# actually imported -- then runs every test this project has --
# sluice_v2/tests, integrations, and tests/test_redesigned_experiments.py
# -- as one `pytest` invocation (pyproject.toml's testpaths covers all
# three).
#
# Usage: ./run_all_tests.sh
#        (optionally: SKIP_INSTALL=1 ./run_all_tests.sh to reuse the
#        venv this script already created, e.g. inside a container built
#        from the pinned dependencies)
#
# Fails (nonzero exit) on any failure, collection error, skip, xfail, or
# xpass, and unless the combined suite contains exactly 120 passing cases.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

VENV="$HERE/.venv"
PY="$VENV/bin/python3"
EXPECTED_TOTAL=120

if [ "${SKIP_INSTALL:-0}" != "1" ]; then
  echo "=== creating isolated virtualenv at $VENV ==="
  python3 -m venv --clear "$VENV"
  echo "=== installing pinned build and runtime dependencies ==="
  PIP_DISABLE_PIP_VERSION_CHECK=1 "$PY" -m pip install --quiet \
    'pip==26.2.1' 'setuptools==80.9.0' 'wheel==0.45.1'
  PIP_DISABLE_PIP_VERSION_CHECK=1 "$PY" -m pip install --quiet \
    --requirement requirements-lock.txt
  PIP_DISABLE_PIP_VERSION_CHECK=1 "$PY" -m pip install --quiet \
    --no-deps --no-build-isolation --editable .
  "$PY" -m pip check
  echo
fi

if [ ! -x "$PY" ]; then
  echo "FAILED: no virtualenv at $VENV -- run without SKIP_INSTALL=1 first." >&2
  exit 1
fi

echo "=== verifying the installed package imports without PYTHONPATH ==="
(cd /tmp && "$PY" -c "import sluice_v2.monitor as m; print('sluice_v2.monitor OK:', m.__file__)")
echo

echo "=== pytest (testpaths: tests, sluice_v2/tests, integrations) ==="
set +e
output="$("$PY" -m pytest -q -ra 2>&1)"
status=$?
set -e
echo "$output"
echo

if [ $status -ne 0 ]; then
  echo "FAILED: pytest exited $status (failures and/or collection errors above)." >&2
  exit 1
fi

summary_line="$(
  printf '%s\n' "$output" \
    | grep -E '^[[:space:]]*[0-9]+ passed(, .+)? in ' \
    | tail -1 \
    || true
)"
if [ -z "$summary_line" ]; then
  echo "FAILED: could not find a pytest summary line to verify the total against." >&2
  exit 1
fi
if printf '%s\n' "$summary_line" | grep -qE \
  '(^|, )[0-9]+ (skipped|xfailed|xpassed|failed|errors?)(,| in |$)'; then
  echo "FAILED: summary line reports a non-pass outcome:" >&2
  echo "  $summary_line" >&2
  exit 1
fi

total="$(printf '%s\n' "$summary_line" | sed -E 's/^[[:space:]]*([0-9]+).*/\1/')"
if [ "$total" -ne "$EXPECTED_TOTAL" ]; then
  echo "FAILED: expected exactly $EXPECTED_TOTAL passing cases; pytest reported $total." >&2
  exit 1
fi

echo "All suites passed. Combined total: $total passed, 0 skipped/xfail/xpass, 0 errors."
