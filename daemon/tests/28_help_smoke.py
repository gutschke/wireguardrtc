#!/usr/bin/env python3
# 28_help_smoke.py — smoke-test that the daemon's argparse `--help` actually
# produces output.
#
# A passing run requires exit code 0 AND non-empty stdout.  This catches
# the corruption shape that bit v0.2.0: the daemon's module-level `main`
# (no parens) made `python3 wireguardrtc --help` exit 0 silently, so a
# naive exit-code-only CI check would have missed it.
#
# Scope: only the daemon entry-point.  `wireguardrtc-key-oracle` and
# `wireguardrtc-raw-helper` deliberately accept no arguments — their
# integrity is covered by Tests 16/17 (runtime fabric) and Test 29
# (AST lint).  The bash wrappers (`wireguardrtc-provision-*`) are
# trivial shell glue.
#
# Exit codes (per tests/README.md):
#   0 — smoke test passed
#   1 — daemon's --help produced no output or non-zero exit
#   2 — environmental: daemon venv missing (re-run with $PY override)

import os
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def find_venv_python():
    """Look for a venv with daemon deps (websockets + PyNaCl)."""
    # Honour explicit override first.
    override = os.environ.get("PY")
    if override and os.access(override, os.X_OK):
        return override
    # Conventional locations.  REPO is daemon/, so walk up two levels too —
    # the project-root layout puts the dev venv at wireguardrtc/venv/.
    candidates = [
        os.path.join(REPO, "venv", "bin", "python3"),
        os.path.join(os.path.dirname(REPO), "venv", "bin", "python3"),
        os.path.join(os.path.dirname(os.path.dirname(REPO)),
                     "venv", "bin", "python3"),
        "/var/lib/wireguardrtc/venv/bin/python3",
    ]
    for c in candidates:
        if os.access(c, os.X_OK):
            return c
    return None


py = find_venv_python()
if not py:
    print("  SKIP: daemon venv not found.  Create one via:")
    print("    python3 -m venv venv && venv/bin/pip install websockets pynacl")
    print("  …or set $PY to a python with those deps installed.")
    sys.exit(2)

daemon = os.path.join(REPO, "wireguardrtc")
if not os.path.isfile(daemon):
    print(f"  FAIL: daemon not found at {daemon}")
    sys.exit(1)

print(f"=== daemon --help smoke ({os.path.basename(py)}) ===")

try:
    result = subprocess.run(
        [py, daemon, "--help"],
        capture_output=True, text=True, timeout=10,
    )
except subprocess.TimeoutExpired:
    print("  FAIL [wireguardrtc]: --help timed out after 10 s")
    sys.exit(1)

if result.returncode != 0:
    print(f"  FAIL [wireguardrtc]: exit {result.returncode}")
    print(f"    stderr: {result.stderr[:400]!r}")
    sys.exit(1)

if not result.stdout.strip():
    print("  FAIL [wireguardrtc]: exit 0 but stdout was empty.")
    print("    This is the v0.2.0 corruption signature: module-bottom")
    print("    `main` (no parens) defines main and exits 0 silently.")
    print(f"    stderr was: {result.stderr[:400]!r}")
    sys.exit(1)

print(f"  PASS [wireguardrtc]: exit 0, {len(result.stdout)} bytes on stdout")
print(f"    first line: {result.stdout.splitlines()[0]!r}")
sys.exit(0)
