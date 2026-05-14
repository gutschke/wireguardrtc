#!/usr/bin/env python3
# 47_test_flag_gate.py — verify the WIREGUARDRTC_ALLOW_TEST_FLAGS gate.
#
# Test-only flags (--pubkey-override, --endpoint-override,
# --auto-confirm-sas, and any later additions following the same
# pattern) are foot-guns in normal use.  The daemon gates them behind
# a single env var so they can't be triggered by mistake.  This file
# exercises the gate's contract:
#
#  - Without the env var: flags are hidden from --help, and using
#    them on the command line aborts with a clear error.
#  - With the env var:    flags appear in --help with [TEST-ONLY],
#    and using them prints a warning to stderr.

import os
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DAEMON = os.path.join(REPO, "wireguardrtc")
PYTHON = os.path.join(REPO, "venv", "bin", "python3")


def _run(args, env_extra=None):
    env = os.environ.copy()
    # Strip the gate so we control it precisely.
    env.pop("WIREGUARDRTC_ALLOW_TEST_FLAGS", None)
    if env_extra:
        env.update(env_extra)
    return subprocess.run([PYTHON, DAEMON] + args,
                          capture_output=True, text=True,
                          timeout=15, env=env)


def test_help_hides_test_flags_when_gate_off():
    r = _run(["--help"])
    assert r.returncode == 0, f"--help rc={r.returncode}"
    assert "--pubkey-override" not in r.stdout, \
        "pubkey-override leaked into --help without the gate"
    assert "--endpoint-override" not in r.stdout, \
        "endpoint-override leaked into --help without the gate"
    assert "--auto-confirm-sas" not in r.stdout, \
        "auto-confirm-sas leaked into --help without the gate"
    assert "[TEST-ONLY]" not in r.stdout


def test_help_shows_test_flags_when_gate_on():
    r = _run(["--help"], env_extra={"WIREGUARDRTC_ALLOW_TEST_FLAGS": "1"})
    assert r.returncode == 0, f"--help rc={r.returncode}"
    assert "--pubkey-override" in r.stdout
    assert "--endpoint-override" in r.stdout
    assert "--auto-confirm-sas" in r.stdout
    # The [TEST-ONLY] prefix flags them visually.
    assert r.stdout.count("[TEST-ONLY]") >= 3


def test_using_flag_without_gate_is_rejected():
    r = _run(["--mint-wormhole", "--auto-confirm-sas"])
    assert r.returncode == 2, \
        f"expected rc=2, got {r.returncode} stderr={r.stderr!r}"
    assert "Refusing to honor test-only flag" in r.stderr
    assert "WIREGUARDRTC_ALLOW_TEST_FLAGS=1" in r.stderr


def test_using_flag_with_gate_prints_warning():
    """Start the daemon with a test flag set, gate enabled.  The
    daemon will block trying to reach the broker, so we kill it after
    a short delay and read what it wrote to stderr — the warning
    should be there before any network activity happens."""
    import time
    p = subprocess.Popen(
        [PYTHON, DAEMON, "--mint-wormhole",
         "--auto-confirm-sas",
         "--pubkey-override", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
         "--endpoint-override", "1.2.3.4:51820"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        env={**os.environ, "WIREGUARDRTC_ALLOW_TEST_FLAGS": "1"})
    try:
        time.sleep(1.5)  # let the warning land before broker work
        p.terminate()
        out, err = p.communicate(timeout=3)
    finally:
        try: p.kill()
        except Exception: pass
    assert "WIREGUARDRTC_ALLOW_TEST_FLAGS=1" in err, \
        f"warning missing from stderr: {err[:300]!r}"
    assert "Don't use this outside a test harness" in err


def test_unrelated_flag_doesnt_trigger_gate():
    # --check-nat shouldn't trip the test-flag gate.
    r = _run(["--check-nat", "--family", "4",
              "--stun-servers", "127.0.0.1:9"])
    # The probe will fail because there's no STUN server at :9, but
    # the failure should be from the probe layer, not from the gate.
    assert "Refusing to honor test-only flag" not in r.stderr


# ─── Driver ──────────────────────────────────────────────────────

def main():
    if not os.path.exists(PYTHON):
        print(f"  (skipping; venv python missing at {PYTHON})")
        sys.exit(0)
    tests = [
        test_help_hides_test_flags_when_gate_off,
        test_help_shows_test_flags_when_gate_on,
        test_using_flag_without_gate_is_rejected,
        test_using_flag_with_gate_prints_warning,
        test_unrelated_flag_doesnt_trigger_gate,
    ]
    failures = 0
    for t in tests:
        try:
            t()
            print(f"  ✓ {t.__name__}")
        except subprocess.TimeoutExpired as e:
            # test_using_flag_with_gate_prints_warning is expected to
            # time out — but it ALSO checks stderr inside the test,
            # which raises a different exception when failing.  A
            # bare TimeoutExpired here means the test never even
            # reached its assertions.
            print(f"  ✗ {t.__name__}: timeout: {e}")
            failures += 1
        except Exception as e:
            import traceback
            print(f"  ✗ {t.__name__}: {e}")
            traceback.print_exc()
            failures += 1
    print()
    print(f"{len(tests) - failures}/{len(tests)} passed")
    sys.exit(0 if failures == 0 else 1)


if __name__ == "__main__":
    main()
