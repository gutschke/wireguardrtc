#!/usr/bin/env python3
# 48_broker_config_ux.py — verify the daemon's "no broker configured"
# UX is admin-friendly.
#
# F1 spec: a vanilla install must NOT silently default to the public
# broker, and must NOT crash trying to resolve "your.broker.example".
# Instead, the daemon refuses to start with a clear multi-line message
# that presents the two choices (public-broker vs self-host) inline so
# the admin can act without consulting external documentation.

import os
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DAEMON = os.path.join(REPO, "wireguardrtc")
PYTHON = os.path.join(REPO, "venv", "bin", "python3")
SHIPPED_CONF = os.path.join(REPO, "wireguardrtc.conf")


def _run_with_conf(conf_text):
    """Run the daemon (config-validation only) and return (rc, stderr)."""
    with tempfile.TemporaryDirectory() as td:
        cfg = os.path.join(td, "wireguardrtc.conf")
        peers_d = os.path.join(td, "peers.d")
        os.makedirs(peers_d, exist_ok=True)
        with open(cfg, "w") as f:
            f.write(conf_text)
        # --show-config forces a config-validation pass, then prints
        # the parsed state, then exits 0.  If validation fails the
        # daemon exits non-zero with the fatal message on stderr.
        env = os.environ.copy()
        env.pop("WIREGUARDRTC_ALLOW_TEST_FLAGS", None)
        r = subprocess.run(
            [PYTHON, DAEMON, "--config", cfg,
             "--peers-dir", peers_d, "--show-config"],
            capture_output=True, text=True, timeout=15, env=env,
        )
        return r.returncode, r.stdout + r.stderr


def _shipped_conf_text():
    with open(SHIPPED_CONF) as f:
        return f.read()


def test_shipped_conf_does_not_silently_default_to_public_broker():
    """The shipped config, used verbatim, must NOT result in the daemon
    silently connecting to the public broker.  Admin must make a
    deliberate choice."""
    text = _shipped_conf_text()
    # Inject a valid salt so we get past that gate to the broker check.
    text = text.replace(
        "Salt = CHANGE_ME_TO_A_SECURE_RANDOM_STRING",
        "Salt = test-salt-value-base64==",
    )
    rc, out = _run_with_conf(text)
    assert rc != 0, (
        "shipped config validated OK without admin intervention; "
        "broker selection should be required.\n"
        f"output:\n{out}"
    )
    # The fatal message must mention what the admin needs to do, in
    # actionable terms.  We don't pin exact wording but require the
    # two broker options to appear.
    lower = out.lower()
    assert "peerjsserver" in lower, \
        f"error message doesn't mention PeerJsServer:\n{out}"
    assert "0.peerjs.com" in out, \
        f"error message doesn't mention the public broker option:\n{out}"
    assert "self-host" in lower or "peerjs-server" in lower, \
        f"error message doesn't mention the self-hosting option:\n{out}"


def test_explicit_public_broker_works():
    """If the admin uncomments the public-broker lines, validation passes."""
    text = (
        "[Global]\n"
        "Salt = test-salt-value-base64==\n"
        "PeerJsServer = wss://0.peerjs.com/peerjs\n"
        "PeerJsKey = peerjs\n"
        "\n[Stun]\nServers = stun.l.google.com:19302\n"
    )
    rc, out = _run_with_conf(text)
    assert rc == 0, f"explicit public broker rejected:\n{out}"


def test_self_hosted_broker_works():
    """Self-hosted broker (Docker recipe) values validate."""
    text = (
        "[Global]\n"
        "Salt = test-salt-value-base64==\n"
        "PeerJsServer = ws://broker.example.internal:9000/peerjs\n"
        "PeerJsKey = MyVeryLongSecretKey123\n"
        "\n[Stun]\nServers = stun.l.google.com:19302\n"
    )
    rc, out = _run_with_conf(text)
    assert rc == 0, f"self-hosted broker rejected:\n{out}"


def test_placeholder_broker_url_is_rejected():
    """The literal 'your.broker.example' from the shipped Docker recipe
    must be flagged — it's a non-resolvable hostname and was never
    meant to be an active value."""
    text = (
        "[Global]\n"
        "Salt = test-salt-value-base64==\n"
        "PeerJsServer = ws://your.broker.example:9000/peerjs\n"
        "PeerJsKey = YOUR_SECRET_KEY\n"
        "\n[Stun]\nServers = stun.l.google.com:19302\n"
    )
    rc, out = _run_with_conf(text)
    assert rc != 0, (
        "placeholder broker URL accepted; admin would hit DNS failure "
        "later with no helpful pointer.\n"
        f"output:\n{out}"
    )
    assert "your.broker.example" in out or "placeholder" in out.lower(), (
        f"placeholder error doesn't tell admin what to change:\n{out}"
    )


def test_shipped_conf_has_no_active_placeholder_lines():
    """The shipped config must not contain uncommented placeholder
    PeerJs lines that would cause silent broker mis-routing."""
    text = _shipped_conf_text()
    for ln in text.splitlines():
        stripped = ln.strip()
        if stripped.startswith("#") or not stripped:
            continue
        assert "your.broker.example" not in stripped, (
            f"shipped config has active placeholder broker URL:\n{ln}"
        )
        assert "YOUR_SECRET_KEY" not in stripped, (
            f"shipped config has active placeholder key:\n{ln}"
        )


def main():
    if not os.path.exists(PYTHON):
        print(f"  (skipping; venv python missing at {PYTHON})")
        sys.exit(0)
    tests = [
        test_shipped_conf_does_not_silently_default_to_public_broker,
        test_explicit_public_broker_works,
        test_self_hosted_broker_works,
        test_placeholder_broker_url_is_rejected,
        test_shipped_conf_has_no_active_placeholder_lines,
    ]
    failures = 0
    for t in tests:
        try:
            t()
            print(f"  ✓ {t.__name__}")
        except AssertionError as e:
            print(f"  ✗ {t.__name__}: {e}")
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
