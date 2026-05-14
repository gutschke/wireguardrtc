#!/usr/bin/env python3
# 51_enrollment_default_config.py — F2: the shipped config makes
# enrollment work out of the box for the most common case.
#
# Out-of-box expectations:
#   - [Enrollment] section is ACTIVE in the shipped config (not
#     commented), so the admin doesn't have to hunt for what to
#     uncomment.
#   - ProvisionScript points at the broker client
#     (/usr/sbin/wireguardrtc-provision-client), which is the
#     correct seam for both daemon-side (privilege-separated) and
#     CLI-side (sudo) flows.
#   - The shipped config refers to wireguardrtc-provision-default as
#     the default Provisioner (the broker's actual helper); a fresh
#     install gets a working enrollment path without further admin
#     intervention beyond `Pool = ...`.

import configparser
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHIPPED_CONF = os.path.join(REPO, "wireguardrtc.conf")


def _parsed_shipped():
    cp = configparser.ConfigParser()
    cp.optionxform = str
    cp.read(SHIPPED_CONF)
    return cp


def test_enrollment_section_present_and_enabled():
    cp = _parsed_shipped()
    assert cp.has_section("Enrollment"), \
        "shipped config is missing [Enrollment]"
    enabled = cp.get("Enrollment", "Enabled", fallback="").strip().lower()
    assert enabled in ("yes", "true", "1", "on"), (
        f"shipped [Enrollment] Enabled = {enabled!r}; "
        "expected an affirmative default so the wormhole-pair CLI "
        "works without manual config edits"
    )


def test_provision_script_points_at_broker_client():
    cp = _parsed_shipped()
    ps = cp.get("Enrollment", "ProvisionScript", fallback="").strip()
    assert ps == "/usr/sbin/wireguardrtc-provision-client", (
        f"shipped [Enrollment] ProvisionScript = {ps!r}; "
        "should be /usr/sbin/wireguardrtc-provision-client so the "
        "unprivileged daemon hits the broker, not the helper directly"
    )


def test_shipped_provisioning_example_exists():
    """The .deb ships /etc/wireguardrtc/provisioning.conf.example or
    equivalent so admins know how to configure the Pool when using
    -default.  We check the source-tree counterpart here."""
    candidate = os.path.join(REPO, "provisioning.conf.example")
    assert os.path.exists(candidate), \
        f"missing {candidate} (admins need a template for Pool=...)"
    with open(candidate) as f:
        body = f.read()
    assert "Pool" in body, \
        "provisioning.conf.example doesn't mention Pool=..."


def main():
    tests = [
        test_enrollment_section_present_and_enabled,
        test_provision_script_points_at_broker_client,
        test_shipped_provisioning_example_exists,
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
