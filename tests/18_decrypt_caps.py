#!/usr/bin/env python3
# 18_decrypt_caps.py — verify the size caps in decrypt_envelope and
# decrypt_enroll_blob.  Drives the daemon's pure crypto helpers directly;
# no fabric, no daemon, no kernel.
#
# Coverage:
#   * legitimate sigbox plaintext (~80 bytes) decrypts cleanly
#   * sigbox ciphertext at the b64 cap +1 char is rejected
#   * sigbox plaintext at the cap +1 byte is rejected
#   * legitimate enroll plaintext (~300 bytes) decrypts cleanly
#   * enroll ciphertext at the b64 cap +1 char is rejected
#   * enroll plaintext at the cap +1 byte is rejected

import importlib.util
import importlib.machinery
import json
import os
import sys
import time
import base64

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
loader = importlib.machinery.SourceFileLoader(
    "wgrtc", os.path.join(REPO, "wireguardrtc"))
spec = importlib.util.spec_from_loader("wgrtc", loader)
wgrtc = importlib.util.module_from_spec(spec)
loader.exec_module(wgrtc)

from nacl.secret import SecretBox

KEY = os.urandom(32)


def secretbox_encrypt(plain: bytes) -> str:
    return base64.b64encode(SecretBox(KEY).encrypt(plain)).decode("ascii")


pass_n = 0
fail_n = 0


def expect(desc, value):
    global pass_n, fail_n
    if value:
        print(f"  PASS [{desc}]")
        pass_n += 1
    else:
        print(f"  FAIL [{desc}]")
        fail_n += 1


print("=== decrypt_envelope (sigbox) ===")

# Legitimate — current wire format uses a `candidates` array.  See
# memory/project_protocol_signal_wake_candidates for the design.
plain = json.dumps({
    "v": wgrtc.PROTOCOL_VERSION, "ts": int(time.time()),
    "candidates": [{"ip": "203.0.113.5", "port": 51820, "kind": "stun"}],
}).encode("utf-8")
ct_b64 = secretbox_encrypt(plain)
expect("legit-sigbox", wgrtc.decrypt_envelope(KEY, ct_b64) is not None)

# Plaintext over cap.
big = json.dumps({
    "v": wgrtc.PROTOCOL_VERSION, "ts": int(time.time()),
    "ip": "203.0.113.5", "port": 51820,
    "junk": "A" * (wgrtc.MAX_SIGBOX_PLAINTEXT + 1),
}).encode("utf-8")
ct_b64 = secretbox_encrypt(big)
# Note: this test is "we got a valid ciphertext that decrypts to >cap";
# the caller has the right key but feeds oversized.
expect("plaintext-over-cap-rejected",
       wgrtc.decrypt_envelope(KEY, ct_b64) is None)

# Ciphertext-b64 over cap.  We don't even decode it.
giant_b64 = "A" * (wgrtc.MAX_SIGBOX_CIPHERTEXT_B64 + 1)
expect("ciphertext-over-cap-rejected",
       wgrtc.decrypt_envelope(KEY, giant_b64) is None)

# Garbage/non-string.
expect("non-string-rejected",
       wgrtc.decrypt_envelope(KEY, None) is None)

print()
print("=== decrypt_enroll_blob ===")

plain = json.dumps({
    "v": wgrtc.PROTOCOL_VERSION, "ts": int(time.time()),
    "token_check": "abc",
    "hint": "pixel-8",
    "device": "android",
}).encode("utf-8")
ct_b64 = secretbox_encrypt(plain)
expect("legit-enroll", wgrtc.decrypt_enroll_blob(KEY, ct_b64) is not None)

big = json.dumps({
    "v": wgrtc.PROTOCOL_VERSION, "ts": int(time.time()),
    "junk": "A" * (wgrtc.MAX_ENROLL_PLAINTEXT + 1),
}).encode("utf-8")
ct_b64 = secretbox_encrypt(big)
expect("enroll-plaintext-over-cap",
       wgrtc.decrypt_enroll_blob(KEY, ct_b64) is None)

giant_b64 = "A" * (wgrtc.MAX_ENROLL_CIPHERTEXT_B64 + 1)
expect("enroll-ciphertext-over-cap",
       wgrtc.decrypt_enroll_blob(KEY, giant_b64) is None)

print()
print(f"summary: {pass_n} passed, {fail_n} failed")
sys.exit(0 if fail_n == 0 else 1)
