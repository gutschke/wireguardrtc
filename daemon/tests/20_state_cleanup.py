#!/usr/bin/env python3
# 20_state_cleanup.py — verify auto-enrollment state gets cleaned up
# even when enrollment never completes (token expires unused) or is
# carried over from a previous boot.
#
# Three state stores need cleanup; each has a different mechanism:
#
#   1. pending-tokens.json (daemon-owned)
#      Cleaned by PendingTokensStore.purge_expired().  Verified here
#      by populating the file with a mix of expired/fresh entries
#      and asserting the post-purge state.
#
#   2. permits/ directory (root-owned, broker-managed)
#      Cleaned opportunistically inside wireguardrtc-provision-broker
#      on every request.  We exercise this by spawning the broker
#      with stdin/stdout pipes and confirming stale permits are
#      unlinked even when the request itself is rejected for an
#      unrelated reason.
#
#   3. <iface>.pending-rtc/ sidecars (admin-side; site-specific
#      add-peer-rtc helper families that wrap the daemon CLI).
#      Cleaned opportunistically inside add-peer-rtc on every mint.
#      Not covered here because the helper script families don't
#      ship in the .deb.

import importlib.machinery
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
import base64

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
loader = importlib.machinery.SourceFileLoader(
    "wgrtc", os.path.join(REPO, "wireguardrtc"))
spec = importlib.util.spec_from_loader("wgrtc", loader)
wgrtc = importlib.util.module_from_spec(spec)
loader.exec_module(wgrtc)

pass_n = 0
fail_n = 0
def expect(desc, actual, want):
    global pass_n, fail_n
    if actual == want:
        print(f"  PASS [{desc}]")
        pass_n += 1
    else:
        print(f"  FAIL [{desc}] expected {want!r} got {actual!r}")
        fail_n += 1


# ─── 1. PendingTokensStore.purge_expired ────────────────────────────────
print("=== pending-tokens.json purge_expired ===")
with tempfile.TemporaryDirectory() as state_dir:
    store = wgrtc.PendingTokensStore(state_dir)
    now = int(time.time())
    # Hand-craft state: mix of expired/fresh, plus expired cache.
    state = {
        "tokens": [
            # Expired, never used → should drop.
            {"token_b64": base64.b64encode(b"\x00" * 32).decode(),
             "name_hint": "alice", "iface": "wg0",
             "created_at": now - 7200, "expires_at": now - 3600,
             "used": False, "used_at": None, "used_by": None},
            # Fresh, never used → should keep.
            {"token_b64": base64.b64encode(b"\x01" * 32).decode(),
             "name_hint": "bob", "iface": "wg0",
             "created_at": now, "expires_at": now + 3600,
             "used": False, "used_at": None, "used_by": None},
            # Used recently (< 24h) → should keep (replay-cache window).
            {"token_b64": base64.b64encode(b"\x02" * 32).decode(),
             "name_hint": "carol", "iface": "wg0",
             "created_at": now - 100, "expires_at": now + 100,
             "used": True, "used_at": now - 50, "used_by": "...="},
            # Used long ago (> 24h) → should drop.
            {"token_b64": base64.b64encode(b"\x03" * 32).decode(),
             "name_hint": "dave", "iface": "wg0",
             "created_at": now - 100000, "expires_at": now - 99000,
             "used": True, "used_at": now - 90000, "used_by": "...="},
        ],
        "recent_enrollments": [
            # Expired cache entry → should drop.
            {"client_pub_b64": "stale", "envelope": {},
             "expires_at": now - 60},
            # Fresh cache entry → should keep.
            {"client_pub_b64": "fresh", "envelope": {},
             "expires_at": now + 60},
        ],
    }
    with open(os.path.join(state_dir, "pending-tokens.json"), "w") as f:
        json.dump(state, f)

    removed = store.purge_expired()
    expect("count", removed, 3)  # 2 expired tokens + 1 expired cache

    with open(os.path.join(state_dir, "pending-tokens.json")) as f:
        post = json.load(f)
    name_hints = {t["name_hint"] for t in post["tokens"]}
    expect("kept-bob",   "bob"   in name_hints, True)
    expect("kept-carol", "carol" in name_hints, True)  # within 24h replay window
    expect("dropped-alice", "alice" in name_hints, False)
    expect("dropped-dave",  "dave"  in name_hints, False)
    cache_keys = {e["client_pub_b64"] for e in post["recent_enrollments"]}
    expect("cache-kept-fresh",   "fresh" in cache_keys, True)
    expect("cache-dropped-stale", "stale" in cache_keys, False)


# ─── 1d. write_auto_active_peer + load merge ────────────────────────────
# After a successful ENROLL the daemon writes a peers.d-style drop-in
# with Mode=active under <state_dir>/auto-enrolled.d/.  The merged
# load_peer_configs() picks it up alongside admin entries, with admin
# entries winning on pubkey collision.
print()
print("=== auto-active drop-in writer ===")
with tempfile.TemporaryDirectory() as scratch:
    state_dir = os.path.join(scratch, "state")
    os.makedirs(state_dir)
    pubkey = base64.b64encode(b"\x00" * 32).decode()
    wgrtc.write_auto_active_peer(
        state_dir=__import__("pathlib").Path(state_dir),
        pubkey_b64=pubkey, label="alice", iface="wg0",
    )
    aa_dir = wgrtc.auto_active_dir(__import__("pathlib").Path(state_dir))
    expect("auto-active-dir-created", aa_dir.is_dir(), True)
    files = list(aa_dir.glob("*.conf"))
    expect("one-conf-emitted", len(files), 1)
    body = files[0].read_text()
    expect("contains-pubkey", pubkey in body, True)
    expect("contains-mode-active", "Mode = active" in body, True)
    # Re-enrollment of the same pubkey (same label) overwrites
    # idempotently — same filename (sha256 fingerprint), no
    # accumulating files.
    wgrtc.write_auto_active_peer(
        state_dir=__import__("pathlib").Path(state_dir),
        pubkey_b64=pubkey, label="alice", iface="wg0",
    )
    expect("idempotent-no-extra-file",
           len(list(aa_dir.glob("*.conf"))), 1)

    # load_peer_configs merges admin + auto-active; admin wins.
    admin_dir = os.path.join(scratch, "admin-peers.d")
    os.makedirs(admin_dir)
    # Admin entry for the SAME pubkey but Mode=passive.
    with open(os.path.join(admin_dir, "alice.conf"), "w") as f:
        f.write(f"[Peer]\nPublicKey = {pubkey}\nMode = passive\n")
    merged = wgrtc.load_peer_configs(
        __import__("pathlib").Path(admin_dir),
        auto_active_directory=__import__("pathlib").Path(aa_dir),
    )
    expect("merged-has-pubkey", pubkey in merged, True)
    expect("admin-wins-over-auto-active",
           merged[pubkey].mode, wgrtc.Mode.PASSIVE)


# ─── 1b. mint() same-name supersede ─────────────────────────────────────
# Per the duplicate-label policy: re-minting an unexpired token for the
# same name_hint must replace the previous one (not stack alongside it),
# and return the superseded metadata so the CLI can warn the admin.
print()
print("=== mint same-name supersede ===")
with tempfile.TemporaryDirectory() as state_dir:
    store = wgrtc.PendingTokensStore(state_dir)
    tok1, prev1 = store.mint("alice", expires_in=3600)
    expect("first-mint-no-prev", prev1, None)
    tok2, prev2 = store.mint("alice", expires_in=3600)
    expect("second-mint-supersedes", prev2 is not None, True)
    expect("supersede-name", prev2.get("name_hint"), "alice")
    expect("supersede-token-was-old",
           prev2.get("token_b64"), base64.b64encode(tok1).decode())
    # Different name leaves the alice entry alone.
    tok3, prev3 = store.mint("bob", expires_in=3600)
    expect("different-name-no-supersede", prev3, None)
    # Final state: exactly one alice + one bob, neither used.
    with open(os.path.join(state_dir, "pending-tokens.json")) as f:
        post = json.load(f)
    name_hints = sorted(t["name_hint"] for t in post["tokens"])
    expect("final-tokens", name_hints, ["alice", "bob"])


# ─── 1c. supersede also removes the previous broker permit ──────────────
# When a re-mint supersedes a previous token, any broker permit file
# for the previous token must be removed too — otherwise an admin who
# already shipped the QR could see it succeed against a stale permit
# even though the new mint replaced the token in pending-tokens.json.
print()
print("=== supersede removes previous permit ===")
with tempfile.TemporaryDirectory() as scratch:
    permits_dir = os.path.join(scratch, "permits")
    os.makedirs(permits_dir, mode=0o700)
    os.environ["WIREGUARDRTC_PROVISION_PERMITS_DIR"] = permits_dir

    state_dir = os.path.join(scratch, "state")
    os.makedirs(state_dir, mode=0o700)
    store = wgrtc.PendingTokensStore(state_dir)

    # Mint #1 + write its permit (mimicking what cmd_enroll_token does).
    tok1, prev1 = store.mint("alice", expires_in=3600)
    expect("permit-pre-no-prev", prev1, None)
    wgrtc.write_provision_permit(tok1, "alice",
                                 expires_at=int(time.time()) + 3600)
    permit1_name = base64.urlsafe_b64encode(tok1).rstrip(b"=").decode()
    expect("permit-pre-exists",
           os.path.isfile(os.path.join(permits_dir, permit1_name)), True)

    # Mint #2 supersedes — caller invokes remove_provision_permit on the
    # superseded entry's token_b64 (this is the helper cmd_enroll_token
    # uses).  Verify the permit file is gone afterwards.
    tok2, prev2 = store.mint("alice", expires_in=3600)
    expect("permit-supersede-meta", prev2 is not None, True)
    wgrtc.remove_provision_permit(base64.b64decode(prev2["token_b64"]))
    expect("permit-removed-after-supersede",
           os.path.isfile(os.path.join(permits_dir, permit1_name)), False)

    # The new permit (tok2) is what subsequent enrollments would gate on.
    wgrtc.write_provision_permit(tok2, "alice",
                                 expires_at=int(time.time()) + 3600)
    permit2_name = base64.urlsafe_b64encode(tok2).rstrip(b"=").decode()
    expect("permit-new-exists",
           os.path.isfile(os.path.join(permits_dir, permit2_name)), True)

    # remove_provision_permit on a token with no permit must be a no-op
    # (other code paths call it speculatively; missing-file isn't fatal).
    wgrtc.remove_provision_permit(b"\x00" * 32)
    expect("permit-remove-missing-noop",
           os.path.isfile(os.path.join(permits_dir, permit2_name)), True)

    del os.environ["WIREGUARDRTC_PROVISION_PERMITS_DIR"]


# ─── 2. broker permit cleanup ────────────────────────────────────────────
print()
print("=== broker permit cleanup ===")
BROKER = os.path.join(REPO, "wireguardrtc-provision-broker")
with tempfile.TemporaryDirectory() as work:
    permits = os.path.join(work, "permits")
    os.makedirs(permits, mode=0o700)
    binstub = os.path.join(work, "bin")
    os.makedirs(binstub)
    # Stub `ip link show wg0` and `ip -o link show wg0` (both forms
    # appear: the broker uses the former, the raw-helper the latter).
    with open(os.path.join(binstub, "ip"), "w") as f:
        f.write('#!/bin/bash\n'
                'args="$*"\n'
                '[[ "$args" == *"link show wg0" ]] && exit 0\n'
                'exit 1\n')
    os.chmod(os.path.join(binstub, "ip"), 0o755)
    # Stub Provisioner — we don't actually want it to run for this test.
    with open(os.path.join(work, "provisioner"), "w") as f:
        f.write('#!/bin/bash\nexit 0\n')
    os.chmod(os.path.join(work, "provisioner"), 0o755)
    with open(os.path.join(work, "broker.conf"), "w") as f:
        f.write(f"Provisioner = {work}/provisioner\n")

    now = int(time.time())
    # Three permits: one expired, one with malformed JSON, one fresh.
    expired_tok = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    fresh_tok   = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
    junk_tok    = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
    with open(os.path.join(permits, expired_tok), "w") as f:
        json.dump({"name_hint": "alice",
                   "expires_at": now - 100, "created_at": now - 200}, f)
    with open(os.path.join(permits, fresh_tok), "w") as f:
        json.dump({"name_hint": "bob",
                   "expires_at": now + 100, "created_at": now}, f)
    with open(os.path.join(permits, junk_tok), "w") as f:
        f.write("not-valid-json")

    # Fire ANY request — even a nonexistent-permit one — and the broker
    # opportunistic-purge should run before the actual request handling.
    # We use the fresh token + a NAME mismatch so the broker rejects
    # post-cleanup, and we can then inspect the dir.
    pub = base64.b64encode(b"\x00" * 32).decode()  # 44 chars
    # The broker's stdin is line-delimited (`read -t 5 -r line`).
    # Without the trailing newline the read times out.
    req = json.dumps({
        "iface": "wg0",
        "name": "wrong-name",
        "pubkey": pub,
        "token": fresh_tok,
    }) + "\n"
    env = os.environ.copy()
    env["PATH"] = binstub + ":" + env.get("PATH", "")
    env["WIREGUARDRTC_PROVISION_BROKER_CONF"] = os.path.join(work, "broker.conf")
    env["WIREGUARDRTC_PROVISION_PERMITS_DIR"] = permits
    res = subprocess.run([BROKER], input=req, capture_output=True,
                         text=True, env=env, timeout=10)
    # The expected response is a permit-name-mismatch reject, but
    # critically the cleanup ran first.
    remaining = set(os.listdir(permits))
    expect("expired-purged", expired_tok in remaining, False)
    expect("junk-purged",    junk_tok    in remaining, False)
    expect("fresh-kept",     fresh_tok   in remaining, True)
    # The broker MUST have rejected this request rather than provisioning,
    # since the name didn't match the permit.
    try:
        resp = json.loads(res.stdout)
    except Exception:
        resp = {}
    expect("broker-rejected-name-mismatch",
           resp.get("status"), "reject")


# ─── 4. PendingTokensStore.unmint (CR-D1 rollback) ────────────────────
print()
print("=== PendingTokensStore.unmint ===")
with tempfile.TemporaryDirectory() as state_dir:
    store = wgrtc.PendingTokensStore(state_dir)
    # Mint two tokens; unmint the first; second should remain.
    tok1, _ = store.mint("alpha", expires_in=300, max_pending=8)
    tok2, _ = store.mint("beta",  expires_in=300, max_pending=8)
    expect("two-tokens-after-mint",
           len(store.list_tokens()),
           2)
    removed = store.unmint(tok1)
    expect("unmint-returns-True-for-fresh-token", removed, True)
    # list_tokens may include used tokens; filter to active ones.
    active = [t for t in store.list_tokens() if not t.get("used")]
    expect("one-active-token-after-unmint",
           len(active),
           1)
    expect("the-remaining-token-is-tok2",
           active[0]["name_hint"],
           "beta")
    # Unminting an unknown token returns False; doesn't disturb state.
    fake_tok = b"\x00" * 32
    removed = store.unmint(fake_tok)
    expect("unmint-returns-False-for-unknown-token", removed, False)
    active = [t for t in store.list_tokens() if not t.get("used")]
    expect("state-unchanged-after-failed-unmint",
           len(active),
           1)
    # Unminting a USED token also returns False — once consumed, the
    # entry is part of the replay-cache, not free for revocation.
    # Mark tok2 as used by hand to simulate the post-claim state.
    with store._txn() as txn:
        for t in txn.state["tokens"]:
            if t["token_b64"] == base64.b64encode(tok2).decode():
                t["used"] = True
        txn.commit()
    removed = store.unmint(tok2)
    expect("unmint-returns-False-for-already-used-token", removed, False)


print()
print(f"summary: {pass_n} passed, {fail_n} failed")
sys.exit(0 if fail_n == 0 else 1)
