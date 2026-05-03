#!/bin/bash
# 13_provision_broker.sh — unit-ish test of the provisioning broker.
#
# Exercises wireguardrtc-provision-broker's validation + permit-gating
# logic against a stub Provisioner.  Does NOT spin up a full PeerJS
# fabric — these tests are independent of the daemon.  Each test sends
# one JSON request on stdin and inspects the JSON response on stdout.
#
# Coverage:
#   * bad-json / wrong types
#   * bad iface (eth0, "../../foo", uppercase, spaces)
#   * bad name (comma, slash, control chars, length, shell metas)
#   * GOOD name: spaces + apostrophes + Unicode (e.g. "Anna's Pixel 8")
#   * bad pubkey (wrong length, wrong alphabet, wrong decoded length)
#   * bad token (wrong charset, wrong length)
#   * no-permit (provisioning attempted with no matching permit)
#   * permit-name-mismatch
#   * permit-expired
#   * happy path (permit present, name matches, expiry valid)
#   * single-use enforcement (second call after happy path fails)
#
# No root needed; no kernel WG interface needed (we stub `ip link show`
# via PATH so the broker's iface-presence check passes).

set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
BROKER="$REPO/wireguardrtc-provision-broker"

[[ -x "$BROKER" ]] || { echo "error: $BROKER not found" >&2; exit 2; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$WORK/permits" "$WORK/bin" "$WORK/state"
chmod 0700 "$WORK/permits"

# Stub `ip` so iface-present check passes for wg0/wg1, fails for others.
cat >"$WORK/bin/ip" <<'EOF'
#!/bin/bash
# Stub: only "ip link show wgN" succeeds, for wg0..wg9.
if [[ "$1" == "link" && "$2" == "show" ]]; then
    case "$3" in
        wg0|wg1|wg0p1|wg0p2|wg1p1) exit 0;;
        *) exit 1;;
    esac
fi
exit 1
EOF
chmod +x "$WORK/bin/ip"

# Stub Provisioner — records each call to a log.
cat >"$WORK/bin/provisioner" <<EOF
#!/bin/bash
echo "called: \$*" >>"$WORK/provisioner.log"
exit 0
EOF
chmod +x "$WORK/bin/provisioner"

cat >"$WORK/broker.conf" <<EOF
Provisioner = $WORK/bin/provisioner
EOF

# Helper: run one broker invocation with the given JSON request.
# Echoes the broker's status (ok|reject|error) and stderr-tail for
# easy assertion in tests.
run_broker() {
    local json="$1"
    PATH="$WORK/bin:$PATH" \
    WIREGUARDRTC_PROVISION_BROKER_CONF="$WORK/broker.conf" \
    WIREGUARDRTC_PROVISION_PERMITS_DIR="$WORK/permits" \
        "$BROKER" <<<"$json" 2>/dev/null
}

# Helper: extract one field from the broker's JSON response.
field() {
    python3 -c "import json,sys; print(json.loads(sys.argv[1]).get(sys.argv[2],''))" "$1" "$2"
}

# Helper: drop a permit file with a given expiry offset (seconds from now).
write_permit() {
    local token_b64="$1" name_hint="$2" expiry_offset="$3"
    python3 - "$WORK/permits/$token_b64" "$name_hint" "$expiry_offset" <<'PY'
import json, sys, time, os
path, name, off = sys.argv[1], sys.argv[2], int(sys.argv[3])
permit = {"name_hint": name, "expires_at": int(time.time()) + off,
          "created_at": int(time.time())}
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as f:
    json.dump(permit, f)
PY
}

# A real-shaped pubkey + token (zeros, b64-encoded; 32 bytes each).
PUB="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
TOK_GOOD="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

pass=0
fail=0
expect() {
    local desc="$1" expected_status="$2" expected_stderr_substr="$3" json="$4"
    local resp status stderr
    resp=$(run_broker "$json")
    status=$(field "$resp" status)
    stderr=$(field "$resp" stderr)
    if [[ "$status" == "$expected_status" \
          && "$stderr" == *"$expected_stderr_substr"* ]]; then
        echo "  PASS [$desc] -> $status:$stderr"
        pass=$((pass+1))
    else
        echo "  FAIL [$desc] expected=$expected_status:*$expected_stderr_substr* got=$status:$stderr"
        echo "    request: $json"
        echo "    response: $resp"
        fail=$((fail+1))
    fi
}

echo "=== validation: malformed JSON / wrong types ==="
expect "bad-json" reject bad-json 'not-json'
expect "empty-object" reject not-string '{}'
expect "iface-not-string" reject iface-not-string '{"iface":42,"name":"x","pubkey":"'"$PUB"'","token":"'"$TOK_GOOD"'"}'

echo "=== iface validation ==="
expect "iface-eth" reject bad-iface '{"iface":"eth0","name":"x","pubkey":"'"$PUB"'","token":"'"$TOK_GOOD"'"}'
expect "iface-uppercase" reject bad-iface '{"iface":"Wg0","name":"x","pubkey":"'"$PUB"'","token":"'"$TOK_GOOD"'"}'
expect "iface-traversal" reject bad-iface '{"iface":"../etc","name":"x","pubkey":"'"$PUB"'","token":"'"$TOK_GOOD"'"}'

echo "=== name validation ==="
expect "name-comma" reject bad-name-chars '{"iface":"wg0","name":"a,b","pubkey":"'"$PUB"'","token":"'"$TOK_GOOD"'"}'
expect "name-slash" reject bad-name-chars '{"iface":"wg0","name":"a/b","pubkey":"'"$PUB"'","token":"'"$TOK_GOOD"'"}'
expect "name-shell" reject bad-name-chars '{"iface":"wg0","name":"a;b","pubkey":"'"$PUB"'","token":"'"$TOK_GOOD"'"}'
expect "name-quote" reject bad-name-chars '{"iface":"wg0","name":"a\"b","pubkey":"'"$PUB"'","token":"'"$TOK_GOOD"'"}'
expect "name-empty" reject bad-name-chars '{"iface":"wg0","name":"","pubkey":"'"$PUB"'","token":"'"$TOK_GOOD"'"}'
LONG=$(printf 'A%.0s' {1..65})
expect "name-too-long" reject bad-name-chars "{\"iface\":\"wg0\",\"name\":\"$LONG\",\"pubkey\":\"$PUB\",\"token\":\"$TOK_GOOD\"}"
# name VALIDATIONS THAT SHOULD PASS validation but fail the permit check
expect "name-with-space" reject no-active-permit '{"iface":"wg0","name":"Anna Pixel 8","pubkey":"'"$PUB"'","token":"'"$TOK_GOOD"'"}'
expect "name-apostrophe" reject no-active-permit '{"iface":"wg0","name":"Anna'"'"'s Pixel 8","pubkey":"'"$PUB"'","token":"'"$TOK_GOOD"'"}'
expect "name-unicode" reject no-active-permit '{"iface":"wg0","name":"François","pubkey":"'"$PUB"'","token":"'"$TOK_GOOD"'"}'

echo "=== pubkey validation ==="
expect "pub-short" reject bad-pubkey-shape '{"iface":"wg0","name":"x","pubkey":"AAAA=","token":"'"$TOK_GOOD"'"}'
# 44 chars but uses URL-safe alphabet (- and _) — wrong for standard b64
URL_PUB="A--AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
expect "pub-urlsafe-chars" reject bad-pubkey-shape "{\"iface\":\"wg0\",\"name\":\"x\",\"pubkey\":\"$URL_PUB\",\"token\":\"$TOK_GOOD\"}"

echo "=== token validation ==="
expect "tok-too-short" reject bad-token-shape '{"iface":"wg0","name":"x","pubkey":"'"$PUB"'","token":"AAA"}'
expect "tok-stdb64-chars" reject bad-token-shape '{"iface":"wg0","name":"x","pubkey":"'"$PUB"'","token":"AAA+/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}'

echo "=== iface-present check ==="
expect "iface-not-present" reject iface-not-present '{"iface":"wg99","name":"x","pubkey":"'"$PUB"'","token":"'"$TOK_GOOD"'"}'

echo "=== no permit at all ==="
rm -f "$WORK/permits/"*
expect "no-permit" reject no-active-permit '{"iface":"wg0","name":"alice","pubkey":"'"$PUB"'","token":"'"$TOK_GOOD"'"}'

echo "=== permit name mismatch ==="
write_permit "$TOK_GOOD" "alice-laptop" 600
expect "permit-name-mismatch" reject permit-name-mismatch '{"iface":"wg0","name":"bob","pubkey":"'"$PUB"'","token":"'"$TOK_GOOD"'"}'

echo "=== permit expired ==="
rm -f "$WORK/permits/"*
write_permit "$TOK_GOOD" "alice" -10  # 10 seconds in the past
expect "permit-expired" reject permit-expired '{"iface":"wg0","name":"alice","pubkey":"'"$PUB"'","token":"'"$TOK_GOOD"'"}'

echo "=== happy path with name containing space + apostrophe ==="
rm -f "$WORK/permits/"*
> "$WORK/provisioner.log"
write_permit "$TOK_GOOD" "Anna's Pixel 8" 600
expect "happy-path-spaces" ok '' '{"iface":"wg0","name":"Anna'"'"'s Pixel 8","pubkey":"'"$PUB"'","token":"'"$TOK_GOOD"'"}'
if grep -q "called: wg0 Anna's Pixel 8" "$WORK/provisioner.log"; then
    echo "  PASS [provisioner-saw-name-verbatim]"; pass=$((pass+1))
else
    echo "  FAIL provisioner.log: $(cat "$WORK/provisioner.log")"; fail=$((fail+1))
fi
if [[ ! -f "$WORK/permits/$TOK_GOOD" ]]; then
    echo "  PASS [permit-consumed]"; pass=$((pass+1))
else
    echo "  FAIL permit not removed after happy path"; fail=$((fail+1))
fi

echo "=== single-use: replay with same token after success ==="
expect "replay-no-permit" reject no-active-permit '{"iface":"wg0","name":"Anna'"'"'s Pixel 8","pubkey":"'"$PUB"'","token":"'"$TOK_GOOD"'"}'

echo
echo "summary: $pass passed, $fail failed"
[[ "$fail" -eq 0 ]]
