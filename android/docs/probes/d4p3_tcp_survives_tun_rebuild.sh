#!/bin/bash
# D4.P3 — empirical kernel probe.
#
# The Android-side claim (cascade-n-design.md §Reconfigure): when
# VpnService.Builder.establish() is called twice with identical
# addresses+routes, kernel TCP sockets survive the swap because
# they're 4-tuple-keyed, not bound to TUN identity.
#
# `Builder.establish()` on Android wraps Linux kernel TUN creation
# + IP address binding + route programming. So the kernel-level
# behavior is observable on any Linux box with root: the question
# is whether DELETING a tun device and IMMEDIATELY RECREATING it
# with the same address preserves bound sockets, OR severs them.
#
# This script probes that by:
#   1. Creating tun0 with 10.250.0.1/32, route 10.250.0.0/24.
#   2. Opening a TCP listener bound to 10.250.0.1:9999 (background nc).
#   3. Verifying the listener is alive (ss -ltn).
#   4. Tearing down tun0 and recreating it with identical config.
#   5. Re-checking whether the listener still appears in ss output
#      AND whether a fresh client can connect to it through the
#      surviving listener.
#
# Outcomes:
#   - Listener survives + connect works  →  hypothesis correct, kernel
#     keeps socket state across address-binding cycle.
#   - Listener survives but connect fails →  socket-half-alive (orphaned
#     by lost route).  Hypothesis partly wrong; production needs to
#     re-bind sockets on rebuild.
#   - Listener gone after rebuild        →  hypothesis wrong, sockets
#     get torn down with the address.  Production cannot use a swap-based
#     reconfigure model; would need a different design (single TUN with
#     dynamic route updates, etc).

set -euo pipefail

TUN=tun-d4p3
ADDR=10.250.0.1
PREFIX=32
SUBNET=10.250.0.0/24
PORT=9999

cleanup() {
  ip link del "$TUN" 2>/dev/null || true
  pkill -f "nc -l 10.250.0" 2>/dev/null || true
  pkill -f "tail -f /dev/null" 2>/dev/null || true
}
trap cleanup EXIT

# ---- step 1: create tun ----
ip tuntap add dev "$TUN" mode tun
ip addr add "$ADDR/$PREFIX" dev "$TUN"
ip link set "$TUN" up
ip route add "$SUBNET" dev "$TUN"

# Keep the tun open so it doesn't auto-delete when nc is done.
tail -f /dev/null > /dev/$TUN 2>/dev/null &
HOLDER=$!

# ---- step 2: open TCP listener ----
# Use ncat (or nc) to listen — keep it open with -k so we can connect twice.
nc -lk "$ADDR" "$PORT" </dev/null >/dev/null 2>&1 &
LISTENER=$!
sleep 0.2

# ---- step 3: snapshot listener state ----
echo "=== before rebuild ==="
ss -ltn "src $ADDR" || true
ss -ltn | grep ":$PORT" || echo "no listener visible on $PORT"

# Connect once to confirm the listener is genuinely accepting.
echo "before" | timeout 2 nc -q 1 "$ADDR" "$PORT" >/dev/null && \
  echo "connect-before: OK" || echo "connect-before: FAIL"

# ---- step 4: rebuild tun ----
echo "=== rebuilding tun ==="
kill $HOLDER 2>/dev/null || true
ip link del "$TUN" 2>/dev/null || true

# Now recreate with IDENTICAL config.
ip tuntap add dev "$TUN" mode tun
ip addr add "$ADDR/$PREFIX" dev "$TUN"
ip link set "$TUN" up
ip route add "$SUBNET" dev "$TUN"
tail -f /dev/null > /dev/$TUN 2>/dev/null &
HOLDER=$!
sleep 0.2

# ---- step 5: did the listener survive? ----
echo "=== after rebuild ==="
ss -ltn "src $ADDR" || true
ss -ltn | grep ":$PORT" || echo "no listener visible on $PORT"

# Probe the listener PID directly — if `nc` saw the address vanish
# it would have exited.
if kill -0 $LISTENER 2>/dev/null; then
  echo "listener-pid-alive: YES"
else
  echo "listener-pid-alive: NO (process exited during rebuild)"
fi

# Try to connect again. If the listener is half-alive (process up
# but socket detached from the address) this will timeout.
echo "after" | timeout 2 nc -q 1 "$ADDR" "$PORT" >/dev/null && \
  echo "connect-after: OK" || echo "connect-after: FAIL"

# ---- step 6: the harder case — ESTABLISHED connection survival ----
#
# The above only proves a LISTEN socket survives. The design doc
# claim is that an ESTABLISHED TCP connection (with peer 4-tuple,
# RTT state, congestion window) ALSO survives the rebuild — that's
# the load-bearing UX promise.
#
# Probe: establish a long-lived connection, hold it open across
# a SECOND teardown+recreate cycle, then read+write through it.
echo "=== ESTABLISHED-survival probe ==="

# Set up a second listener (the first nc may have peer state from
# previous probes that confuses this round).
nc -lk "$ADDR" $((PORT+1)) </dev/null >/tmp/srv.out 2>&1 &
LISTENER2=$!
sleep 0.2

# Open a long-running client connection via a coproc-style fifo.
mkfifo /tmp/client.fifo 2>/dev/null || true
exec 9<>/tmp/client.fifo
nc -q 30 "$ADDR" $((PORT+1)) <&9 >/tmp/client.out 2>&1 &
CLIENT=$!
sleep 0.3

# Send "alpha" — should appear in server's output.
echo "alpha" >&9
sleep 0.2
if grep -q "alpha" /tmp/srv.out 2>/dev/null; then
  echo "estab-before: OK (alpha received)"
else
  echo "estab-before: FAIL — server didn't see 'alpha'"
fi

# Snapshot the connection 4-tuple before rebuild.
echo "--- ss snapshot before rebuild ---"
ss -tn state established | grep ":$((PORT+1))" || echo "(no ESTABLISHED on $((PORT+1)))"

# Tear the TUN down + recreate (the same swap that joiner-N forces).
kill $HOLDER 2>/dev/null || true
ip link del "$TUN" 2>/dev/null || true
ip tuntap add dev "$TUN" mode tun
ip addr add "$ADDR/$PREFIX" dev "$TUN"
ip link set "$TUN" up
ip route add "$SUBNET" dev "$TUN"
tail -f /dev/null > /dev/$TUN 2>/dev/null &
HOLDER=$!
sleep 0.3

# Did the connection survive?
echo "--- ss snapshot after rebuild ---"
ss -tn state established | grep ":$((PORT+1))" || echo "(no ESTABLISHED on $((PORT+1)))"

# Send "omega" through the SAME client — should appear in server.
echo "omega" >&9
sleep 0.3
if grep -q "omega" /tmp/srv.out 2>/dev/null; then
  echo "estab-after: OK (omega received through pre-existing connection)"
else
  echo "estab-after: FAIL — kernel TCP did NOT survive the rebuild"
  echo "  server log:"
  sed 's/^/    /' /tmp/srv.out
fi

# Cleanup the second probe.
kill $CLIENT $LISTENER2 2>/dev/null || true
exec 9>&-
rm -f /tmp/client.fifo /tmp/client.out /tmp/srv.out

# ---- cleanup is in trap ----
echo "=== done ==="
