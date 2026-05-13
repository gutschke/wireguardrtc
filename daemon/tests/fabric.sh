#!/bin/bash
# fabric.sh — minimal namespace-based test fabric for wireguardrtc.
#
# Provides a way to spin up multiple "host" namespaces (each with its own
# network namespace, kernel WireGuard interfaces, nftables, etc.) while
# running entirely as an unprivileged user.  Built on `unshare -Urn`.
#
# Architecture: a single outer user-namespace + network-namespace owns
# all the test hosts as child processes.  Each host is itself in its own
# net namespace, but shares the user namespace with the parent so we can
# move veth interfaces between them with `ip link set ... netns <pid>`.
# This sidesteps the "ip netns add" mount-propagation issue in
# a sandbox.
#
# ─── Modes of use ──────────────────────────────────────────────────────────
#
#  1. Run a one-shot test script inside the fabric:
#
#        ./fabric.sh ./my-test.sh
#
#     The fabric is set up, my-test.sh runs (with `fabric_*` functions in
#     scope after sourcing this file), and everything is torn down on exit.
#
#  2. Use as a library inside a script that needs the fabric:
#
#        #!/bin/bash
#        # If we're not yet inside the fabric, re-exec via fabric.sh.
#        [[ -z "$WGRTC_FABRIC_INSIDE" ]] && exec /path/to/fabric.sh "$0" "$@"
#        source /path/to/fabric.sh   # provides fabric_* functions
#        fabric_create_host server
#        fabric_create_host client
#        fabric_link server client
#        fabric_exec server ip addr add 10.0.0.1/24 dev veth-server-client
#        ...
#
#  3. As a library only (sourced from inside a fabric session):
#
#        source fabric.sh   # safe re-source; just defines functions
#
# ─── Public API ────────────────────────────────────────────────────────────
#
#   fabric_create_host <name>
#       Spawn a new host with an isolated network namespace.
#
#   fabric_link <host1> <host2> [iface1] [iface2]
#       Connect two hosts via a veth pair.  Default interface names are
#       `veth-<host1>-<host2>` and `veth-<host2>-<host1>`.
#
#   fabric_exec <host> <cmd...>
#       Run cmd in the host's namespace, fire-and-forget (no output capture).
#
#   fabric_exec_capture <host> <cmd...>
#       Run cmd in the host's namespace, wait for completion, print stdout
#       and stderr.  Returns the command's exit code.
#
#   fabric_pid <host>
#       Print the host's process PID (for ad-hoc nsenter from inside fabric).
#
#   fabric_status
#       List active hosts and their PIDs.
#
# Environment:
#   FABRIC_DEBUG=1     Enable verbose logging to stderr.
#   FABRIC_TMP         Override the per-fabric scratch directory (default
#                      auto-created under $TMPDIR or /tmp).
#
# Exit:
#   The fabric tears down all hosts and removes the scratch directory on
#   normal exit, EXIT trap, or signal.
#
# Caveats:
#   - `ping` does NOT work inside fabric hosts.  ICMP raw sockets require
#     CAP_NET_RAW in the host's *initial* network namespace, which our
#     user-namespace "root" does not possess.  Use TCP or UDP connectivity
#     probes (nc, socat, real protocol traffic) instead.  The wireguardrtc
#     daemon's hole-punching is UDP-based and works fine.
#   - The fabric uses an outer user-namespace + network-namespace for
#     isolation.  It does not isolate /sys, /proc, or the cgroup hierarchy
#     beyond what `unshare -U` and `unshare -n` provide.  Tests should not
#     assume cgroup-level resource isolation.

set -euo pipefail

# ─── Detect mode: re-exec into fabric if needed ────────────────────────────

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # We're being executed as a script (not sourced).
    if [[ -z "${WGRTC_FABRIC_INSIDE:-}" ]]; then
        # Top-level: re-exec ourselves inside an outer unshare.
        export WGRTC_FABRIC_INSIDE=1
        exec unshare -Urn --fork bash "$0" "$@"
    fi
    # We're inside the fabric (re-exec'd).  Set up state, register cleanup,
    # then run the user's command.  Functions are defined below.
    _fabric_main_inner=1
else
    # Sourced.  Skip auto-unshare; just provide the functions.
    _fabric_main_inner=0
fi

# ─── State ─────────────────────────────────────────────────────────────────

if [[ -z "${FABRIC_TMP:-}" ]]; then
    FABRIC_TMP=$(mktemp -d "${TMPDIR:-/tmp}/wgrtc-fabric.XXXXXX")
    export FABRIC_TMP
fi

_fabric_log() {
    [[ "${FABRIC_DEBUG:-0}" == "1" ]] && echo "[fabric] $*" >&2
    return 0
}

_fabric_die() {
    echo "[fabric] error: $*" >&2
    exit 1
}

# ─── Cleanup ───────────────────────────────────────────────────────────────

_fabric_cleanup() {
    local rc=$?
    _fabric_log "cleanup (rc=$rc)"
    # Tell each host to exit.  Best-effort.
    local cmdfifo
    shopt -s nullglob
    for cmdfifo in "$FABRIC_TMP"/*.cmd; do
        [[ -p "$cmdfifo" ]] || continue
        printf '%s\0' "__fabric_exit__" > "$cmdfifo" 2>/dev/null || true
    done
    shopt -u nullglob
    # Kill any lingering children.
    local pids
    pids=$(jobs -p 2>/dev/null || true)
    if [[ -n "$pids" ]]; then
        kill $pids 2>/dev/null || true
        wait 2>/dev/null || true
    fi
    rm -rf "$FABRIC_TMP"
    return $rc
}

if [[ $_fabric_main_inner -eq 1 ]]; then
    trap _fabric_cleanup EXIT INT TERM HUP
fi

# ─── Public functions ──────────────────────────────────────────────────────

fabric_create_host() {
    local name="$1"
    [[ -z "$name" ]] && _fabric_die "fabric_create_host: name required"
    [[ "$name" =~ ^[A-Za-z0-9_-]+$ ]] \
        || _fabric_die "fabric_create_host: invalid name $name"
    [[ -e "$FABRIC_TMP/$name.pid" ]] \
        && _fabric_die "fabric_create_host: $name already exists"

    local cmdfifo="$FABRIC_TMP/$name.cmd"
    mkfifo "$cmdfifo"

    # Spawn the host's worker.  It runs in its own net namespace within
    # the fabric's user namespace.  It reads command MESSAGES from its
    # FIFO (NUL-delimited so multi-line commands survive intact) and
    # evaluates them in its own bash context.
    unshare -n --fork bash -c "
        set +e
        ip link set lo up
        echo \$BASHPID > '$FABRIC_TMP/$name.pid'
        # Open the FIFO read+write so reads block on empty rather than EOF
        # when the writer side temporarily closes.
        exec 3<> '$cmdfifo'
        while IFS= read -r -d '' msg <&3; do
            [[ \"\$msg\" == '__fabric_exit__' ]] && break
            eval \"\$msg\"
        done
    " &

    # Wait until the worker has registered its PID.
    local i
    for ((i=0; i<50; i++)); do
        [[ -e "$FABRIC_TMP/$name.pid" ]] && break
        sleep 0.05
    done
    [[ -e "$FABRIC_TMP/$name.pid" ]] \
        || _fabric_die "fabric_create_host: $name failed to register"
    _fabric_log "host $name pid=$(<"$FABRIC_TMP/$name.pid")"
}

fabric_link() {
    local h1="$1" h2="$2"
    local if1="${3:-veth-${h1}-${h2}}"
    local if2="${4:-veth-${h2}-${h1}}"
    [[ -e "$FABRIC_TMP/$h1.pid" ]] || _fabric_die "fabric_link: unknown host $h1"
    [[ -e "$FABRIC_TMP/$h2.pid" ]] || _fabric_die "fabric_link: unknown host $h2"
    local p1 p2
    p1=$(<"$FABRIC_TMP/$h1.pid")
    p2=$(<"$FABRIC_TMP/$h2.pid")
    ip link add "$if1" type veth peer name "$if2"
    ip link set "$if1" netns "$p1"
    ip link set "$if2" netns "$p2"
    _fabric_log "linked $h1:$if1 <-> $h2:$if2"
}

fabric_exec() {
    local h="$1"; shift
    [[ -e "$FABRIC_TMP/$h.cmd" ]] || _fabric_die "fabric_exec: unknown host $h"
    # NUL-delimit the message so multi-line commands survive `read -d ''`.
    printf '%s\0' "$*" > "$FABRIC_TMP/$h.cmd"
}

fabric_exec_capture() {
    local h="$1"; shift
    [[ -e "$FABRIC_TMP/$h.cmd" ]] || _fabric_die "fabric_exec_capture: unknown host $h"
    # Allocate per-call output and signaling files.
    local outfile="$FABRIC_TMP/.out.$$.$RANDOM"
    local rcfile="$outfile.rc"
    # Treat the args as a single shell command string (joined with spaces,
    # like `bash -c`).  This means callers can pass either one quoted
    # string or multiple words; both forms work the way one expects from
    # a shell.  Embedded spaces inside single args are preserved when
    # callers quote them, e.g. fabric_exec_capture A 'echo "a b"'.
    local cmd="$*"
    # Wrap in `bash -c <script>` so multi-line / heredoc-style scripts
    # work regardless of trailing whitespace.  printf %q guards the
    # script body against shell metacharacter interpretation by the
    # outer eval.
    local quoted_cmd
    quoted_cmd=$(printf '%q' "$cmd")
    printf '%s\0' "bash -c $quoted_cmd > '$outfile' 2>&1 ; echo \$? > '$rcfile'" \
        > "$FABRIC_TMP/$h.cmd"
    # Wait for completion.  Default 60s; override with FABRIC_EXEC_TIMEOUT=N
    # (in seconds) for tests that legitimately need longer.
    local timeout="${FABRIC_EXEC_TIMEOUT:-60}"
    local iters=$((timeout * 20))    # 50ms per tick
    local i
    for ((i=0; i<iters; i++)); do
        [[ -e "$rcfile" ]] && break
        sleep 0.05
    done
    if [[ ! -e "$rcfile" ]]; then
        _fabric_die "fabric_exec_capture: timeout in $h: $cmd"
    fi
    local rc
    rc=$(<"$rcfile")
    cat "$outfile"
    rm -f "$outfile" "$rcfile"
    return "$rc"
}

fabric_pid() {
    local h="$1"
    [[ -e "$FABRIC_TMP/$h.pid" ]] || _fabric_die "fabric_pid: unknown host $h"
    cat "$FABRIC_TMP/$h.pid"
}

fabric_status() {
    echo "fabric tmp dir: $FABRIC_TMP"
    local f h pid
    for f in "$FABRIC_TMP"/*.pid; do
        [[ -e "$f" ]] || continue
        h=$(basename "$f" .pid)
        pid=$(<"$f")
        if kill -0 "$pid" 2>/dev/null; then
            echo "  $h  pid=$pid  net=$(readlink "/proc/$pid/ns/net" 2>/dev/null || echo '?')"
        else
            echo "  $h  pid=$pid  (dead)"
        fi
    done
}

# ─── Inner main: run user command if we re-exec'd ──────────────────────────

if [[ $_fabric_main_inner -eq 1 ]]; then
    if [[ $# -eq 0 ]]; then
        echo "fabric: ready (FABRIC_TMP=$FABRIC_TMP)" >&2
        echo "fabric: no command given; entering interactive bash" >&2
        bash --rcfile <(echo "PS1='[fabric]\\$ '")
    else
        # Run the user's command/script.  If it's a shell script, source
        # this file inside it to get the fabric_* functions.  We expose
        # FABRIC_SH as the path so tests can `source "$FABRIC_SH"`.
        FABRIC_SH="$(realpath "$0")"
        export FABRIC_SH FABRIC_TMP WGRTC_FABRIC_INSIDE
        "$@"
    fi
fi
