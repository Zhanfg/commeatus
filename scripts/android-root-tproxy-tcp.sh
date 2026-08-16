#!/system/bin/sh
set -eu

# Android Root TCP-transparent preview for Commeatus.
# Only selected app TCP is intercepted. UDP remains untouched until the native
# transparent UDP ingress lands; this script never pretends otherwise.

PORT="${COMMEATUS_TPROXY_PORT:-12948}"
MARK="${COMMEATUS_TPROXY_MARK:-0x66c0}"
MASK="${COMMEATUS_TPROXY_MASK:-0xffff}"
TABLE="${COMMEATUS_TPROXY_TABLE:-20660}"
PREF="${COMMEATUS_TPROXY_PREF:-20660}"
UID_RANGE="${COMMEATUS_UID_RANGE:-10000-999999}"
IPV6="${COMMEATUS_IPV6:-1}"
STATE_DIR="${COMMEATUS_STATE_DIR:-/data/local/tmp/commeatus-root}"
CHAIN_OUT="CMT_TCP_OUT"
CHAIN_PRE="CMT_TCP_PRE"
PID_FILE="$STATE_DIR/commeatus.pid"
LOG_FILE="$STATE_DIR/commeatus.log"

say() { echo "commeatus-root: $*" >&2; }
die() { say "$*"; exit 1; }

need_root() {
    [ "$(id -u)" = "0" ] || die "root is required"
}

need_tools() {
    command -v ip >/dev/null 2>&1 || die "missing ip"
    command -v iptables >/dev/null 2>&1 || die "missing iptables"
    if [ "$IPV6" = "1" ]; then
        command -v ip6tables >/dev/null 2>&1 || die "IPv6 requested but ip6tables is missing"
    fi
}

ipt() { iptables -w "$@"; }
ipt6() { ip6tables -w "$@"; }

remove_v4() {
    ipt -t mangle -D OUTPUT -p tcp -j "$CHAIN_OUT" 2>/dev/null || true
    ipt -t mangle -D PREROUTING -p tcp -m mark --mark "$MARK/$MASK" -j "$CHAIN_PRE" 2>/dev/null || true
    ipt -t mangle -F "$CHAIN_OUT" 2>/dev/null || true
    ipt -t mangle -X "$CHAIN_OUT" 2>/dev/null || true
    ipt -t mangle -F "$CHAIN_PRE" 2>/dev/null || true
    ipt -t mangle -X "$CHAIN_PRE" 2>/dev/null || true
    ip rule del pref "$PREF" fwmark "$MARK/$MASK" lookup "$TABLE" 2>/dev/null || true
    ip route flush table "$TABLE" 2>/dev/null || true
}

remove_v6() {
    [ "$IPV6" = "1" ] || return 0
    ipt6 -t mangle -D OUTPUT -p tcp -j "$CHAIN_OUT" 2>/dev/null || true
    ipt6 -t mangle -D PREROUTING -p tcp -m mark --mark "$MARK/$MASK" -j "$CHAIN_PRE" 2>/dev/null || true
    ipt6 -t mangle -F "$CHAIN_OUT" 2>/dev/null || true
    ipt6 -t mangle -X "$CHAIN_OUT" 2>/dev/null || true
    ipt6 -t mangle -F "$CHAIN_PRE" 2>/dev/null || true
    ipt6 -t mangle -X "$CHAIN_PRE" 2>/dev/null || true
    ip -6 rule del pref "$PREF" fwmark "$MARK/$MASK" lookup "$TABLE" 2>/dev/null || true
    ip -6 route flush table "$TABLE" 2>/dev/null || true
}

remove_rules() {
    remove_v4
    remove_v6
}

probe_tproxy4() {
    local chain="CMT_TCP_PROBE4"
    ipt -t mangle -N "$chain" 2>/dev/null || die "cannot create IPv4 TPROXY probe chain"
    if ! ipt -t mangle -A "$chain" -p tcp -j TPROXY --on-ip 127.0.0.1 --on-port "$PORT" --tproxy-mark "$MARK/$MASK"; then
        ipt -t mangle -F "$chain" 2>/dev/null || true
        ipt -t mangle -X "$chain" 2>/dev/null || true
        die "kernel/iptables does not provide IPv4 TPROXY"
    fi
    ipt -t mangle -F "$chain"
    ipt -t mangle -X "$chain"
}

probe_tproxy6() {
    [ "$IPV6" = "1" ] || return 0
    local chain="CMT_TCP_PROBE6"
    ipt6 -t mangle -N "$chain" 2>/dev/null || die "cannot create IPv6 TPROXY probe chain"
    if ! ipt6 -t mangle -A "$chain" -p tcp -j TPROXY --on-ip ::1 --on-port "$PORT" --tproxy-mark "$MARK/$MASK"; then
        ipt6 -t mangle -F "$chain" 2>/dev/null || true
        ipt6 -t mangle -X "$chain" 2>/dev/null || true
        die "kernel/ip6tables does not provide IPv6 TPROXY"
    fi
    ipt6 -t mangle -F "$chain"
    ipt6 -t mangle -X "$chain"
}

ensure_table_free() {
    [ -z "$(ip route show table "$TABLE" 2>/dev/null)" ] || die "IPv4 route table $TABLE is already in use"
    if [ "$IPV6" = "1" ]; then
        [ -z "$(ip -6 route show table "$TABLE" 2>/dev/null)" ] || die "IPv6 route table $TABLE is already in use"
    fi
}

install_v4() {
    ip route add local 0.0.0.0/0 dev lo table "$TABLE"
    ip rule add pref "$PREF" fwmark "$MARK/$MASK" lookup "$TABLE"

    ipt -t mangle -N "$CHAIN_OUT"
    ipt -t mangle -A "$CHAIN_OUT" -d 127.0.0.0/8 -j RETURN
    ipt -t mangle -A "$CHAIN_OUT" -d 169.254.0.0/16 -j RETURN
    ipt -t mangle -A "$CHAIN_OUT" -d 224.0.0.0/4 -j RETURN
    ipt -t mangle -A "$CHAIN_OUT" -p tcp -m owner --uid-owner "$UID_RANGE" -j MARK --set-xmark "$MARK/$MASK"

    ipt -t mangle -N "$CHAIN_PRE"
    ipt -t mangle -A "$CHAIN_PRE" -p tcp -j TPROXY --on-ip 127.0.0.1 --on-port "$PORT" --tproxy-mark "$MARK/$MASK"

    # Attach PREROUTING first, OUTPUT last: no selected app packet is marked until
    # the local-delivery target already exists.
    ipt -t mangle -I PREROUTING 1 -p tcp -m mark --mark "$MARK/$MASK" -j "$CHAIN_PRE"
    ipt -t mangle -I OUTPUT 1 -p tcp -j "$CHAIN_OUT"
}

install_v6() {
    [ "$IPV6" = "1" ] || return 0
    ip -6 route add local ::/0 dev lo table "$TABLE"
    ip -6 rule add pref "$PREF" fwmark "$MARK/$MASK" lookup "$TABLE"

    ipt6 -t mangle -N "$CHAIN_OUT"
    ipt6 -t mangle -A "$CHAIN_OUT" -d ::1/128 -j RETURN
    ipt6 -t mangle -A "$CHAIN_OUT" -d fe80::/10 -j RETURN
    ipt6 -t mangle -A "$CHAIN_OUT" -d ff00::/8 -j RETURN
    ipt6 -t mangle -A "$CHAIN_OUT" -p tcp -m owner --uid-owner "$UID_RANGE" -j MARK --set-xmark "$MARK/$MASK"

    ipt6 -t mangle -N "$CHAIN_PRE"
    ipt6 -t mangle -A "$CHAIN_PRE" -p tcp -j TPROXY --on-ip ::1 --on-port "$PORT" --tproxy-mark "$MARK/$MASK"
    ipt6 -t mangle -I PREROUTING 1 -p tcp -m mark --mark "$MARK/$MASK" -j "$CHAIN_PRE"
    ipt6 -t mangle -I OUTPUT 1 -p tcp -j "$CHAIN_OUT"
}

install_rules() {
    need_root
    need_tools
    remove_rules
    ensure_table_free
    probe_tproxy4
    probe_tproxy6
    trap 'remove_rules' INT TERM HUP EXIT
    install_v4
    install_v6
    trap - INT TERM HUP EXIT
    say "TCP TPROXY installed: port=$PORT mark=$MARK/$MASK table=$TABLE uid-range=$UID_RANGE ipv6=$IPV6"
    say "UDP is NOT intercepted in this preview."
}

process_running() {
    [ -f "$PID_FILE" ] || return 1
    local pid
    pid="$(cat "$PID_FILE" 2>/dev/null || true)"
    [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
}

start_daemon() {
    need_root
    need_tools
    [ "$#" -ge 1 ] || die "start requires <config> [binary]"
    local config="$1"
    local binary="${2:-./commeatus}"
    [ -f "$config" ] || die "config not found: $config"
    [ -x "$binary" ] || die "binary not executable: $binary"
    mkdir -p "$STATE_DIR"
    if process_running; then
        die "daemon already running with pid $(cat "$PID_FILE")"
    fi
    remove_rules
    : > "$LOG_FILE"
    nohup "$binary" run --config "$config" >>"$LOG_FILE" 2>&1 </dev/null &
    local pid=$!
    echo "$pid" > "$PID_FILE"
    local n=0
    while [ "$n" -lt 50 ]; do
        if ! kill -0 "$pid" 2>/dev/null; then
            rm -f "$PID_FILE"
            tail -n 80 "$LOG_FILE" >&2 || true
            die "daemon exited during startup"
        fi
        # Give the listener bind path time to finish before installing routing.
        if [ "$n" -ge 5 ]; then
            break
        fi
        sleep 0.1
        n=$((n + 1))
    done
    if ! install_rules; then
        kill "$pid" 2>/dev/null || true
        rm -f "$PID_FILE"
        exit 1
    fi
    say "daemon started: pid=$pid log=$LOG_FILE"
}

stop_daemon() {
    need_root
    need_tools
    remove_rules
    if process_running; then
        local pid
        pid="$(cat "$PID_FILE")"
        kill "$pid" 2>/dev/null || true
        local n=0
        while kill -0 "$pid" 2>/dev/null && [ "$n" -lt 30 ]; do
            sleep 0.1
            n=$((n + 1))
        done
        kill -9 "$pid" 2>/dev/null || true
    fi
    rm -f "$PID_FILE"
    say "TPROXY rules removed and daemon stopped"
}

status() {
    need_root
    need_tools
    if process_running; then
        say "daemon running: pid=$(cat "$PID_FILE")"
    else
        say "daemon not running"
    fi
    ip rule show | grep -F "fwmark" | grep -F "$TABLE" || true
    ipt -t mangle -S "$CHAIN_OUT" 2>/dev/null || true
    ipt -t mangle -S "$CHAIN_PRE" 2>/dev/null || true
    if [ "$IPV6" = "1" ]; then
        ip -6 rule show | grep -F "fwmark" | grep -F "$TABLE" || true
        ipt6 -t mangle -S "$CHAIN_OUT" 2>/dev/null || true
        ipt6 -t mangle -S "$CHAIN_PRE" 2>/dev/null || true
    fi
}

case "${1:-}" in
    install)
        install_rules
        ;;
    remove)
        need_root
        need_tools
        remove_rules
        ;;
    start)
        shift
        start_daemon "$@"
        ;;
    stop)
        stop_daemon
        ;;
    restart)
        shift
        stop_daemon
        start_daemon "$@"
        ;;
    status)
        status
        ;;
    *)
        cat >&2 <<EOF
Usage:
  $0 start <config> [binary]
  $0 stop
  $0 restart <config> [binary]
  $0 install
  $0 remove
  $0 status

Environment:
  COMMEATUS_TPROXY_PORT=$PORT
  COMMEATUS_TPROXY_MARK=$MARK
  COMMEATUS_TPROXY_MASK=$MASK
  COMMEATUS_TPROXY_TABLE=$TABLE
  COMMEATUS_TPROXY_PREF=$PREF
  COMMEATUS_UID_RANGE=$UID_RANGE
  COMMEATUS_IPV6=$IPV6
  COMMEATUS_STATE_DIR=$STATE_DIR
EOF
        exit 2
        ;;
esac
