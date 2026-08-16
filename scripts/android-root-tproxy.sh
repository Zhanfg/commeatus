#!/system/bin/sh
set -eu

PORT="${COMMEATUS_TPROXY_PORT:-12948}"
MARK="${COMMEATUS_TPROXY_MARK:-0x66c0}"
MASK="${COMMEATUS_TPROXY_MASK:-0xffff}"
TABLE="${COMMEATUS_TPROXY_TABLE:-20660}"
PREF="${COMMEATUS_TPROXY_PREF:-20660}"
UID_RANGE="${COMMEATUS_UID_RANGE:-10000-999999}"
IPV6="${COMMEATUS_IPV6:-1}"
STATE_DIR="${COMMEATUS_STATE_DIR:-/data/local/tmp/commeatus-root}"
TCP_OUT="CMT_TCP_OUT"
TCP_PRE="CMT_TCP_PRE"
UDP_OUT="CMT_UDP_OUT"
UDP_PRE="CMT_UDP_PRE"
PID_FILE="$STATE_DIR/commeatus.pid"
LOG_FILE="$STATE_DIR/commeatus.log"

say() { echo "commeatus-root: $*" >&2; }
die() { say "$*"; exit 1; }
need_root() { [ "$(id -u)" = "0" ] || die "root is required"; }
need_tools() {
    command -v ip >/dev/null 2>&1 || die "missing ip"
    command -v iptables >/dev/null 2>&1 || die "missing iptables"
    if [ "$IPV6" = "1" ]; then command -v ip6tables >/dev/null 2>&1 || die "IPv6 requested but ip6tables is missing"; fi
}
ipt() { iptables -w "$@"; }
ipt6() { ip6tables -w "$@"; }

remove_family() {
    local cmd="$1" ipcmd="$2"
    for proto_chain in "tcp:$TCP_OUT:$TCP_PRE" "udp:$UDP_OUT:$UDP_PRE"; do
        local proto out pre
        proto="${proto_chain%%:*}"
        local rest="${proto_chain#*:}"
        out="${rest%%:*}"
        pre="${rest#*:}"
        $cmd -t mangle -D OUTPUT -p "$proto" -j "$out" 2>/dev/null || true
        $cmd -t mangle -D PREROUTING -p "$proto" -m mark --mark "$MARK/$MASK" -j "$pre" 2>/dev/null || true
        $cmd -t mangle -F "$out" 2>/dev/null || true
        $cmd -t mangle -X "$out" 2>/dev/null || true
        $cmd -t mangle -F "$pre" 2>/dev/null || true
        $cmd -t mangle -X "$pre" 2>/dev/null || true
    done
    $ipcmd rule del pref "$PREF" fwmark "$MARK/$MASK" lookup "$TABLE" 2>/dev/null || true
    $ipcmd route flush table "$TABLE" 2>/dev/null || true
}
remove_rules() {
    remove_family "iptables -w" "ip"
    if [ "$IPV6" = "1" ]; then remove_family "ip6tables -w" "ip -6"; fi
}

probe_one() {
    local cmd="$1" family="$2" proto="$3" on_ip="$4" suffix="$5"
    local chain="CMT_PROBE_${proto}_${suffix}"
    $cmd -t mangle -N "$chain" 2>/dev/null || die "cannot create $family $proto TPROXY probe chain"
    if ! $cmd -t mangle -A "$chain" -p "$proto" -j TPROXY --on-ip "$on_ip" --on-port "$PORT" --tproxy-mark "$MARK/$MASK"; then
        $cmd -t mangle -F "$chain" 2>/dev/null || true
        $cmd -t mangle -X "$chain" 2>/dev/null || true
        die "$family $proto TPROXY is unavailable"
    fi
    $cmd -t mangle -F "$chain"
    $cmd -t mangle -X "$chain"
}
probe_all() {
    probe_one "iptables -w" IPv4 tcp 127.0.0.1 4
    probe_one "iptables -w" IPv4 udp 127.0.0.1 4
    if [ "$IPV6" = "1" ]; then
        probe_one "ip6tables -w" IPv6 tcp ::1 6
        probe_one "ip6tables -w" IPv6 udp ::1 6
    fi
}

ensure_table_free() {
    [ -z "$(ip route show table "$TABLE" 2>/dev/null)" ] || die "IPv4 route table $TABLE is already in use"
    if [ "$IPV6" = "1" ]; then [ -z "$(ip -6 route show table "$TABLE" 2>/dev/null)" ] || die "IPv6 route table $TABLE is already in use"; fi
}

install_protocol_chain() {
    local cmd="$1" proto="$2" out="$3" pre="$4" on_ip="$5"
    $cmd -t mangle -N "$out"
    if [ "$cmd" = "iptables -w" ]; then
        $cmd -t mangle -A "$out" -d 127.0.0.0/8 -j RETURN
        $cmd -t mangle -A "$out" -d 169.254.0.0/16 -j RETURN
        $cmd -t mangle -A "$out" -d 224.0.0.0/4 -j RETURN
    else
        $cmd -t mangle -A "$out" -d ::1/128 -j RETURN
        $cmd -t mangle -A "$out" -d fe80::/10 -j RETURN
        $cmd -t mangle -A "$out" -d ff00::/8 -j RETURN
    fi
    $cmd -t mangle -A "$out" -p "$proto" -m owner --uid-owner "$UID_RANGE" -j MARK --set-xmark "$MARK/$MASK"
    $cmd -t mangle -N "$pre"
    $cmd -t mangle -A "$pre" -p "$proto" -j TPROXY --on-ip "$on_ip" --on-port "$PORT" --tproxy-mark "$MARK/$MASK"
    $cmd -t mangle -I PREROUTING 1 -p "$proto" -m mark --mark "$MARK/$MASK" -j "$pre"
}

install_rules() {
    need_root; need_tools; remove_rules; ensure_table_free; probe_all
    trap 'remove_rules' INT TERM HUP EXIT
    ip route add local 0.0.0.0/0 dev lo table "$TABLE"
    ip rule add pref "$PREF" fwmark "$MARK/$MASK" lookup "$TABLE"
    install_protocol_chain "iptables -w" tcp "$TCP_OUT" "$TCP_PRE" 127.0.0.1
    install_protocol_chain "iptables -w" udp "$UDP_OUT" "$UDP_PRE" 127.0.0.1
    if [ "$IPV6" = "1" ]; then
        ip -6 route add local ::/0 dev lo table "$TABLE"
        ip -6 rule add pref "$PREF" fwmark "$MARK/$MASK" lookup "$TABLE"
        install_protocol_chain "ip6tables -w" tcp "$TCP_OUT" "$TCP_PRE" ::1
        install_protocol_chain "ip6tables -w" udp "$UDP_OUT" "$UDP_PRE" ::1
    fi
    # Enable app marking only after all local delivery/TPROXY hooks exist.
    ipt -t mangle -I OUTPUT 1 -p tcp -j "$TCP_OUT"
    ipt -t mangle -I OUTPUT 1 -p udp -j "$UDP_OUT"
    if [ "$IPV6" = "1" ]; then
        ipt6 -t mangle -I OUTPUT 1 -p tcp -j "$TCP_OUT"
        ipt6 -t mangle -I OUTPUT 1 -p udp -j "$UDP_OUT"
    fi
    trap - INT TERM HUP EXIT
    say "TCP+UDP TPROXY installed: port=$PORT mark=$MARK/$MASK table=$TABLE uid-range=$UID_RANGE ipv6=$IPV6"
}

process_running() {
    [ -f "$PID_FILE" ] || return 1
    local pid="$(cat "$PID_FILE" 2>/dev/null || true)"
    [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
}
start_daemon() {
    need_root; need_tools
    [ "$#" -ge 1 ] || die "start requires <config> [binary]"
    local config="$1" binary="${2:-./commeatus}"
    [ -f "$config" ] || die "config not found: $config"
    [ -x "$binary" ] || die "binary not executable: $binary"
    mkdir -p "$STATE_DIR"
    process_running && die "daemon already running with pid $(cat "$PID_FILE")"
    remove_rules
    : > "$LOG_FILE"
    nohup "$binary" run --config "$config" >>"$LOG_FILE" 2>&1 </dev/null &
    local pid=$!
    echo "$pid" > "$PID_FILE"
    local n=0
    while [ "$n" -lt 50 ]; do
        if ! kill -0 "$pid" 2>/dev/null; then rm -f "$PID_FILE"; tail -n 80 "$LOG_FILE" >&2 || true; die "daemon exited during startup"; fi
        [ "$n" -ge 5 ] && break
        sleep 0.1; n=$((n + 1))
    done
    if ! install_rules; then kill "$pid" 2>/dev/null || true; rm -f "$PID_FILE"; exit 1; fi
    say "daemon started: pid=$pid log=$LOG_FILE"
}
stop_daemon() {
    need_root; need_tools; remove_rules
    if process_running; then
        local pid="$(cat "$PID_FILE")" n=0
        kill "$pid" 2>/dev/null || true
        while kill -0 "$pid" 2>/dev/null && [ "$n" -lt 30 ]; do sleep 0.1; n=$((n + 1)); done
        kill -9 "$pid" 2>/dev/null || true
    fi
    rm -f "$PID_FILE"; say "TPROXY rules removed and daemon stopped"
}
status() {
    need_root; need_tools
    process_running && say "daemon running: pid=$(cat "$PID_FILE")" || say "daemon not running"
    ip rule show | grep -F "fwmark" | grep -F "$TABLE" || true
    for chain in "$TCP_OUT" "$TCP_PRE" "$UDP_OUT" "$UDP_PRE"; do ipt -t mangle -S "$chain" 2>/dev/null || true; done
    if [ "$IPV6" = "1" ]; then
        ip -6 rule show | grep -F "fwmark" | grep -F "$TABLE" || true
        for chain in "$TCP_OUT" "$TCP_PRE" "$UDP_OUT" "$UDP_PRE"; do ipt6 -t mangle -S "$chain" 2>/dev/null || true; done
    fi
}
case "${1:-}" in
    install) install_rules ;;
    remove) need_root; need_tools; remove_rules ;;
    start) shift; start_daemon "$@" ;;
    stop) stop_daemon ;;
    restart) shift; stop_daemon; start_daemon "$@" ;;
    status) status ;;
    *) echo "usage: $0 start <config> [binary] | stop | restart <config> [binary] | install | remove | status" >&2; exit 2 ;;
esac
