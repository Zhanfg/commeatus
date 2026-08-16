#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "tproxy-tcp-netns-e2e: root is required (run with sudo)" >&2
  exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
binary="${1:-$repo_root/target/release/commeatus}"
binary="$(realpath "$binary")"
helper="$repo_root/scripts/android-root-tproxy-tcp.sh"

[[ -x "$binary" ]] || { echo "missing executable: $binary" >&2; exit 1; }
command -v iptables >/dev/null
command -v ip >/dev/null
command -v setpriv >/dev/null
command -v python3 >/dev/null

ns_cmt="cmt-$RANDOM-$$"
ns_srv="srv-$RANDOM-$$"
state="/tmp/commeatus-netns-$RANDOM-$$"
config="/tmp/commeatus-netns-$RANDOM-$$.conf"
server_pid=""

cleanup() {
  set +e
  if ip netns list | grep -q "^$ns_cmt\b"; then
    ip netns exec "$ns_cmt" env \
      COMMEATUS_IPV6=0 \
      COMMEATUS_UID_RANGE=10000-10000 \
      COMMEATUS_STATE_DIR="$state" \
      sh "$helper" stop >/dev/null 2>&1 || true
  fi
  [[ -z "$server_pid" ]] || kill "$server_pid" >/dev/null 2>&1 || true
  ip netns del "$ns_cmt" >/dev/null 2>&1 || true
  ip netns del "$ns_srv" >/dev/null 2>&1 || true
  rm -rf "$state" "$config"
}
trap cleanup EXIT INT TERM

ip netns add "$ns_cmt"
ip netns add "$ns_srv"
ip link add veth-cmt type veth peer name veth-srv
ip link set veth-cmt netns "$ns_cmt"
ip link set veth-srv netns "$ns_srv"
ip -n "$ns_cmt" addr add 10.203.0.1/24 dev veth-cmt
ip -n "$ns_srv" addr add 10.203.0.2/24 dev veth-srv
ip -n "$ns_cmt" link set lo up
ip -n "$ns_srv" link set lo up
ip -n "$ns_cmt" link set veth-cmt up
ip -n "$ns_srv" link set veth-srv up

cat > "$config" <<'EOF'
version 1
listen tproxy-tcp 127.0.0.1:12948
default direct
EOF

ip netns exec "$ns_srv" python3 -u - <<'PY' &
import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("10.203.0.2", 18080))
s.listen(4)
while True:
    c, _ = s.accept()
    data = c.recv(65535)
    c.sendall(b"echo:" + data)
    c.close()
PY
server_pid=$!

server_ready=0
for _ in $(seq 1 50); do
  if ip netns exec "$ns_cmt" python3 - <<'PY'
import socket
s = socket.socket()
s.settimeout(0.1)
try:
    s.connect(("10.203.0.2", 18080))
except OSError:
    raise SystemExit(1)
finally:
    s.close()
PY
  then
    server_ready=1
    break
  fi
  sleep 0.1
done
[[ "$server_ready" -eq 1 ]] || { echo "echo server did not become ready" >&2; exit 1; }

ip netns exec "$ns_cmt" env \
  COMMEATUS_IPV6=0 \
  COMMEATUS_UID_RANGE=10000-10000 \
  COMMEATUS_STATE_DIR="$state" \
  sh "$helper" start "$config" "$binary"

ip netns exec "$ns_cmt" env \
  COMMEATUS_IPV6=0 \
  COMMEATUS_UID_RANGE=10000-10000 \
  COMMEATUS_STATE_DIR="$state" \
  sh "$helper" status

response="$(ip netns exec "$ns_cmt" setpriv --reuid=10000 --regid=10000 --clear-groups python3 - <<'PY'
import socket
s = socket.create_connection(("10.203.0.2", 18080), timeout=5)
s.sendall(b"through-tproxy")
data = s.recv(65535)
print(data.decode(), end="")
s.close()
PY
)"
[[ "$response" == "echo:through-tproxy" ]]

iptables_out="$(ip netns exec "$ns_cmt" iptables -w -t mangle -L CMT_TCP_OUT -n -v -x)"
iptables_pre="$(ip netns exec "$ns_cmt" iptables -w -t mangle -L CMT_TCP_PRE -n -v -x)"
printf '%s\n' "$iptables_out"
printf '%s\n' "$iptables_pre"
out_packets="$(awk '/MARK/ {print $1; exit}' <<<"$iptables_out")"
pre_packets="$(awk '/TPROXY/ {print $1; exit}' <<<"$iptables_pre")"
[[ "${out_packets:-0}" -ge 1 ]]
[[ "${pre_packets:-0}" -ge 1 ]]

ip netns exec "$ns_cmt" env \
  COMMEATUS_IPV6=0 \
  COMMEATUS_UID_RANGE=10000-10000 \
  COMMEATUS_STATE_DIR="$state" \
  sh "$helper" stop

! ip netns exec "$ns_cmt" iptables -w -t mangle -S CMT_TCP_OUT >/dev/null 2>&1
! ip netns exec "$ns_cmt" iptables -w -t mangle -S CMT_TCP_PRE >/dev/null 2>&1
! ip netns exec "$ns_cmt" ip rule show | grep -q 'lookup 20660'
[[ ! -e "$state/commeatus.pid" ]]

echo "tproxy-tcp-netns-e2e: PASS"
