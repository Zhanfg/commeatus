#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "tproxy-udp-netns-e2e: root is required (run with sudo)" >&2
  exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
binary="$(realpath "${1:-$repo_root/target/release/commeatus}")"
helper="$repo_root/scripts/android-root-tproxy.sh"
[[ -x "$binary" ]] || { echo "missing executable: $binary" >&2; exit 1; }

ns_cmt="cmt-udp-$RANDOM-$$"
ns_srv="srv-udp-$RANDOM-$$"
state="/tmp/commeatus-udp-netns-$RANDOM-$$"
config="/tmp/commeatus-udp-netns-$RANDOM-$$.conf"
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
ip link add veth-cmt-udp type veth peer name veth-srv-udp
ip link set veth-cmt-udp netns "$ns_cmt"
ip link set veth-srv-udp netns "$ns_srv"
ip -n "$ns_cmt" addr add 10.204.0.1/24 dev veth-cmt-udp
ip -n "$ns_srv" addr add 10.204.0.2/24 dev veth-srv-udp
ip -n "$ns_cmt" link set lo up
ip -n "$ns_srv" link set lo up
ip -n "$ns_cmt" link set veth-cmt-udp up
ip -n "$ns_srv" link set veth-srv-udp up

cat > "$config" <<'EOF'
version 1
listen tproxy-tcp 127.0.0.1:12948
listen tproxy-udp 127.0.0.1:12948
default direct
EOF

ip netns exec "$ns_srv" python3 -u - <<'PY' &
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("10.204.0.2", 18081))
while True:
    data, peer = s.recvfrom(65535)
    s.sendto(b"echo:" + data if data else b"", peer)
PY
server_pid=$!
sleep 0.2

ip netns exec "$ns_cmt" env \
  COMMEATUS_IPV6=0 \
  COMMEATUS_UID_RANGE=10000-10000 \
  COMMEATUS_STATE_DIR="$state" \
  sh "$helper" start "$config" "$binary"

response="$(ip netns exec "$ns_cmt" setpriv --reuid=10000 --regid=10000 --clear-groups python3 - <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("10.204.0.1", 0))
s.settimeout(5)
s.sendto(b"through-tproxy-udp", ("10.204.0.2", 18081))
data, source = s.recvfrom(65535)
assert source == ("10.204.0.2", 18081), source
assert data == b"echo:through-tproxy-udp", data
s.sendto(b"", ("10.204.0.2", 18081))
data, source = s.recvfrom(65535)
assert source == ("10.204.0.2", 18081), source
assert data == b"", data
print("PASS", end="")
PY
)"
[[ "$response" == "PASS" ]]

udp_out="$(ip netns exec "$ns_cmt" iptables -w -t mangle -L CMT_UDP_OUT -n -v -x)"
udp_pre="$(ip netns exec "$ns_cmt" iptables -w -t mangle -L CMT_UDP_PRE -n -v -x)"
printf '%s\n' "$udp_out"
printf '%s\n' "$udp_pre"
out_packets="$(awk '/MARK/ {print $1; exit}' <<<"$udp_out")"
pre_packets="$(awk '/TPROXY/ {print $1; exit}' <<<"$udp_pre")"
[[ "${out_packets:-0}" -ge 2 ]]
[[ "${pre_packets:-0}" -ge 2 ]]

ip netns exec "$ns_cmt" env \
  COMMEATUS_IPV6=0 \
  COMMEATUS_UID_RANGE=10000-10000 \
  COMMEATUS_STATE_DIR="$state" \
  sh "$helper" stop

for chain in CMT_TCP_OUT CMT_TCP_PRE CMT_UDP_OUT CMT_UDP_PRE; do
  ! ip netns exec "$ns_cmt" iptables -w -t mangle -S "$chain" >/dev/null 2>&1
done
! ip netns exec "$ns_cmt" ip rule show | grep -q 'lookup 20660'
[[ ! -e "$state/commeatus.pid" ]]

echo "tproxy-udp-netns-e2e: PASS"
