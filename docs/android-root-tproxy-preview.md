# Android Root transparent preview (v0.6 development)

This preview carries ordinary Android application TCP **and UDP** through the native Commeatus runtime without a userspace TUN packet stack.

```text
selected app TCP/UDP
  -> OUTPUT mark
  -> policy route to loopback
  -> protocol-specific TPROXY
  -> tproxy-tcp / tproxy-udp listener
  -> native Flow/Policy
  -> DIRECT or native proxy endpoint (Trojan supports both TCP and UDP)
```

For UDP, the listener receives the kernel original destination through `ORIGDSTADDR` ancillary metadata. Every local UDP client address owns an independent bounded `DatagramRouteSet`; DIRECT and Trojan UDP therefore reuse the same provider boundary as SOCKS5 UDP instead of a second routing implementation.

Replies are sent from a bounded cache of transparent sockets bound to the real remote source IP **and port**. This is necessary because packet-info can choose a source IP but cannot change the UDP source port. CI proves the client observes the exact remote `IP:port` through the full TPROXY namespace path.

## Run

Copy `examples/android-root-tproxy.conf`, replace the TEST-NET endpoint/password, then from a root shell:

```sh
chmod 755 ./commeatus ./scripts/android-root-tproxy.sh
./commeatus check --config ./android-root.conf
./scripts/android-root-tproxy.sh start ./android-root.conf ./commeatus
./scripts/android-root-tproxy.sh status
```

Stop and restore networking:

```sh
./scripts/android-root-tproxy.sh stop
```

The default interception UID range is `10000-999999`. Narrow it while testing with `COMMEATUS_UID_RANGE=<uid>-<uid>`. IPv6 remains enabled by default; disabling it requires explicit `COMMEATUS_IPV6=0`.

## Current alpha constraints

- the daemon still runs as root in this preview; privilege separation is a later supervisor slice;
- transparent UDP state is keyed by local client socket address and expires after 120 seconds idle;
- at most 512 transparent UDP clients, 32 outbound endpoints per client, 256 remote peers per DIRECT association, and 256 cached reply-source sockets are retained;
- root lifecycle is shell-based until the installable module/supervisor package lands;
- QUIC is carried as ordinary UDP but Commeatus does not inspect QUIC semantics;
- no automatic boot enablement is shipped by this source slice.
