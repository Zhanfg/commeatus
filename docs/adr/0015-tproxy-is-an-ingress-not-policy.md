# ADR-0015: TPROXY Is an Ingress, Not Policy

- Status: Accepted
- Date: 2026-08-16

## Context

Commeatus 0.5 can proxy real TCP and UDP when an application explicitly speaks SOCKS5/HTTP to the daemon, but Android Root cannot yet feed ordinary application connections into that runtime. A usable Root-first build needs transparent interception without moving routing semantics into shell/iptables code.

Linux/Android TPROXY preserves the packet destination and delivers it to a socket that opted into `IP_TRANSPARENT` / `IPV6_TRANSPARENT`. That makes it a suitable ingress mechanism: the original destination can be converted into the same native `Target` that explicit inbounds already feed into `FlowContext -> PolicyEngine -> ExecutionPlan`.

## Decision

TPROXY is an **ingress/platform mechanism only**.

The transparent listener may:

1. create a platform socket with the transparent socket option;
2. recover the kernel-preserved original destination;
3. convert that destination to native `Target`;
4. hand the flow to the ordinary policy and outbound execution path.

It must not contain protocol-name routing, hard-coded proxy selection, hidden DNS resolution, or DIRECT fallback logic.

The first implementation slice is TCP only. UDP transparent ingress is a separate slice because correct UDP reply-source/original-destination handling has different socket semantics and must not be faked by a TCP-shaped abstraction.

## Android Root lifecycle

The initial deployment helper owns only Commeatus-specific policy-routing entries and named netfilter chains. It:

- selects third-party Android app UIDs by default;
- leaves the root-owned daemon outside interception, preventing recursive interception without yet changing every outbound socket to carry `SO_MARK`;
- installs PREROUTING before enabling OUTPUT marking;
- rolls back only its own rules on failure/stop;
- refuses to reuse a non-empty chosen policy-routing table;
- keeps IPv6 enabled by default and fails explicitly if the requested IPv6 TPROXY surface is unavailable;
- does not touch UDP in the TCP preview.

A later supervisor can replace the shell lifecycle without changing flow/policy semantics.

## Consequences

### Positive

- real Android application TCP can enter the native runtime without a VPN/TUN userspace packet stack;
- DIRECT and Trojan TCP share the same policy/outbound implementation as explicit inbounds;
- no TPROXY-specific route decisions leak into the core;
- the listener uses safe `socket2` APIs, keeping daemon code free of new unsafe blocks;
- UDP can be implemented correctly rather than hidden behind a misleading partial abstraction.

### Negative / deferred

- this slice is not yet full-device proxying: UDP remains outside interception;
- daemon-owned outbound sockets rely on the preview process running as uid 0 while app interception defaults to uid 10000+; future privilege dropping requires explicit socket marks or a dedicated bypass identity;
- local Android netfilter/policy-routing availability is device/kernel dependent and must be probed before activation;
- process supervision is shell-based until the Root supervisor/package lifecycle exists.
