# ADR-0016: Transparent UDP Replies Require Source-Correct Sockets

Status: Accepted

## Context

Linux/Android TPROXY preserves the original UDP destination instead of rewriting it. A transparent UDP ingress therefore receives two pieces of authority from the kernel:

- the client socket address;
- the original destination socket address carried as ancillary metadata.

After native policy/outbound execution returns a datagram, the application must receive that reply as though it came from the original remote destination. Preserving only the source IP is insufficient because UDP source ports are part of the transport identity.

## Decision

Transparent UDP ingress is an ingress adapter, not a routing policy.

Incoming datagrams are converted into the ordinary native `Target` and evaluated through the same `FlowContext -> Policy -> ExecutionPlan -> OutboundRegistry` path as other UDP inbounds.

Replies are emitted through bounded `IP_TRANSPARENT` UDP sockets bound to the exact original source `IP:port`. The implementation does not fake the source with a global listener port and does not silently fall back to DIRECT when a selected proxy datagram provider is unavailable.

Original-destination ancillary decoding uses safe `nix` wrappers. Commeatus daemon code remains `#![forbid(unsafe_code)]`; unsafe system-call decoding stays inside the audited dependency boundary.

## Constraints

- IPv4 and IPv6 original-destination metadata are required; a datagram without it is invalid for this ingress.
- client state, reply sockets, route count, receive bursts, and idle lifetime are bounded.
- one client may select several outbound endpoints over time; readiness tokens therefore come from a listener-wide allocator rather than per-client overlapping ranges.
- the Android Root interception script must bypass the root-owned daemon and install/remove only Commeatus-owned routing/netfilter state.
- TCP and UDP transparent listeners may share the same numeric address/port because they occupy different transport socket namespaces.

## Consequences

The same transparent UDP ingress can execute DIRECT and native proxy datagram providers such as Trojan UDP without protocol-name branches in the listener.

Future QUIC-native providers can attach through the existing datagram provider/readiness boundary without changing TPROXY policy semantics.
