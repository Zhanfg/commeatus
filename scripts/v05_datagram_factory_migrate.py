from pathlib import Path

path = Path("crates/daemon/src/socks5.rs")
text = path.read_text()


def replace_once(old: str, new: str) -> None:
    global text
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected one match, found {count}: {old[:120]!r}")
    text = text.replace(old, new, 1)


replace_once(
    "    datagram::{DatagramAssociation, DirectDatagramAssociation},",
    "    datagram::DatagramRouteSet,",
)
replace_once(
    "const UDP_DIRECT_IPV4_TOKEN: Token = Token(2);\nconst UDP_DIRECT_IPV6_TOKEN: Token = Token(3);",
    "const UDP_OUTBOUND_FIRST_TOKEN: Token = Token(2);",
)
replace_once(
    '''    let mut control = MioTcpStream::from_std(control);
    let mut relay = MioUdpSocket::from_std(relay);
    let mut direct = DirectDatagramAssociation::new(Arc::clone(&dns))?;
    let mut poll = Poll::new()?;
    poll.registry()
        .register(&mut control, UDP_CONTROL_TOKEN, Interest::READABLE)?;
    poll.registry()
        .register(&mut relay, UDP_CLIENT_TOKEN, Interest::READABLE)?;
    direct.register_readiness(
        poll.registry(),
        UDP_DIRECT_IPV4_TOKEN,
        UDP_DIRECT_IPV6_TOKEN,
    )?;
''',
    '''    let mut control = MioTcpStream::from_std(control);
    let mut relay = MioUdpSocket::from_std(relay);
    let mut poll = Poll::new()?;
    poll.registry()
        .register(&mut control, UDP_CONTROL_TOKEN, Interest::READABLE)?;
    poll.registry()
        .register(&mut relay, UDP_CLIENT_TOKEN, Interest::READABLE)?;
    let mut routes = DatagramRouteSet::new(UDP_OUTBOUND_FIRST_TOKEN);
''',
)
replace_once(
    '''        let direct_readable = events.iter().any(|event| {
            matches!(event.token(), UDP_DIRECT_IPV4_TOKEN | UDP_DIRECT_IPV6_TOKEN)
                && event.is_readable()
        });
''',
    '''        let outbound_readable = events
            .iter()
            .filter(|event| event.is_readable() && routes.owns_token(event.token()))
            .map(|event| event.token())
            .collect::<Vec<_>>();
''',
)
replace_once(
    '''                        if handle_udp_client_packet(
                            &mut direct,
                            &runtime,
                            &outbounds,
                            &client_packet[..length],
                        ) {''',
    '''                        if handle_udp_client_packet(
                            &mut routes,
                            poll.registry(),
                            &runtime,
                            &dns,
                            &outbounds,
                            &client_packet[..length],
                        ) {''',
)
replace_once(
    '''        if direct_readable {
            for _ in 0..MAX_UDP_EVENT_BURST {
                let Some(received) = direct.receive(&mut remote_packet)? else {
                    break;
                };
                let Some(client) = client_address else {
                    continue;
                };
                let response =
                    encode_udp_response(&received.source, &remote_packet[..received.length])?;
                if send_or_queue_client_reply(&relay, &mut pending_replies, response, client) {
                    last_activity = Instant::now();
                }
            }
        }
''',
    '''        for token in outbound_readable {
            for _ in 0..MAX_UDP_EVENT_BURST {
                let Some(received) = routes.receive_ready(token, &mut remote_packet)? else {
                    break;
                };
                let Some(client) = client_address else {
                    continue;
                };
                let response =
                    encode_udp_response(&received.source, &remote_packet[..received.length])?;
                if send_or_queue_client_reply(&relay, &mut pending_replies, response, client) {
                    last_activity = Instant::now();
                }
            }
        }
''',
)
replace_once(
    '''fn handle_udp_client_packet(
    association: &mut dyn DatagramAssociation,
    runtime: &Runtime,
    outbounds: &OutboundRegistry,
    packet: &[u8],
) -> bool {
    let Ok((target, payload)) = parse_udp_request(packet) else {
        return false;
    };

    let endpoint = match proxy::plan_action(runtime, &target, TransportProtocol::Udp) {
        ExecutionAction::Reject { .. } => return false,
        ExecutionAction::Route { endpoint } => endpoint,
    };

    if !outbounds
        .capabilities(&endpoint)
        .is_some_and(EndpointCapabilities::supports_udp)
    {
        return false;
    }

    // A proxy route must never degrade to DIRECT just because no proxy
    // datagram executor exists yet.
    if !matches!(endpoint, Endpoint::Direct) {
        return false;
    }

    association.send(&target, payload).is_ok()
}
''',
    '''fn handle_udp_client_packet(
    routes: &mut DatagramRouteSet,
    registry: &mio::Registry,
    runtime: &Runtime,
    dns: &Arc<DnsEngine>,
    outbounds: &OutboundRegistry,
    packet: &[u8],
) -> bool {
    let Ok((target, payload)) = parse_udp_request(packet) else {
        return false;
    };

    let endpoint = match proxy::plan_action(runtime, &target, TransportProtocol::Udp) {
        ExecutionAction::Reject { .. } => return false,
        ExecutionAction::Route { endpoint } => endpoint,
    };

    if !outbounds
        .capabilities(&endpoint)
        .is_some_and(EndpointCapabilities::supports_udp)
    {
        return false;
    }

    routes
        .send_with(endpoint, &target, payload, registry, |endpoint| {
            outbounds.open_datagram(endpoint, Arc::clone(dns))
        })
        .is_ok()
}
''',
)

for forbidden in (
    "DirectDatagramAssociation",
    "UDP_DIRECT_IPV4_TOKEN",
    "UDP_DIRECT_IPV6_TOKEN",
    "matches!(endpoint, Endpoint::Direct)",
):
    if forbidden in text:
        raise SystemExit(f"SOCKS5 still owns concrete datagram routing: {forbidden}")

if "outbounds.open_datagram" not in text or "DatagramRouteSet" not in text:
    raise SystemExit("SOCKS5 migration did not route through outbound datagram factory")

path.write_text(text)
