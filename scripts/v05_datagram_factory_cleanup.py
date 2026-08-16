from pathlib import Path

path = Path("crates/daemon/src/datagram.rs")
text = path.read_text()

old = '''        self.routes
            .get_mut(&endpoint)
            .expect("datagram route was inserted or already existed")
            .execution
            .send(target, payload)
'''
new = '''        let route = self.routes.get_mut(&endpoint).ok_or_else(|| {
            io::Error::other("datagram route disappeared after successful insertion")
        })?;
        route.execution.send(target, payload)
'''
if text.count(old) != 1:
    raise SystemExit("unexpected DatagramRouteSet post-insert lookup")
text = text.replace(old, new, 1)

marker = '''        assert!(!routes.owns_token(Token(9)));
    }
}'''
addition = '''        assert!(!routes.owns_token(Token(9)));
    }

    #[test]
    fn route_set_rejects_unbounded_endpoint_growth() {
        let poll = mio::Poll::new().unwrap();
        let mut routes = DatagramRouteSet::new(Token(32));
        let target = Target::new(DestinationHost::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 53).unwrap();

        for index in 0..MAX_DATAGRAM_ROUTES {
            let endpoint = Endpoint::Proxy(EndpointId::new(format!("proxy-{index}")).unwrap());
            routes
                .send_with(endpoint, &target, b"x", poll.registry(), |_| {
                    Ok(Box::new(FakeExecution {
                        sends: Arc::new(AtomicUsize::new(0)),
                    }))
                })
                .unwrap();
        }
        assert_eq!(routes.route_count(), MAX_DATAGRAM_ROUTES);

        let overflow = Endpoint::Proxy(EndpointId::new("proxy-overflow").unwrap());
        let error = routes
            .send_with(overflow, &target, b"x", poll.registry(), |_| {
                Ok(Box::new(FakeExecution {
                    sends: Arc::new(AtomicUsize::new(0)),
                }))
            })
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::QuotaExceeded);
        assert_eq!(routes.route_count(), MAX_DATAGRAM_ROUTES);
    }
}'''
if text.count(marker) != 1:
    raise SystemExit("unexpected end of datagram route-set tests")
text = text.replace(marker, addition, 1)

if '.expect("datagram route was inserted or already existed")' in text:
    raise SystemExit("production datagram route expect remains")

path.write_text(text)
