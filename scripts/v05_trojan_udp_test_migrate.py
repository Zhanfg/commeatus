from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected one match in {path}, found {count}: {old!r}")
    p.write_text(text.replace(old, new, 1))


replace_once(
    "crates/daemon/src/protocol.rs",
    '        assert_eq!(trojan("secret").unwrap().name(), "trojan");',
    '        assert_eq!(\n            trojan_with_verifier(TrojanVerifier::new("secret").unwrap()).name(),\n            "trojan"\n        );',
)
replace_once(
    "crates/daemon/src/protocol.rs",
    '        assert!(trojan("secret").unwrap().capabilities().requires_tls);',
    '        assert!(\n            trojan_with_verifier(TrojanVerifier::new("secret").unwrap())\n                .capabilities()\n                .requires_tls\n        );',
)
replace_once(
    "crates/daemon/src/outbound.rs",
    '            protocol: protocol::trojan("secret").unwrap(),',
    '            protocol: protocol::trojan_with_verifier(\n                crate::trojan::TrojanVerifier::new("secret").unwrap(),\n            ),',
)
replace_once(
    "crates/daemon/src/trojan_outbound_e2e.rs",
    '            protocol: protocol::trojan(PASSWORD).unwrap(),',
    '            protocol: protocol::trojan_with_verifier(\n                crate::trojan::TrojanVerifier::new(PASSWORD).unwrap(),\n            ),',
)
replace_once(
    "crates/daemon/src/config.rs",
    "    fn trojan_tls_endpoint_compiles_as_encrypted_tcp_only() {",
    "    fn trojan_tls_endpoint_compiles_with_stream_and_datagram_capability() {",
)
replace_once(
    "crates/daemon/src/config.rs",
    '''        assert!(capabilities.supports_tcp());
        assert!(!capabilities.supports_udp());
        assert!(capabilities.encrypted_transport());
    }

    #[test]
    fn trojan_plain_tcp_is_rejected_by_candidate_parser() {''',
    '''        assert!(capabilities.supports_tcp());
        assert!(capabilities.supports_udp());
        assert!(capabilities.encrypted_transport());
    }

    #[test]
    fn trojan_plain_tcp_is_rejected_by_candidate_parser() {''',
)

remaining = []
for path in Path("crates/daemon/src").glob("*.rs"):
    text = path.read_text()
    if "protocol::trojan(" in text or "trojan(\"secret\")" in text:
        remaining.append(str(path))
if remaining:
    raise SystemExit("obsolete raw-password Trojan factory remains in: " + ", ".join(remaining))
