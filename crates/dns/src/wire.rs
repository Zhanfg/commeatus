use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ops::Range,
    time::Duration,
};

use super::{DnsAnswer, DnsError, DnsErrorKind, DnsQuery, normalize_name};

const DNS_HEADER_BYTES: usize = 12;
const MAX_DNS_MESSAGE_BYTES: usize = u16::MAX as usize;
const MAX_DNS_ANSWER_RECORDS: usize = 512;
const MAX_DNS_NAME_POINTER_HOPS: usize = 32;
const MAX_DNS_ALIAS_HOPS: usize = 16;

const FLAG_QR: u16 = 0x8000;
const FLAG_TC: u16 = 0x0200;
const FLAG_RD: u16 = 0x0100;
const RCODE_MASK: u16 = 0x000f;

const CLASS_IN: u16 = 1;
const TYPE_A: u16 = 1;
const TYPE_CNAME: u16 = 5;
const TYPE_AAAA: u16 = 28;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AddressRecordType {
    A,
    Aaaa,
}

impl AddressRecordType {
    const fn code(self) -> u16 {
        match self {
            Self::A => TYPE_A,
            Self::Aaaa => TYPE_AAAA,
        }
    }
}

#[derive(Debug)]
struct ResourceRecord {
    owner: String,
    rr_type: u16,
    class: u16,
    ttl: Duration,
    rdata: Range<usize>,
}

pub(crate) fn encode_address_query(
    id: u16,
    query: &DnsQuery,
    record_type: AddressRecordType,
) -> Result<Vec<u8>, DnsError> {
    let mut message = Vec::with_capacity(DNS_HEADER_BYTES + query.name().len() + 6);
    push_u16(&mut message, id);
    push_u16(&mut message, FLAG_RD);
    push_u16(&mut message, 1); // QDCOUNT
    push_u16(&mut message, 0); // ANCOUNT
    push_u16(&mut message, 0); // NSCOUNT
    push_u16(&mut message, 0); // ARCOUNT
    encode_name(query.name(), &mut message)?;
    push_u16(&mut message, record_type.code());
    push_u16(&mut message, CLASS_IN);
    Ok(message)
}

pub(crate) fn parse_address_response(
    expected_id: u16,
    query: &DnsQuery,
    record_type: AddressRecordType,
    message: &[u8],
) -> Result<DnsAnswer, DnsError> {
    if message.len() < DNS_HEADER_BYTES || message.len() > MAX_DNS_MESSAGE_BYTES {
        return Err(invalid_response(
            "DNS response size is outside the supported bounds",
        ));
    }

    let id = read_u16(message, 0)?;
    if id != expected_id {
        return Err(invalid_response(
            "DNS response transaction ID does not match query",
        ));
    }

    let flags = read_u16(message, 2)?;
    if flags & FLAG_QR == 0 {
        return Err(invalid_response(
            "DNS response is missing the response flag",
        ));
    }
    if flags & FLAG_TC != 0 {
        return Err(DnsError::new(
            DnsErrorKind::ResolverFailure,
            "DNS response is truncated",
        ));
    }
    match flags & RCODE_MASK {
        0 => {}
        3 => {
            return Err(DnsError::new(
                DnsErrorKind::NoRecords,
                format!("DNS upstream reported NXDOMAIN for {}", query.name()),
            ));
        }
        code => {
            return Err(DnsError::new(
                DnsErrorKind::ResolverFailure,
                format!(
                    "DNS upstream returned response code {code} for {}",
                    query.name()
                ),
            ));
        }
    }

    let question_count = usize::from(read_u16(message, 4)?);
    let answer_count = usize::from(read_u16(message, 6)?);
    if question_count != 1 {
        return Err(invalid_response(
            "DNS response must contain exactly one question",
        ));
    }
    if answer_count > MAX_DNS_ANSWER_RECORDS {
        return Err(invalid_response(
            "DNS response answer count exceeds the configured bound",
        ));
    }

    let mut offset = DNS_HEADER_BYTES;
    let question_name = decode_name(message, &mut offset)?;
    if question_name != query.name() {
        return Err(invalid_response(
            "DNS response question name does not match query",
        ));
    }
    let question_type = take_u16(message, &mut offset)?;
    let question_class = take_u16(message, &mut offset)?;
    if question_type != record_type.code() || question_class != CLASS_IN {
        return Err(invalid_response(
            "DNS response question type/class does not match query",
        ));
    }

    let mut records = Vec::with_capacity(answer_count);
    for _ in 0..answer_count {
        let owner = decode_name(message, &mut offset)?;
        let rr_type = take_u16(message, &mut offset)?;
        let class = take_u16(message, &mut offset)?;
        let ttl = Duration::from_secs(u64::from(take_u32(message, &mut offset)?));
        let rdlength = usize::from(take_u16(message, &mut offset)?);
        let end = offset
            .checked_add(rdlength)
            .filter(|end| *end <= message.len())
            .ok_or_else(|| invalid_response("DNS resource record data is truncated"))?;
        records.push(ResourceRecord {
            owner,
            rr_type,
            class,
            ttl,
            rdata: offset..end,
        });
        offset = end;
    }

    resolve_addresses_through_aliases(query, record_type, message, &records)
}

fn resolve_addresses_through_aliases(
    query: &DnsQuery,
    record_type: AddressRecordType,
    message: &[u8],
    records: &[ResourceRecord],
) -> Result<DnsAnswer, DnsError> {
    let mut accepted_names = HashSet::new();
    accepted_names.insert(query.name().to_owned());
    let mut chain_ttl: Option<Duration> = None;

    for _ in 0..MAX_DNS_ALIAS_HOPS {
        let mut changed = false;
        for record in records {
            if record.class != CLASS_IN
                || record.rr_type != TYPE_CNAME
                || !accepted_names.contains(&record.owner)
            {
                continue;
            }
            let mut offset = record.rdata.start;
            let target = decode_name(message, &mut offset)?;
            if offset != record.rdata.end {
                return Err(invalid_response(
                    "DNS CNAME record has trailing or malformed data",
                ));
            }
            chain_ttl = Some(min_ttl(chain_ttl, record.ttl));
            if accepted_names.insert(target) {
                changed = true;
            }
        }
        if !changed {
            break;
        }
        if accepted_names.len() > MAX_DNS_ALIAS_HOPS + 1 {
            return Err(invalid_response(
                "DNS CNAME chain exceeds the configured bound",
            ));
        }
    }

    let mut addresses = Vec::new();
    let mut ttl = chain_ttl;
    for record in records {
        if record.class != CLASS_IN
            || record.rr_type != record_type.code()
            || !accepted_names.contains(&record.owner)
        {
            continue;
        }
        let address = match record_type {
            AddressRecordType::A => {
                if record.rdata.len() != 4 {
                    return Err(invalid_response("DNS A record has invalid RDLENGTH"));
                }
                IpAddr::V4(Ipv4Addr::new(
                    message[record.rdata.start],
                    message[record.rdata.start + 1],
                    message[record.rdata.start + 2],
                    message[record.rdata.start + 3],
                ))
            }
            AddressRecordType::Aaaa => {
                if record.rdata.len() != 16 {
                    return Err(invalid_response("DNS AAAA record has invalid RDLENGTH"));
                }
                let octets: [u8; 16] = message[record.rdata.clone()]
                    .try_into()
                    .map_err(|_| invalid_response("DNS AAAA record length conversion failed"))?;
                IpAddr::V6(Ipv6Addr::from(octets))
            }
        };
        if !addresses.contains(&address) {
            addresses.push(address);
        }
        ttl = Some(min_ttl(ttl, record.ttl));
    }

    DnsAnswer::new(addresses, ttl)
}

fn min_ttl(current: Option<Duration>, candidate: Duration) -> Duration {
    current.map_or(candidate, |current| current.min(candidate))
}

fn encode_name(name: &str, output: &mut Vec<u8>) -> Result<(), DnsError> {
    for label in name.split('.') {
        let length = u8::try_from(label.len())
            .map_err(|_| DnsError::new(DnsErrorKind::InvalidName, "DNS label is too long"))?;
        if length == 0 || length > 63 {
            return Err(DnsError::new(
                DnsErrorKind::InvalidName,
                "invalid DNS label length",
            ));
        }
        output.push(length);
        output.extend_from_slice(label.as_bytes());
    }
    output.push(0);
    if output.len() > MAX_DNS_MESSAGE_BYTES {
        return Err(DnsError::new(
            DnsErrorKind::InvalidConfiguration,
            "encoded DNS query exceeds maximum message size",
        ));
    }
    Ok(())
}

fn decode_name(message: &[u8], offset: &mut usize) -> Result<String, DnsError> {
    let mut cursor = *offset;
    let mut resume = None;
    let mut labels = Vec::new();
    let mut hops = 0_usize;
    let mut decoded_bytes = 0_usize;

    loop {
        let length = *message
            .get(cursor)
            .ok_or_else(|| invalid_response("DNS name is truncated"))?;
        if length & 0xc0 == 0xc0 {
            let second = *message
                .get(cursor + 1)
                .ok_or_else(|| invalid_response("DNS compression pointer is truncated"))?;
            let pointer = (usize::from(length & 0x3f) << 8) | usize::from(second);
            if pointer >= message.len() {
                return Err(invalid_response("DNS compression pointer is out of bounds"));
            }
            if pointer >= cursor {
                return Err(invalid_response(
                    "DNS compression pointer does not point backward",
                ));
            }
            if resume.is_none() {
                resume = Some(cursor + 2);
            }
            cursor = pointer;
            hops += 1;
            if hops > MAX_DNS_NAME_POINTER_HOPS {
                return Err(invalid_response(
                    "DNS compression pointer chain exceeds the bound",
                ));
            }
            continue;
        }
        if length & 0xc0 != 0 {
            return Err(invalid_response(
                "DNS name uses an unsupported label encoding",
            ));
        }
        cursor += 1;
        if length == 0 {
            *offset = resume.unwrap_or(cursor);
            break;
        }
        let length = usize::from(length);
        if length > 63 {
            return Err(invalid_response("DNS label exceeds 63 bytes"));
        }
        let end = cursor
            .checked_add(length)
            .filter(|end| *end <= message.len())
            .ok_or_else(|| invalid_response("DNS label is truncated"))?;
        let label = std::str::from_utf8(&message[cursor..end])
            .map_err(|_| invalid_response("DNS response name is not UTF-8/ASCII"))?;
        if !label.is_ascii() {
            return Err(invalid_response("DNS response name is not ASCII"));
        }
        decoded_bytes = decoded_bytes
            .checked_add(length + usize::from(!labels.is_empty()))
            .ok_or_else(|| invalid_response("DNS decoded name length overflow"))?;
        if decoded_bytes > 253 {
            return Err(invalid_response("DNS decoded name exceeds 253 bytes"));
        }
        labels.push(label.to_ascii_lowercase());
        cursor = end;
    }

    if labels.is_empty() {
        return Err(invalid_response("DNS response contains an empty root name"));
    }
    normalize_name(&labels.join("."))
        .map_err(|_| invalid_response("DNS response contains an invalid hostname"))
}

fn read_u16(message: &[u8], offset: usize) -> Result<u16, DnsError> {
    let bytes = message
        .get(offset..offset + 2)
        .ok_or_else(|| invalid_response("DNS message is truncated"))?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn take_u16(message: &[u8], offset: &mut usize) -> Result<u16, DnsError> {
    let value = read_u16(message, *offset)?;
    *offset += 2;
    Ok(value)
}

fn take_u32(message: &[u8], offset: &mut usize) -> Result<u32, DnsError> {
    let bytes = message
        .get(*offset..*offset + 4)
        .ok_or_else(|| invalid_response("DNS message is truncated"))?;
    *offset += 4;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn push_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn invalid_response(message: impl Into<String>) -> DnsError {
    DnsError::new(DnsErrorKind::InvalidResponse, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn question(name: &str, record_type: AddressRecordType) -> Vec<u8> {
        let query = DnsQuery::new(name).unwrap();
        let encoded = encode_address_query(0x1234, &query, record_type).unwrap();
        encoded[DNS_HEADER_BYTES..].to_vec()
    }

    fn response_header(id: u16, answer_count: u16, rcode: u16) -> Vec<u8> {
        let mut response = Vec::new();
        push_u16(&mut response, id);
        push_u16(&mut response, FLAG_QR | FLAG_RD | (rcode & RCODE_MASK));
        push_u16(&mut response, 1);
        push_u16(&mut response, answer_count);
        push_u16(&mut response, 0);
        push_u16(&mut response, 0);
        response
    }

    fn push_pointer_name(output: &mut Vec<u8>, offset: u16) {
        output.push(0xc0 | ((offset >> 8) as u8 & 0x3f));
        output.push(offset as u8);
    }

    fn push_rr_header(output: &mut Vec<u8>, rr_type: u16, ttl: u32, rdlength: u16) {
        push_u16(output, rr_type);
        push_u16(output, CLASS_IN);
        output.extend_from_slice(&ttl.to_be_bytes());
        push_u16(output, rdlength);
    }

    #[test]
    fn query_encoding_preserves_id_name_and_family() {
        let query = DnsQuery::new("Api.Example.").unwrap();
        let message = encode_address_query(0xbeef, &query, AddressRecordType::Aaaa).unwrap();
        assert_eq!(&message[..2], &[0xbe, 0xef]);
        assert_eq!(read_u16(&message, 2).unwrap(), FLAG_RD);
        assert_eq!(read_u16(&message, 4).unwrap(), 1);
        assert_eq!(&message[12..25], b"\x03api\x07example\x00");
        assert_eq!(read_u16(&message, 25).unwrap(), TYPE_AAAA);
        assert_eq!(read_u16(&message, 27).unwrap(), CLASS_IN);
    }

    #[test]
    fn compressed_a_response_preserves_ttl() {
        let query = DnsQuery::new("a.example").unwrap();
        let mut response = response_header(0x1234, 1, 0);
        response.extend_from_slice(&question("a.example", AddressRecordType::A));
        push_pointer_name(&mut response, 12);
        push_rr_header(&mut response, TYPE_A, 90, 4);
        response.extend_from_slice(&[203, 0, 113, 9]);

        let answer =
            parse_address_response(0x1234, &query, AddressRecordType::A, &response).unwrap();
        assert_eq!(
            answer.addresses(),
            &[IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))]
        );
        assert_eq!(answer.ttl(), Some(Duration::from_secs(90)));
    }

    #[test]
    fn aaaa_response_is_supported() {
        let query = DnsQuery::new("v6.example").unwrap();
        let mut response = response_header(0x1234, 1, 0);
        response.extend_from_slice(&question("v6.example", AddressRecordType::Aaaa));
        push_pointer_name(&mut response, 12);
        push_rr_header(&mut response, TYPE_AAAA, 120, 16);
        response.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());

        let answer =
            parse_address_response(0x1234, &query, AddressRecordType::Aaaa, &response).unwrap();
        assert_eq!(answer.addresses(), &[IpAddr::V6(Ipv6Addr::LOCALHOST)]);
        assert_eq!(answer.ttl(), Some(Duration::from_secs(120)));
    }

    #[test]
    fn cname_chain_bounds_effective_ttl() {
        let query = DnsQuery::new("alias.example").unwrap();
        let mut response = response_header(0x1234, 2, 0);
        response.extend_from_slice(&question("alias.example", AddressRecordType::A));

        push_pointer_name(&mut response, 12);
        let cname_target = b"\x06target\x07example\x00";
        push_rr_header(&mut response, TYPE_CNAME, 30, cname_target.len() as u16);
        response.extend_from_slice(cname_target);

        let owner_offset = response.len();
        response.extend_from_slice(cname_target);
        push_rr_header(&mut response, TYPE_A, 90, 4);
        response.extend_from_slice(&[192, 0, 2, 44]);
        assert!(owner_offset < 0x4000);

        let answer =
            parse_address_response(0x1234, &query, AddressRecordType::A, &response).unwrap();
        assert_eq!(
            answer.addresses(),
            &[IpAddr::V4(Ipv4Addr::new(192, 0, 2, 44))]
        );
        assert_eq!(answer.ttl(), Some(Duration::from_secs(30)));
    }

    #[test]
    fn unrelated_address_record_is_not_accepted() {
        let query = DnsQuery::new("wanted.example").unwrap();
        let mut response = response_header(0x1234, 1, 0);
        response.extend_from_slice(&question("wanted.example", AddressRecordType::A));
        response.extend_from_slice(b"\x09unrelated\x07example\x00");
        push_rr_header(&mut response, TYPE_A, 60, 4);
        response.extend_from_slice(&[192, 0, 2, 1]);

        let error =
            parse_address_response(0x1234, &query, AddressRecordType::A, &response).unwrap_err();
        assert_eq!(error.kind(), DnsErrorKind::NoRecords);
    }

    #[test]
    fn zero_ttl_is_preserved_for_cache_policy() {
        let query = DnsQuery::new("volatile.example").unwrap();
        let mut response = response_header(0x1234, 1, 0);
        response.extend_from_slice(&question("volatile.example", AddressRecordType::A));
        push_pointer_name(&mut response, 12);
        push_rr_header(&mut response, TYPE_A, 0, 4);
        response.extend_from_slice(&[198, 51, 100, 8]);

        let answer =
            parse_address_response(0x1234, &query, AddressRecordType::A, &response).unwrap();
        assert_eq!(answer.ttl(), Some(Duration::ZERO));
    }

    #[test]
    fn nxdomain_is_no_records_not_transport_failure() {
        let query = DnsQuery::new("missing.example").unwrap();
        let mut response = response_header(0x1234, 0, 3);
        response.extend_from_slice(&question("missing.example", AddressRecordType::A));
        let error =
            parse_address_response(0x1234, &query, AddressRecordType::A, &response).unwrap_err();
        assert_eq!(error.kind(), DnsErrorKind::NoRecords);
    }

    #[test]
    fn transaction_id_mismatch_is_invalid_response() {
        let query = DnsQuery::new("id.example").unwrap();
        let mut response = response_header(0x9999, 0, 0);
        response.extend_from_slice(&question("id.example", AddressRecordType::A));
        let error =
            parse_address_response(0x1234, &query, AddressRecordType::A, &response).unwrap_err();
        assert_eq!(error.kind(), DnsErrorKind::InvalidResponse);
    }

    #[test]
    fn compression_pointer_loop_is_rejected() {
        let query = DnsQuery::new("loop.example").unwrap();
        let mut response = response_header(0x1234, 1, 0);
        response.extend_from_slice(&question("loop.example", AddressRecordType::A));
        let owner_offset = response.len();
        push_pointer_name(&mut response, owner_offset as u16);
        push_rr_header(&mut response, TYPE_A, 60, 4);
        response.extend_from_slice(&[127, 0, 0, 1]);
        let error =
            parse_address_response(0x1234, &query, AddressRecordType::A, &response).unwrap_err();
        assert_eq!(error.kind(), DnsErrorKind::InvalidResponse);
    }
}
