use std::{fmt, net::IpAddr, str::FromStr};

/// Canonical IP network used by native policy matchers.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum IpCidr {
    V4 { network: u32, prefix: u8 },
    V6 { network: u128, prefix: u8 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CidrParseError {
    MissingPrefix,
    InvalidAddress,
    InvalidPrefix,
    PrefixOutOfRange,
}

impl fmt::Display for CidrParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingPrefix => f.write_str("CIDR prefix is required"),
            Self::InvalidAddress => f.write_str("invalid CIDR address"),
            Self::InvalidPrefix => f.write_str("invalid CIDR prefix"),
            Self::PrefixOutOfRange => f.write_str("CIDR prefix is out of range"),
        }
    }
}

impl std::error::Error for CidrParseError {}

impl IpCidr {
    #[must_use]
    pub fn contains(self, address: IpAddr) -> bool {
        match (self, address) {
            (Self::V4 { network, prefix }, IpAddr::V4(address)) => {
                let mask = v4_mask(prefix);
                u32::from(address) & mask == network
            }
            (Self::V6 { network, prefix }, IpAddr::V6(address)) => {
                let mask = v6_mask(prefix);
                u128::from(address) & mask == network
            }
            _ => false,
        }
    }
}

impl FromStr for IpCidr {
    type Err = CidrParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (address, prefix) = value
            .split_once('/')
            .ok_or(CidrParseError::MissingPrefix)?;
        let address: IpAddr = address
            .parse()
            .map_err(|_| CidrParseError::InvalidAddress)?;
        let prefix: u8 = prefix
            .parse()
            .map_err(|_| CidrParseError::InvalidPrefix)?;

        match address {
            IpAddr::V4(address) if prefix <= 32 => {
                let mask = v4_mask(prefix);
                Ok(Self::V4 {
                    network: u32::from(address) & mask,
                    prefix,
                })
            }
            IpAddr::V6(address) if prefix <= 128 => {
                let mask = v6_mask(prefix);
                Ok(Self::V6 {
                    network: u128::from(address) & mask,
                    prefix,
                })
            }
            _ => Err(CidrParseError::PrefixOutOfRange),
        }
    }
}

const fn v4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

const fn v6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_membership_and_normalization() {
        let cidr: IpCidr = "10.42.99.7/16".parse().unwrap();
        assert!(cidr.contains("10.42.0.1".parse().unwrap()));
        assert!(cidr.contains("10.42.255.254".parse().unwrap()));
        assert!(!cidr.contains("10.43.0.1".parse().unwrap()));
    }

    #[test]
    fn zero_and_host_prefixes_work() {
        let any_v4: IpCidr = "0.0.0.0/0".parse().unwrap();
        assert!(any_v4.contains("203.0.113.10".parse().unwrap()));

        let host_v4: IpCidr = "192.0.2.1/32".parse().unwrap();
        assert!(host_v4.contains("192.0.2.1".parse().unwrap()));
        assert!(!host_v4.contains("192.0.2.2".parse().unwrap()));
    }

    #[test]
    fn ipv6_membership_works() {
        let cidr: IpCidr = "2001:db8:abcd::1/48".parse().unwrap();
        assert!(cidr.contains("2001:db8:abcd::42".parse().unwrap()));
        assert!(!cidr.contains("2001:db8:abce::1".parse().unwrap()));

        let host: IpCidr = "2001:db8::1/128".parse().unwrap();
        assert!(host.contains("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn address_families_do_not_cross_match() {
        let cidr: IpCidr = "0.0.0.0/0".parse().unwrap();
        assert!(!cidr.contains("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn invalid_prefixes_are_rejected() {
        assert_eq!(
            "192.0.2.1/33".parse::<IpCidr>(),
            Err(CidrParseError::PrefixOutOfRange)
        );
        assert_eq!(
            "2001:db8::1/129".parse::<IpCidr>(),
            Err(CidrParseError::PrefixOutOfRange)
        );
    }
}
