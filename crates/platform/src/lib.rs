//! Platform integration boundary for Commeatus.
//!
//! The core never assumes that it owns an Android Root environment. Platform
//! features are discovered here and exposed as capabilities so the runtime can
//! degrade from eBPF/TPROXY/TUN without contaminating flow or policy logic.

#![forbid(unsafe_code)]

use std::{fmt, fs, path::Path};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformKind {
    Android,
    Linux,
    Other,
}

impl PlatformKind {
    #[must_use]
    pub const fn current() -> Self {
        if cfg!(target_os = "android") {
            Self::Android
        } else if cfg!(target_os = "linux") {
            Self::Linux
        } else {
            Self::Other
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SupportLevel {
    Available,
    Unavailable,
    Unknown,
}

impl SupportLevel {
    #[must_use]
    pub const fn is_available(self) -> bool {
        matches!(self, Self::Available)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformCapabilities {
    pub platform: PlatformKind,
    pub tun: SupportLevel,
    pub tproxy: SupportLevel,
    pub ebpf: SupportLevel,
    pub btf: SupportLevel,
    pub bpffs: SupportLevel,
}

impl PlatformCapabilities {
    /// Probe only observable, non-destructive kernel/userspace surfaces.
    ///
    /// `Unknown` deliberately means "not proven by this cheap probe", not
    /// "unsupported". In particular, nftables TPROXY may be available without
    /// the legacy iptables target being listed in `/proc/net/ip_tables_targets`.
    #[must_use]
    pub fn probe() -> Self {
        let platform = PlatformKind::current();
        if platform == PlatformKind::Other {
            return Self {
                platform,
                tun: SupportLevel::Unknown,
                tproxy: SupportLevel::Unknown,
                ebpf: SupportLevel::Unknown,
                btf: SupportLevel::Unknown,
                bpffs: SupportLevel::Unknown,
            };
        }

        let tun = if Path::new("/dev/net/tun").exists() {
            SupportLevel::Available
        } else {
            SupportLevel::Unavailable
        };
        let btf = if Path::new("/sys/kernel/btf/vmlinux").exists() {
            SupportLevel::Available
        } else {
            SupportLevel::Unavailable
        };
        let bpffs = if Path::new("/sys/fs/bpf").exists() {
            SupportLevel::Available
        } else {
            SupportLevel::Unavailable
        };
        let ebpf = if btf.is_available()
            || bpffs.is_available()
            || Path::new("/proc/sys/kernel/unprivileged_bpf_disabled").exists()
        {
            SupportLevel::Available
        } else {
            SupportLevel::Unknown
        };
        let tproxy = if file_contains("/proc/net/ip_tables_targets", "TPROXY")
            || file_contains("/proc/modules", "xt_TPROXY")
        {
            SupportLevel::Available
        } else {
            SupportLevel::Unknown
        };

        Self {
            platform,
            tun,
            tproxy,
            ebpf,
            btf,
            bpffs,
        }
    }
}

fn file_contains(path: &str, needle: &str) -> bool {
    fs::read_to_string(path)
        .ok()
        .is_some_and(|content| content.lines().any(|line| line.contains(needle)))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterceptionMode {
    ExplicitProxy,
    Tun,
    Tproxy,
    Ebpf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterceptionRequest {
    pub mode: InterceptionMode,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityError {
    mode: InterceptionMode,
    support: SupportLevel,
}

impl CapabilityError {
    #[must_use]
    pub const fn mode(&self) -> InterceptionMode {
        self.mode
    }

    #[must_use]
    pub const fn support(&self) -> SupportLevel {
        self.support
    }
}

impl fmt::Display for CapabilityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "requested interception mode {:?} has support level {:?}",
            self.mode, self.support
        )
    }
}

impl std::error::Error for CapabilityError {}

pub trait NetworkBackend {
    fn capabilities(&self) -> &PlatformCapabilities;

    fn validate(&self, request: &InterceptionRequest) -> Result<(), CapabilityError> {
        let support = match request.mode {
            InterceptionMode::ExplicitProxy => SupportLevel::Available,
            InterceptionMode::Tun => self.capabilities().tun,
            InterceptionMode::Tproxy => self.capabilities().tproxy,
            InterceptionMode::Ebpf => self.capabilities().ebpf,
        };

        if support == SupportLevel::Available {
            Ok(())
        } else {
            Err(CapabilityError {
                mode: request.mode,
                support,
            })
        }
    }
}

#[derive(Clone, Debug)]
pub struct ProbedBackend {
    capabilities: PlatformCapabilities,
}

impl ProbedBackend {
    #[must_use]
    pub fn current() -> Self {
        Self {
            capabilities: PlatformCapabilities::probe(),
        }
    }

    #[must_use]
    pub const fn from_capabilities(capabilities: PlatformCapabilities) -> Self {
        Self { capabilities }
    }
}

impl NetworkBackend for ProbedBackend {
    fn capabilities(&self) -> &PlatformCapabilities {
        &self.capabilities
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capabilities() -> PlatformCapabilities {
        PlatformCapabilities {
            platform: PlatformKind::Linux,
            tun: SupportLevel::Available,
            tproxy: SupportLevel::Unknown,
            ebpf: SupportLevel::Unavailable,
            btf: SupportLevel::Unavailable,
            bpffs: SupportLevel::Unavailable,
        }
    }

    #[test]
    fn explicit_proxy_is_always_valid() {
        let backend = ProbedBackend::from_capabilities(capabilities());
        assert!(
            backend
                .validate(&InterceptionRequest {
                    mode: InterceptionMode::ExplicitProxy,
                })
                .is_ok()
        );
    }

    #[test]
    fn unknown_is_not_silently_treated_as_available() {
        let backend = ProbedBackend::from_capabilities(capabilities());
        let error = backend
            .validate(&InterceptionRequest {
                mode: InterceptionMode::Tproxy,
            })
            .unwrap_err();
        assert_eq!(error.support(), SupportLevel::Unknown);
    }

    #[test]
    fn current_probe_is_non_destructive() {
        let report = PlatformCapabilities::probe();
        assert_eq!(report.platform, PlatformKind::current());
    }
}
