//! Nix daemon handshake protocol.
//!
//! Handshake sequence (from worker-protocol-connection.cc):
//! 1. Client sends WORKER_MAGIC_1 (u64), client version (u64)
//! 2. Server sends WORKER_MAGIC_2 (u64), server version (u64)
//! 3. If negotiated version >= 1.38: exchange feature StringSets
//!    - Client sends its features, server sends its features
//! 4. Post-handshake: obsolete fields (CPU affinity if >= 1.14, reserveSpace if >= 1.11)
//!    then server sends ClientHandshakeInfo

/// Client magic number: "nixc" as u32 LE (sent as u64).
pub const WORKER_MAGIC_1: u64 = 0x6e697863;

/// Server magic number: "dxio" as u32 LE (sent as u64).
pub const WORKER_MAGIC_2: u64 = 0x6478696f;

/// Protocol version as transmitted on the wire.
///
/// Wire format: `(major << 8) | minor`
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u8,
}

impl ProtocolVersion {
    /// Create a new protocol version.
    pub const fn new(major: u16, minor: u8) -> Self {
        Self { major, minor }
    }

    /// Decode from the wire format `(major << 8) | minor`.
    pub fn from_wire(wire: u64) -> Self {
        Self {
            major: ((wire & 0xff00) >> 8) as u16,
            minor: (wire & 0x00ff) as u8,
        }
    }

    /// Encode to the wire format.
    pub fn to_wire(self) -> u64 {
        ((self.major as u64) << 8) | (self.minor as u64)
    }

    /// Whether this version supports feature negotiation (>= 1.38).
    pub fn has_features(self) -> bool {
        self >= Self::new(1, 38)
    }

    /// Whether the post-handshake sends obsolete CPU affinity (>= 1.14).
    pub fn has_cpu_affinity(self) -> bool {
        self >= Self::new(1, 14)
    }

    /// Whether the post-handshake sends obsolete reserveSpace (>= 1.11).
    pub fn has_reserve_space(self) -> bool {
        self >= Self::new(1, 11)
    }

    /// Whether the post-handshake flushes before reading (>= 1.33).
    pub fn has_post_handshake_flush(self) -> bool {
        self >= Self::new(1, 33)
    }
}

impl std::fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_values() {
        // "nixc" as bytes: n=0x6e, i=0x69, x=0x78, c=0x63
        assert_eq!(WORKER_MAGIC_1, 0x6e697863);
        // "dxio" as bytes: d=0x64, x=0x78, i=0x69, o=0x6f
        assert_eq!(WORKER_MAGIC_2, 0x6478696f);
    }

    #[test]
    fn version_roundtrip() {
        let v = ProtocolVersion::new(1, 37);
        let wire = v.to_wire();
        assert_eq!(wire, (1 << 8) | 37);
        assert_eq!(ProtocolVersion::from_wire(wire), v);
    }

    #[test]
    fn version_display() {
        let v = ProtocolVersion::new(1, 37);
        assert_eq!(format!("{v}"), "1.37");
    }

    #[test]
    fn version_features() {
        assert!(ProtocolVersion::new(1, 38).has_features());
        assert!(ProtocolVersion::new(1, 39).has_features());
        assert!(!ProtocolVersion::new(1, 37).has_features());
    }

    #[test]
    fn version_ordering() {
        let v1_37 = ProtocolVersion::new(1, 37);
        let v1_38 = ProtocolVersion::new(1, 38);
        assert!(v1_37 < v1_38);
        assert!(v1_38 > v1_37);
    }
}
