//! CBOR tag assignments for AgentBridge types (BC v1.1.0 §8.1, RFC 8949).
//!
//! Tags 40001-40005 are assigned to AgentBridge-specific types.
//! Tags 40006-40099 are reserved for future use.

// Re-export tag constants from aim module for convenience
pub use crate::aim::{
    TAG_DURATION, TAG_IDENTIFIER, TAG_INSTANT, TAG_REFERENCE, TAG_WALLCLOCK_INSTANT,
};

/// Reserved tag range start for AgentBridge (RFC 8949 §2).
pub const TAG_AGENTBRIDGE_START: u64 = 40001;
/// Reserved tag range end for AgentBridge.
pub const TAG_AGENTBRIDGE_END: u64 = 40099;

/// Maximum CBOR nesting depth (BC v1.1.0 §8.5 — decoder limit).
pub const MAX_NESTING_DEPTH: usize = 16;

/// Maximum CBOR array/map length (BC v1.1.0 §8.5 — decoder limit).
pub const MAX_ARRAY_LENGTH: usize = 1_048_576; // 2^20

/// Check if a tag is in the AgentBridge reserved range.
pub fn is_agentbridge_tag(tag: u64) -> bool {
    tag >= TAG_AGENTBRIDGE_START && tag <= TAG_AGENTBRIDGE_END
}

/// Check if a tag is known (in the allowlist).
pub fn is_known_tag(tag: u64) -> bool {
    matches!(
        tag,
        TAG_IDENTIFIER | TAG_REFERENCE | TAG_INSTANT | TAG_DURATION | TAG_WALLCLOCK_INSTANT
    )
}

/// Reject unknown tags > 40099 (BC v1.1.0 §8.5 — tag handler allowlist).
pub fn validate_tag(tag: u64) -> bool {
    if tag < TAG_AGENTBRIDGE_START {
        return true; // Standard CBOR tags, not our concern
    }
    if is_known_tag(tag) {
        return true;
    }
    // Unknown AgentBridge tags > 40099 are rejected
    if tag > TAG_AGENTBRIDGE_END {
        return false;
    }
    // Unknown but within reserved range (40006-40099) — rejected per BC §8.5
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tag_constants() {
        assert_eq!(TAG_IDENTIFIER, 40001);
        assert_eq!(TAG_REFERENCE, 40002);
        assert_eq!(TAG_INSTANT, 40003);
        assert_eq!(TAG_DURATION, 40004);
        assert_eq!(TAG_WALLCLOCK_INSTANT, 40005);
    }

    #[test]
    fn test_is_agentbridge_tag() {
        assert!(is_agentbridge_tag(40001));
        assert!(is_agentbridge_tag(40050));
        assert!(is_agentbridge_tag(40099));
        assert!(!is_agentbridge_tag(40000));
        assert!(!is_agentbridge_tag(40100));
        assert!(!is_agentbridge_tag(0));
    }

    #[test]
    fn test_is_known_tag() {
        assert!(is_known_tag(40001));
        assert!(is_known_tag(40002));
        assert!(is_known_tag(40003));
        assert!(is_known_tag(40004));
        assert!(is_known_tag(40005));
        assert!(!is_known_tag(40006)); // reserved but not assigned
        assert!(!is_known_tag(40100)); // out of range
    }

    #[test]
    fn test_validate_tag() {
        // Standard CBOR tags are allowed
        assert!(validate_tag(0));
        assert!(validate_tag(1));
        assert!(validate_tag(1000));
        // Known AgentBridge tags are allowed
        assert!(validate_tag(40001));
        assert!(validate_tag(40005));
        // Unknown AgentBridge tags (40006-40099) are rejected (BC §8.5)
        assert!(!validate_tag(40006));
        assert!(!validate_tag(40050));
        assert!(!validate_tag(40099));
        // Tags > 40099 are rejected
        assert!(!validate_tag(40100));
        assert!(!validate_tag(50000));
    }

    #[test]
    fn test_decoder_limits() {
        assert_eq!(MAX_NESTING_DEPTH, 16);
        assert_eq!(MAX_ARRAY_LENGTH, 1_048_576);
    }
}
