//! AIM primitive types — Abstract Information Model (AIM v1.0.1)
//!
//! Implements the ten primitive semantic domains defined in AIM §3:
//! Boolean, Integer, Decimal, String, Bytes, Instant, Duration, WallclockInstant, Identifier, Reference.
//!
//! Also implements the four-valued distinction (AIM §4):
//! absent / explicit-empty / unknown / invalid.

use serde::{Deserialize, Serialize};
use std::fmt;

// ============================================================================
// CBOR Tag Assignments (BC v1.1.0 §8.1, RFC 8949)
// ============================================================================

/// CBOR tag for `Identifier` (AIM §9).
pub const TAG_IDENTIFIER: u64 = 40001;
/// CBOR tag for `Reference` (AIM §10).
pub const TAG_REFERENCE: u64 = 40002;
/// CBOR tag for `Instant` (AIM §8.1).
pub const TAG_INSTANT: u64 = 40003;
/// CBOR tag for `Duration` (AIM §8.2).
pub const TAG_DURATION: u64 = 40004;
/// CBOR tag for `WallclockInstant` (AIM §8.3).
pub const TAG_WALLCLOCK_INSTANT: u64 = 40005;

// ============================================================================
// Four-valued distinction (AIM §4)
// ============================================================================

/// Four-valued field state (AIM §4): absent, explicit-empty, unknown, invalid.
///
/// Every field in Ordavyn can be in one of four states:
/// - `Absent` — field not present in the model
/// - `ExplicitEmpty` — field present and intentionally empty
/// - `Unknown` — field present but value cannot be established
/// - `Invalid` — input violates model or domain constraint
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueState {
    Absent,
    ExplicitEmpty,
    Unknown,
    Invalid,
}

impl fmt::Display for ValueState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValueState::Absent => write!(f, "absent"),
            ValueState::ExplicitEmpty => write!(f, "explicit-empty"),
            ValueState::Unknown => write!(f, "unknown"),
            ValueState::Invalid => write!(f, "invalid"),
        }
    }
}

// ============================================================================
// Identifier (AIM §9)
// ============================================================================

/// Ordavyn `Identifier` — typed `(namespace, value, version?)` tuple (AIM §9.1).
///
/// Identifiers are immutable. Equality is component-wise (AIM §9.2).
/// The minimum namespace alphabet is URN RFC 8141 subset: `a-z`, `0-9`, `-`, `.`, `:`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identifier {
    /// Namespace — non-empty String from URN RFC 8141 subset alphabet.
    pub namespace: String,
    /// Value — non-empty String or Bytes, type fixed per namespace.
    pub value: String,
    /// Optional version — Integer or String, type fixed per namespace.
    pub version: Option<u64>,
}

impl Identifier {
    /// Create a new Identifier with no version.
    pub fn new(namespace: &str, value: &str) -> Self {
        Self {
            namespace: namespace.to_string(),
            value: value.to_string(),
            version: None,
        }
    }

    /// Create a new Identifier with an integer version.
    pub fn with_version(namespace: &str, value: &str, version: u64) -> Self {
        Self {
            namespace: namespace.to_string(),
            value: value.to_string(),
            version: Some(version),
        }
    }

    /// Validate namespace against AIM §9.1 minimum alphabet (URN RFC 8141 subset).
    pub fn validate_namespace(&self) -> bool {
        if self.namespace.is_empty() {
            return false;
        }
        self.namespace.chars().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.' || c == ':'
        })
    }

    /// Validate value is non-empty (AIM §9.1).
    pub fn validate_value(&self) -> bool {
        !self.value.is_empty()
    }

    /// Validate the identifier is well-formed (AIM §9.1).
    pub fn is_valid(&self) -> bool {
        self.validate_namespace() && self.validate_value()
    }
}

impl fmt::Display for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.version {
            Some(v) => write!(f, "{}:{}:{}", self.namespace, self.value, v),
            None => write!(f, "{}:{}", self.namespace, self.value),
        }
    }
}

impl Ord for Identifier {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Lexicographic order: (namespace, value, version) — AIM §9.2
        // Absent version is less than any present version.
        self.namespace
            .cmp(&other.namespace)
            .then_with(|| self.value.cmp(&other.value))
            .then_with(|| self.version.cmp(&other.version))
    }
}

impl PartialOrd for Identifier {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

// ============================================================================
// Reference (AIM §10)
// ============================================================================

/// Ordavyn `Reference` — typed pointer to another AIM object (AIM §10.1).
///
/// References carry: declared target type, target Identifier, optional closure version (Integer).
/// Target MUST be a non-Reference AIM object (AIM §10.1, BC v1.1.0).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reference {
    /// Declared target type (e.g., "Artifact", "Evidence", "DecisionSubject").
    pub target_type: String,
    /// Target Identifier.
    pub target_id: Identifier,
    /// Optional closure version (Integer, monotonic — BC v1.1.0 §10.1).
    pub closure_version: Option<u64>,
}

impl Reference {
    /// Create a new Reference with no closure version.
    pub fn new(target_type: &str, target_id: Identifier) -> Self {
        Self {
            target_type: target_type.to_string(),
            target_id,
            closure_version: None,
        }
    }

    /// Create a new Reference with a closure version.
    pub fn with_closure_version(target_type: &str, target_id: Identifier, version: u64) -> Self {
        Self {
            target_type: target_type.to_string(),
            target_id,
            closure_version: Some(version),
        }
    }
}

impl fmt::Display for Reference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.closure_version {
            Some(v) => write!(
                f,
                "Reference<{}>({}@{})",
                self.target_type, self.target_id, v
            ),
            None => write!(f, "Reference<{}>({})", self.target_type, self.target_id),
        }
    }
}

// ============================================================================
// Instant (AIM §8.1) — per-context monotonic logical time
// ============================================================================

/// Ordavyn `Instant` — monotonic logical time, per-context (AIM §8.1).
///
/// Stored as nanoseconds since context epoch. Cross-context comparison
/// is invalid without explicit projection (AIM §8.1, AAM §13.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Instant {
    /// Nanoseconds since context epoch.
    pub nanos: u64,
}

impl Instant {
    pub fn from_nanos(nanos: u64) -> Self {
        Self { nanos }
    }

    pub fn from_millis(millis: u64) -> Self {
        Self {
            nanos: millis * 1_000_000,
        }
    }

    pub fn from_secs(secs: u64) -> Self {
        Self {
            nanos: secs * 1_000_000_000,
        }
    }

    /// Subtract two Instants from the same context → Duration (AIM §8.1).
    /// Returns None if `other` > `self` (negative Duration is invalid).
    pub fn duration_since(&self, other: &Instant) -> Option<Duration> {
        self.nanos
            .checked_sub(other.nanos)
            .map(|nanos| Duration { nanos })
    }
}

impl fmt::Display for Instant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Instant({}ns)", self.nanos)
    }
}

// ============================================================================
// Duration (AIM §8.2) — non-negative rational seconds
// ============================================================================

/// Ordavyn `Duration` — non-negative duration in nanoseconds (AIM §8.2).
///
/// Negative durations are invalid. Multiplication by negative scalar is invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Duration {
    /// Nanoseconds (non-negative).
    pub nanos: u64,
}

impl Duration {
    pub fn from_nanos(nanos: u64) -> Self {
        Self { nanos }
    }

    pub fn from_millis(millis: u64) -> Self {
        Self {
            nanos: millis * 1_000_000,
        }
    }

    pub fn from_secs(secs: u64) -> Self {
        Self {
            nanos: secs * 1_000_000_000,
        }
    }

    /// Add two Durations (AIM §8.2).
    pub fn add(&self, other: &Duration) -> Option<Duration> {
        self.nanos
            .checked_add(other.nanos)
            .map(|nanos| Duration { nanos })
    }

    /// Subtract two Durations. Returns None if result would be negative (AIM §8.2).
    pub fn sub(&self, other: &Duration) -> Option<Duration> {
        self.nanos
            .checked_sub(other.nanos)
            .map(|nanos| Duration { nanos })
    }

    /// Check if duration is zero (AIM §4.5: Duration(0) is a valid value, not a state).
    pub fn is_zero(&self) -> bool {
        self.nanos == 0
    }
}

impl fmt::Display for Duration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Duration({}ns)", self.nanos)
    }
}

// ============================================================================
// WallclockInstant (AIM §8.3) — civil time with explicit uncertainty
// ============================================================================

/// Ordavyn `WallclockInstant` — civil time paired with uncertainty (AIM §8.3).
///
/// NOT comparable to `Instant` without explicit projection.
/// Zero uncertainty does NOT collapse the domain distinction (AIM §8.3, BC v1.1.0).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WallclockInstant {
    /// Central value (nanoseconds since civil epoch).
    pub central: u64,
    /// Uncertainty — Duration or Unknown.
    pub uncertainty: WallclockUncertainty,
}

/// Uncertainty for WallclockInstant — either a Duration or Unknown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WallclockUncertainty {
    /// Known uncertainty as a Duration.
    Known(Duration),
    /// Unknown uncertainty.
    Unknown,
}

impl WallclockInstant {
    pub fn new(central: u64, uncertainty: Duration) -> Self {
        Self {
            central,
            uncertainty: WallclockUncertainty::Known(uncertainty),
        }
    }

    pub fn with_unknown_uncertainty(central: u64) -> Self {
        Self {
            central,
            uncertainty: WallclockUncertainty::Unknown,
        }
    }

    /// Check if uncertainty is zero (AIM §8.3: zero uncertainty does NOT collapse domain).
    pub fn has_zero_uncertainty(&self) -> bool {
        match &self.uncertainty {
            WallclockUncertainty::Known(d) => d.is_zero(),
            WallclockUncertainty::Unknown => false,
        }
    }
}

impl fmt::Display for WallclockInstant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.uncertainty {
            WallclockUncertainty::Known(d) => {
                write!(f, "WallclockInstant({}±{}ns)", self.central, d.nanos)
            }
            WallclockUncertainty::Unknown => {
                write!(f, "WallclockInstant({}±unknown)", self.central)
            }
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- Identifier tests ---

    #[test]
    fn test_identifier_new() {
        let id = Identifier::new("participant", "alice");
        assert_eq!(id.namespace, "participant");
        assert_eq!(id.value, "alice");
        assert!(id.version.is_none());
    }

    #[test]
    fn test_identifier_with_version() {
        let id = Identifier::with_version("artifact", "core", 2);
        assert_eq!(id.version, Some(2));
    }

    #[test]
    fn test_identifier_equality() {
        let a = Identifier::new("ns", "val");
        let b = Identifier::new("ns", "val");
        let c = Identifier::new("ns", "other");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_identifier_version_equality() {
        let v1 = Identifier::with_version("ns", "val", 1);
        let v2 = Identifier::with_version("ns", "val", 2);
        let v1_copy = Identifier::with_version("ns", "val", 1);
        assert_ne!(v1, v2); // Different versions are different identifiers
        assert_eq!(v1, v1_copy);
    }

    #[test]
    fn test_identifier_ordering() {
        let a = Identifier::new("a", "1");
        let b = Identifier::new("a", "2");
        let c = Identifier::new("b", "1");
        assert!(a < b);
        assert!(b < c);
    }

    #[test]
    fn test_identifier_version_ordering() {
        let absent = Identifier::new("ns", "val");
        let v0 = Identifier::with_version("ns", "val", 0);
        let v1 = Identifier::with_version("ns", "val", 1);
        // Absent version < version=0 < version=1 (AIM §9.2)
        assert!(absent < v0);
        assert!(v0 < v1);
    }

    #[test]
    fn test_identifier_validate_namespace() {
        assert!(Identifier::new("participant", "x").validate_namespace());
        assert!(Identifier::new("artifact.core", "x").validate_namespace());
        assert!(Identifier::new("a:b:c", "x").validate_namespace());
        assert!(!Identifier::new("", "x").validate_namespace()); // empty
        assert!(!Identifier::new("UPPER", "x").validate_namespace()); // uppercase
        assert!(!Identifier::new("has space", "x").validate_namespace()); // space
    }

    #[test]
    fn test_identifier_display() {
        let id = Identifier::new("participant", "alice");
        assert_eq!(id.to_string(), "participant:alice");
        let id_v = Identifier::with_version("artifact", "core", 2);
        assert_eq!(id_v.to_string(), "artifact:core:2");
    }

    // --- Reference tests ---

    #[test]
    fn test_reference_new() {
        let id = Identifier::new("artifact", "core");
        let r = Reference::new("Artifact", id.clone());
        assert_eq!(r.target_type, "Artifact");
        assert_eq!(r.target_id, id);
        assert!(r.closure_version.is_none());
    }

    #[test]
    fn test_reference_with_closure_version() {
        let id = Identifier::new("artifact", "core");
        let r = Reference::with_closure_version("Artifact", id, 42);
        assert_eq!(r.closure_version, Some(42));
    }

    #[test]
    fn test_reference_equality_same_id_different_type() {
        let id = Identifier::new("ns", "val");
        let r1 = Reference::new("Artifact", id.clone());
        let r2 = Reference::new("Evidence", id);
        // Different declared target types → unequal (AIM §10.4)
        assert_ne!(r1, r2);
    }

    // --- Instant tests ---

    #[test]
    fn test_instant_ordering() {
        let a = Instant::from_secs(100);
        let b = Instant::from_secs(200);
        assert!(a < b);
    }

    #[test]
    fn test_instant_duration_since() {
        let a = Instant::from_secs(200);
        let b = Instant::from_secs(100);
        let d = a.duration_since(&b).unwrap();
        assert_eq!(d, Duration::from_secs(100));
    }

    #[test]
    fn test_instant_duration_since_negative_returns_none() {
        let a = Instant::from_secs(100);
        let b = Instant::from_secs(200);
        // a - b would be negative → None (AIM §8.1: cross-context subtraction invalid)
        assert!(a.duration_since(&b).is_none());
    }

    // --- Duration tests ---

    #[test]
    fn test_duration_add() {
        let a = Duration::from_secs(100);
        let b = Duration::from_secs(200);
        assert_eq!(a.add(&b), Some(Duration::from_secs(300)));
    }

    #[test]
    fn test_duration_sub() {
        let a = Duration::from_secs(300);
        let b = Duration::from_secs(100);
        assert_eq!(a.sub(&b), Some(Duration::from_secs(200)));
    }

    #[test]
    fn test_duration_sub_negative_returns_none() {
        let a = Duration::from_secs(100);
        let b = Duration::from_secs(200);
        assert!(a.sub(&b).is_none()); // negative duration is invalid
    }

    #[test]
    fn test_duration_zero_is_valid_value() {
        // AIM §4.5: Duration(0) is a valid value, NOT a state
        let zero = Duration::from_nanos(0);
        assert!(zero.is_zero());
        // Duration(0) ≠ Absent
        let absent: Option<Duration> = None;
        assert_ne!(Some(zero), absent);
    }

    // --- WallclockInstant tests ---

    #[test]
    fn test_wallclock_zero_uncertainty_does_not_collapse() {
        // AIM §8.3: WallclockInstant with zero uncertainty is still WallclockInstant,
        // NOT comparable to Instant
        let w = WallclockInstant::new(1000, Duration::from_nanos(0));
        assert!(w.has_zero_uncertainty());
        // It's still a WallclockInstant, not an Instant — type system enforces this
    }

    #[test]
    fn test_wallclock_unknown_uncertainty() {
        let w = WallclockInstant::with_unknown_uncertainty(1000);
        assert!(!w.has_zero_uncertainty());
    }

    // --- ValueState tests ---

    #[test]
    fn test_value_state_distinct() {
        // AIM §4: all four states are distinct
        let states = vec![
            ValueState::Absent,
            ValueState::ExplicitEmpty,
            ValueState::Unknown,
            ValueState::Invalid,
        ];
        for (i, a) in states.iter().enumerate() {
            for (j, b) in states.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b, "states {} and {} should differ", i, j);
                }
            }
        }
    }

    #[test]
    fn test_value_state_display() {
        assert_eq!(ValueState::Absent.to_string(), "absent");
        assert_eq!(ValueState::ExplicitEmpty.to_string(), "explicit-empty");
        assert_eq!(ValueState::Unknown.to_string(), "unknown");
        assert_eq!(ValueState::Invalid.to_string(), "invalid");
    }
}
