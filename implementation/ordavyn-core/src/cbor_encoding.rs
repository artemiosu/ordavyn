//! Canonical CBOR encoding for Ordavyn (RFC 8949 §4.2.1, BC v1.1.0 §8).
//!
//! Produces deterministic byte sequences for signing and digest verification.
//! Uses CBOR arrays (not maps) for signable content — guarantees field order by construction.

use crate::aim::{
    Duration, Identifier, Instant, Reference, WallclockInstant, WallclockUncertainty,
};
use crate::cbor_tags::{
    TAG_DURATION, TAG_IDENTIFIER, TAG_INSTANT, TAG_REFERENCE, TAG_WALLCLOCK_INSTANT,
};
use crate::error::{CoreError, Result};
use ciborium::value::Value;
use std::io::Cursor;

// ============================================================================
// AIM type → CBOR Value conversions
// ============================================================================

/// Convert an `Identifier` to a CBOR Value (tagged array).
pub fn identifier_to_cbor(id: &Identifier) -> Value {
    let mut arr = vec![
        Value::Integer(TAG_IDENTIFIER.into()),
        Value::Text(id.namespace.clone()),
        Value::Text(id.value.clone()),
    ];
    if let Some(v) = id.version {
        arr.push(Value::Integer(v.into()));
    }
    Value::Array(arr)
}

/// Convert a CBOR Value to an `Identifier`.
pub fn cbor_to_identifier(val: &Value) -> Result<Identifier> {
    let arr = match val {
        Value::Array(a) => a,
        _ => return Err(CoreError::CborDecoding("Identifier must be array".into())),
    };
    if arr.len() < 3 || arr.len() > 4 {
        return Err(CoreError::CborDecoding(
            "Identifier must have 3-4 elements".into(),
        ));
    }
    // arr[0] is the tag marker
    let namespace = match &arr[1] {
        Value::Text(s) => s.clone(),
        _ => return Err(CoreError::CborDecoding("namespace must be text".into())),
    };
    let value = match &arr[2] {
        Value::Text(s) => s.clone(),
        _ => return Err(CoreError::CborDecoding("value must be text".into())),
    };
    let version = if arr.len() == 4 {
        match &arr[3] {
            Value::Integer(i) => Some((*i).try_into().unwrap_or(0u64)),
            _ => return Err(CoreError::CborDecoding("version must be integer".into())),
        }
    } else {
        None
    };
    Ok(Identifier {
        namespace,
        value,
        version,
    })
}

/// Convert a `Reference` to a CBOR Value.
pub fn reference_to_cbor(r: &Reference) -> Value {
    let mut arr = vec![
        Value::Integer(TAG_REFERENCE.into()),
        Value::Text(r.target_type.clone()),
        identifier_to_cbor(&r.target_id),
    ];
    if let Some(v) = r.closure_version {
        arr.push(Value::Integer(v.into()));
    }
    Value::Array(arr)
}

/// Convert a CBOR Value to a `Reference`.
pub fn cbor_to_reference(val: &Value) -> Result<Reference> {
    let arr = match val {
        Value::Array(a) => a,
        _ => return Err(CoreError::CborDecoding("Reference must be array".into())),
    };
    if arr.len() < 3 || arr.len() > 4 {
        return Err(CoreError::CborDecoding(
            "Reference must have 3-4 elements".into(),
        ));
    }
    let target_type = match &arr[1] {
        Value::Text(s) => s.clone(),
        _ => return Err(CoreError::CborDecoding("target_type must be text".into())),
    };
    let target_id = cbor_to_identifier(&arr[2])?;
    let closure_version = if arr.len() == 4 {
        match &arr[3] {
            Value::Integer(i) => Some((*i).try_into().unwrap_or(0u64)),
            _ => {
                return Err(CoreError::CborDecoding(
                    "closure_version must be integer".into(),
                ))
            }
        }
    } else {
        None
    };
    Ok(Reference {
        target_type,
        target_id,
        closure_version,
    })
}

/// Convert an `Instant` to a CBOR Value.
pub fn instant_to_cbor(i: &Instant) -> Value {
    Value::Array(vec![
        Value::Integer(TAG_INSTANT.into()),
        Value::Integer(i.nanos.into()),
    ])
}

/// Convert a CBOR Value to an `Instant`.
pub fn cbor_to_instant(val: &Value) -> Result<Instant> {
    let arr = match val {
        Value::Array(a) => a,
        _ => return Err(CoreError::CborDecoding("Instant must be array".into())),
    };
    if arr.len() != 2 {
        return Err(CoreError::CborDecoding(
            "Instant must have 2 elements".into(),
        ));
    }
    let nanos = match &arr[1] {
        Value::Integer(i) => (*i).try_into().unwrap_or(0u64),
        _ => {
            return Err(CoreError::CborDecoding(
                "Instant nanos must be integer".into(),
            ))
        }
    };
    Ok(Instant { nanos })
}

/// Convert a `Duration` to a CBOR Value.
pub fn duration_to_cbor(d: &Duration) -> Value {
    Value::Array(vec![
        Value::Integer(TAG_DURATION.into()),
        Value::Integer(d.nanos.into()),
    ])
}

/// Convert a CBOR Value to a `Duration`.
pub fn cbor_to_duration(val: &Value) -> Result<Duration> {
    let arr = match val {
        Value::Array(a) => a,
        _ => return Err(CoreError::CborDecoding("Duration must be array".into())),
    };
    if arr.len() != 2 {
        return Err(CoreError::CborDecoding(
            "Duration must have 2 elements".into(),
        ));
    }
    let nanos = match &arr[1] {
        Value::Integer(i) => (*i).try_into().unwrap_or(0u64),
        _ => {
            return Err(CoreError::CborDecoding(
                "Duration nanos must be integer".into(),
            ))
        }
    };
    Ok(Duration { nanos })
}

/// Convert a `WallclockInstant` to a CBOR Value.
pub fn wallclock_to_cbor(w: &WallclockInstant) -> Value {
    let uncertainty = match &w.uncertainty {
        WallclockUncertainty::Known(d) => duration_to_cbor(d),
        WallclockUncertainty::Unknown => Value::Null,
    };
    Value::Array(vec![
        Value::Integer(TAG_WALLCLOCK_INSTANT.into()),
        Value::Integer(w.central.into()),
        uncertainty,
    ])
}

/// Convert a CBOR Value to a `WallclockInstant`.
pub fn cbor_to_wallclock(val: &Value) -> Result<WallclockInstant> {
    let arr = match val {
        Value::Array(a) => a,
        _ => {
            return Err(CoreError::CborDecoding(
                "WallclockInstant must be array".into(),
            ))
        }
    };
    if arr.len() != 3 {
        return Err(CoreError::CborDecoding(
            "WallclockInstant must have 3 elements".into(),
        ));
    }
    let central = match &arr[1] {
        Value::Integer(i) => (*i).try_into().unwrap_or(0u64),
        _ => return Err(CoreError::CborDecoding("central must be integer".into())),
    };
    let uncertainty = match &arr[2] {
        Value::Null => WallclockUncertainty::Unknown,
        _ => WallclockUncertainty::Known(cbor_to_duration(&arr[2])?),
    };
    Ok(WallclockInstant {
        central,
        uncertainty,
    })
}

// ============================================================================
// Canonical CBOR serialization
// ============================================================================

/// Serialize a CBOR Value to canonical bytes.
pub fn canonical_bytes(value: &Value) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(value, &mut buf)
        .map_err(|e| CoreError::CborEncoding(e.to_string()))?;
    Ok(buf)
}

/// Deserialize canonical CBOR bytes to a Value.
pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Value> {
    ciborium::de::from_reader(&mut Cursor::new(bytes))
        .map_err(|e| CoreError::CborDecoding(e.to_string()))
}

/// Compute SHA-256 digest of canonical CBOR bytes.
pub fn digest(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identifier_cbor_roundtrip() {
        let id = Identifier::new("participant", "alice");
        let cbor = identifier_to_cbor(&id);
        let bytes = canonical_bytes(&cbor).unwrap();
        let decoded = from_canonical_bytes(&bytes).unwrap();
        let id2 = cbor_to_identifier(&decoded).unwrap();
        assert_eq!(id, id2);
    }

    #[test]
    fn test_identifier_with_version_roundtrip() {
        let id = Identifier::with_version("artifact", "core", 3);
        let cbor = identifier_to_cbor(&id);
        let bytes = canonical_bytes(&cbor).unwrap();
        let decoded = from_canonical_bytes(&bytes).unwrap();
        let id2 = cbor_to_identifier(&decoded).unwrap();
        assert_eq!(id, id2);
    }

    #[test]
    fn test_identifier_canonical_deterministic() {
        let id1 = Identifier::new("ns", "val");
        let id2 = Identifier::new("ns", "val");
        let b1 = canonical_bytes(&identifier_to_cbor(&id1)).unwrap();
        let b2 = canonical_bytes(&identifier_to_cbor(&id2)).unwrap();
        assert_eq!(b1, b2);
    }

    #[test]
    fn test_reference_roundtrip() {
        let r = Reference::new("Artifact", Identifier::new("artifact", "core"));
        let cbor = reference_to_cbor(&r);
        let bytes = canonical_bytes(&cbor).unwrap();
        let decoded = from_canonical_bytes(&bytes).unwrap();
        let r2 = cbor_to_reference(&decoded).unwrap();
        assert_eq!(r, r2);
    }

    #[test]
    fn test_instant_roundtrip() {
        let i = Instant::from_secs(1234567890);
        let cbor = instant_to_cbor(&i);
        let bytes = canonical_bytes(&cbor).unwrap();
        let decoded = from_canonical_bytes(&bytes).unwrap();
        let i2 = cbor_to_instant(&decoded).unwrap();
        assert_eq!(i, i2);
    }

    #[test]
    fn test_duration_roundtrip() {
        let d = Duration::from_millis(500);
        let cbor = duration_to_cbor(&d);
        let bytes = canonical_bytes(&cbor).unwrap();
        let decoded = from_canonical_bytes(&bytes).unwrap();
        let d2 = cbor_to_duration(&decoded).unwrap();
        assert_eq!(d, d2);
    }

    #[test]
    fn test_wallclock_known_roundtrip() {
        let w = WallclockInstant::new(1000000, Duration::from_millis(500));
        let cbor = wallclock_to_cbor(&w);
        let bytes = canonical_bytes(&cbor).unwrap();
        let decoded = from_canonical_bytes(&bytes).unwrap();
        let w2 = cbor_to_wallclock(&decoded).unwrap();
        assert_eq!(w, w2);
    }

    #[test]
    fn test_wallclock_unknown_roundtrip() {
        let w = WallclockInstant::with_unknown_uncertainty(1000000);
        let cbor = wallclock_to_cbor(&w);
        let bytes = canonical_bytes(&cbor).unwrap();
        let decoded = from_canonical_bytes(&bytes).unwrap();
        let w2 = cbor_to_wallclock(&decoded).unwrap();
        assert_eq!(w, w2);
    }

    #[test]
    fn test_digest_deterministic() {
        let id = Identifier::new("ns", "val");
        let bytes = canonical_bytes(&identifier_to_cbor(&id)).unwrap();
        let d1 = digest(&bytes);
        let d2 = digest(&bytes);
        assert_eq!(d1, d2);
    }

    #[test]
    fn test_digest_different_for_different_values() {
        let id1 = Identifier::new("ns", "val1");
        let id2 = Identifier::new("ns", "val2");
        let b1 = canonical_bytes(&identifier_to_cbor(&id1)).unwrap();
        let b2 = canonical_bytes(&identifier_to_cbor(&id2)).unwrap();
        assert_ne!(digest(&b1), digest(&b2));
    }
}
