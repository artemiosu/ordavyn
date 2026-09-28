//! Experimental v2: strict JSON transport, domain-separated deterministic CBOR.
use crate::security::{invalid, MAX_BODY};
use crate::{Ed25519Signature, Message, Result, SignatureAlgorithm};
use serde::{Deserialize, Deserializer, Serializer};
use serde_json::Value;
pub const ENCODING: &str = "ordavyn-cbor-v2";
pub const DOMAIN: &[u8] = b"ordavyn:v2:message\0";

pub fn required_option<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> std::result::Result<Option<T>, D::Error> {
    Option::<T>::deserialize(d)
}
pub mod algorithm {
    use super::*;
    pub fn serialize<S: Serializer>(
        v: &Option<SignatureAlgorithm>,
        s: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::Serialize;
        v.map(|a| a.id()).serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> std::result::Result<Option<SignatureAlgorithm>, D::Error> {
        match Option::<u8>::deserialize(d)? {
            None => Ok(None),
            Some(1) => Ok(Some(SignatureAlgorithm::Ed25519)),
            _ => Err(serde::de::Error::custom("unsupported algorithm")),
        }
    }
}
pub mod signature {
    use super::*;
    pub fn serialize<S: Serializer>(
        v: &Option<Ed25519Signature>,
        s: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::Serialize;
        v.as_ref()
            .map(|sig| {
                sig.bytes
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            })
            .serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> std::result::Result<Option<Ed25519Signature>, D::Error> {
        let Some(s) = Option::<String>::deserialize(d)? else {
            return Ok(None);
        };
        if !lower_hex(&s, 128) {
            return Err(serde::de::Error::custom("invalid signature"));
        }
        let bytes = (0..128)
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect();
        Ok(Some(Ed25519Signature::new(
            bytes,
            SignatureAlgorithm::Ed25519,
        )))
    }
}
fn lower_hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn tree(v: &Value, depth: usize) -> Result<()> {
    if depth > 32 {
        return Err(invalid("tree depth exceeds 32"));
    }
    match v {
        Value::Array(a) => {
            for x in a {
                tree(x, depth + 1)?
            }
        }
        Value::Object(m) => {
            for x in m.values() {
                tree(x, depth + 1)?
            }
        }
        _ => {}
    }
    Ok(())
}
pub fn validate(msg: &Message, signing: bool) -> Result<()> {
    tree(&msg.payload, 2)?;
    if msg.version != 2 || msg.encoding != ENCODING {
        return Err(invalid("unsupported wire version or encoding"));
    }
    for (id, ns) in [
        (&msg.id, "message"),
        (&msg.operation_id, "logical-operation"),
        (&msg.from, "participant"),
        (&msg.to, "participant"),
        (&msg.epoch, "epoch"),
    ] {
        if id.namespace != ns {
            return Err(invalid("invalid envelope namespace"));
        }
    }
    for id in [
        &msg.id,
        &msg.operation_id,
        &msg.from,
        &msg.to,
        &msg.epoch,
        &msg.subject.target_id,
    ] {
        if !id.is_valid() || id.namespace.len() > 256 || id.value.len() > 256 {
            return Err(invalid("invalid identifier"));
        }
    }
    if msg.subject.target_type.is_empty() || msg.subject.target_type.len() > 256 {
        return Err(invalid("invalid reference"));
    }
    match (&msg.signature_alg, &msg.key_id, &msg.signature) {
        (None, None, None) => {}
        (Some(SignatureAlgorithm::Ed25519), Some(k), sig) if lower_hex(k, 16) => match sig {
            None if signing => {}
            Some(s) if s.bytes.len() == 64 && s.algorithm == SignatureAlgorithm::Ed25519 => {}
            _ => return Err(invalid("invalid signature")),
        },
        _ => return Err(invalid("invalid signing metadata")),
    }
    let value = serde_json::to_value(msg).map_err(|_| invalid("invalid JSON value"))?;
    tree(&value, 1)?;
    let mut model = Vec::new();
    ciborium::ser::into_writer(&cbor(&value)?, &mut model)
        .map_err(|_| invalid("CBOR serialization"))?;
    if model.len() > MAX_BODY {
        return Err(invalid("model exceeds 64KiB"));
    }
    Ok(())
}
fn cbor(v: &Value) -> Result<ciborium::Value> {
    use ciborium::Value as C;
    Ok(match v {
        Value::Null => C::Null,
        Value::Bool(b) => C::Bool(*b),
        Value::String(s) => C::Text(s.clone()),
        Value::Number(n) => {
            if n.is_f64() {
                C::Float(n.as_f64().ok_or_else(|| invalid("invalid float"))?)
            } else if let Some(i) = n.as_i64() {
                C::Integer(i.into())
            } else {
                C::Integer(n.as_u64().ok_or_else(|| invalid("invalid integer"))?.into())
            }
        }
        Value::Array(a) => C::Array(a.iter().map(cbor).collect::<Result<_>>()?),
        Value::Object(m) => {
            let mut entries = Vec::new();
            for (k, v) in m {
                let key = C::Text(k.clone());
                let mut bytes = Vec::new();
                ciborium::ser::into_writer(&key, &mut bytes).map_err(|_| invalid("CBOR key"))?;
                entries.push((bytes, key, cbor(v)?));
            }
            entries.sort_by(|a, b| a.0.len().cmp(&b.0.len()).then(a.0.cmp(&b.0)));
            C::Map(entries.into_iter().map(|(_, k, v)| (k, v)).collect())
        }
    })
}
pub fn signable_bytes(msg: &Message) -> Result<Vec<u8>> {
    validate(msg, true)?;
    let mut value = serde_json::to_value(msg).map_err(|_| invalid("invalid message"))?;
    value.as_object_mut().unwrap().remove("signature");
    let mut bytes = DOMAIN.to_vec();
    ciborium::ser::into_writer(&cbor(&value)?, &mut bytes)
        .map_err(|_| invalid("CBOR serialization"))?;
    Ok(bytes)
}
pub fn to_json(msg: &Message) -> Result<Vec<u8>> {
    validate(msg, false)?;
    let bytes = serde_json::to_vec(msg).map_err(|_| invalid("JSON serialization"))?;
    if bytes.len() > MAX_BODY {
        return Err(invalid("body exceeds 64KiB"));
    }
    Ok(bytes)
}
pub fn from_json(bytes: &[u8]) -> Result<Message> {
    crate::json::message(bytes)
}
/// Check integer tokens before serde_json can round an out-of-range integer into f64.
pub(crate) fn check_tokens(bytes: &[u8]) -> Result<()> {
    if bytes.len() > MAX_BODY {
        return Err(invalid("body exceeds 64KiB"));
    }
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            i += 1;
            while i < bytes.len() {
                if bytes[i] == b'\\' {
                    i += 2;
                } else if bytes[i] == b'"' {
                    i += 1;
                    break;
                } else {
                    i += 1;
                }
            }
        } else if bytes[i] == b'-' || bytes[i].is_ascii_digit() {
            let start = i;
            i += 1;
            while i < bytes.len() && (bytes[i].is_ascii_digit() || b".eE+-".contains(&bytes[i])) {
                i += 1;
            }
            let token = &bytes[start..i];
            if !token.iter().any(|c| b".eE".contains(c)) {
                let s = std::str::from_utf8(token).map_err(|_| invalid("invalid number"))?;
                if s == "-0"
                    || (s.starts_with('-') && s.parse::<i64>().is_err())
                    || (!s.starts_with('-') && s.parse::<u64>().is_err())
                {
                    return Err(invalid("integer out of range or negative zero"));
                }
            }
        } else {
            i += 1;
        }
    }
    Ok(())
}
