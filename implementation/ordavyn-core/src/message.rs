//! Local Ordavyn message envelope with Ed25519-authenticated metadata.
//! Rust signs the domain-separated deterministic CBOR v2 map; transport is JSON.

use crate::aim::{Identifier, Instant, Reference};
use crate::crypto::{Ed25519Keypair, Ed25519Signature, SignatureAlgorithm};
use crate::error::{CoreError, Result};
use serde::{Deserialize, Serialize};

/// Message type (BC v1.1.0 §4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MessageType {
    Request,
    Response,
    Event,
    Error,
}

/// Local envelope; only Ed25519 and the fixed CBOR signing format are supported.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Message {
    /// Protocol version (currently 2).
    pub version: u8,
    /// Message type.
    #[serde(rename = "type")]
    pub msg_type: MessageType,
    /// Message ID (AIM §3.5 — unique per message).
    pub id: Identifier,
    /// Logical Operation ID (LOM §3.1).
    pub operation_id: Identifier,
    /// Decision Subject reference (DSM §3).
    pub subject: Reference,
    /// Sender participant (RCM §3.1).
    pub from: Identifier,
    /// Recipient participant (RCM §3.1).
    pub to: Identifier,
    /// Current Epoch (RCM §3.4).
    pub epoch: Identifier,
    /// Message-specific payload.
    pub payload: serde_json::Value,
    /// Signature algorithm (BC §3.8 registry). None for unsigned messages.
    #[serde(with = "crate::wire::algorithm")]
    pub signature_alg: Option<SignatureAlgorithm>,
    /// Verifier key identifier. None for unsigned messages.
    #[serde(deserialize_with = "crate::wire::required_option")]
    pub key_id: Option<String>,
    /// Variable-length signature. None for unsigned messages.
    #[serde(with = "crate::wire::signature")]
    pub signature: Option<Ed25519Signature>,
    /// Send time (AIM §8.1).
    pub timestamp: Instant,
    /// Fixed signing representation "ordavyn-cbor-v2"; JSON transport does not negotiate it.
    pub encoding: String,
}

impl Message {
    /// Check if this message is signed.
    pub fn is_signed(&self) -> bool {
        self.signature.is_some()
    }

    /// Sign this message with an Ed25519 keypair.
    ///
    /// Uses PureEdDSA (RFC 8032, direct signing, NO pre-hash).
    /// Signs the canonical CBOR encoding of the message (excluding only the signature value).
    pub fn sign(&mut self, keypair: &Ed25519Keypair) -> Result<()> {
        let mut candidate = self.clone();
        candidate.signature_alg = Some(SignatureAlgorithm::Ed25519);
        candidate.key_id = Some(keypair.key_id());
        candidate.signature = None;
        let signable_bytes = candidate.canonical_signable_bytes()?;
        candidate.signature = Some(keypair.sign(&signable_bytes));
        crate::wire::validate(&candidate, false)?;
        *self = candidate;
        Ok(())
    }

    /// Verify this message's signature.
    ///
    /// Uses PureEdDSA verification (RFC 8032).
    pub fn verify_signature(&self, public_key: &crate::crypto::Ed25519PublicKey) -> Result<()> {
        let sig = self
            .signature
            .as_ref()
            .ok_or_else(|| CoreError::InvalidMessage("no signature present".to_string()))?;

        if self.signature_alg != Some(SignatureAlgorithm::Ed25519)
            || self.key_id.as_deref() != Some(public_key.key_id().as_str())
            || self.encoding != "ordavyn-cbor-v2"
            || sig.algorithm != SignatureAlgorithm::Ed25519
        {
            return Err(CoreError::InvalidMessage(
                "invalid signature metadata".into(),
            ));
        }
        let signable_bytes = self.canonical_signable_bytes()?;

        Ed25519Keypair::verify(public_key, &signable_bytes, sig)
    }

    /// Domain-separated RFC8949 length-first deterministic CBOR v2.
    pub fn canonical_signable_bytes(&self) -> Result<Vec<u8>> {
        crate::wire::signable_bytes(self)
    }
}

/// Builder for constructing messages.
pub struct MessageBuilder {
    msg: Message,
}

impl MessageBuilder {
    pub fn new(from: Identifier, to: Identifier) -> Self {
        Self {
            msg: Message {
                version: 2,
                msg_type: MessageType::Request,
                id: Identifier::new("message", &uuid_like()),
                operation_id: Identifier::new("logical-operation", &uuid_like()),
                subject: Reference::new(
                    "DecisionSubject",
                    Identifier::new("decision-subject", "placeholder"),
                ),
                from,
                to,
                epoch: Identifier::new("epoch", "current"),
                payload: serde_json::Value::Null,
                signature_alg: None,
                key_id: None,
                signature: None,
                timestamp: Instant::from_nanos(0),
                encoding: "ordavyn-cbor-v2".to_string(),
            },
        }
    }

    pub fn msg_type(mut self, t: MessageType) -> Self {
        self.msg.msg_type = t;
        self
    }

    pub fn id(mut self, id: Identifier) -> Self {
        self.msg.id = id;
        self
    }

    pub fn operation_id(mut self, id: Identifier) -> Self {
        self.msg.operation_id = id;
        self
    }

    pub fn subject(mut self, subject: Reference) -> Self {
        self.msg.subject = subject;
        self
    }

    pub fn epoch(mut self, epoch: Identifier) -> Self {
        self.msg.epoch = epoch;
        self
    }

    pub fn payload(mut self, payload: serde_json::Value) -> Self {
        self.msg.payload = payload;
        self
    }

    pub fn timestamp(mut self, ts: Instant) -> Self {
        self.msg.timestamp = ts;
        self
    }

    pub fn build(self) -> Message {
        self.msg
    }
}

/// Simple UUID-like generator for prototype (not cryptographically random, just unique-ish).
fn uuid_like() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aim::Identifier;

    #[test]
    fn test_message_builder() {
        let from = Identifier::new("participant", "alice").clone();
        let to = Identifier::new("participant", "bob").clone();

        let msg = MessageBuilder::new(from.clone(), to.clone())
            .msg_type(MessageType::Request)
            .payload(serde_json::json!({"action": "search", "query": "laptop"}))
            .build();

        assert_eq!(msg.version, 2);
        assert_eq!(msg.msg_type, MessageType::Request);
        assert_eq!(msg.from, from);
        assert_eq!(msg.to, to);
        assert!(!msg.is_signed());
    }

    #[test]
    fn test_message_sign_and_verify() {
        let from = Identifier::new("participant", "alice").clone();
        let to = Identifier::new("participant", "bob").clone();

        let mut msg = MessageBuilder::new(from, to)
            .payload(serde_json::json!({"action": "buy", "product_id": "12345"}))
            .build();

        let kp = Ed25519Keypair::generate();

        // Sign
        msg.sign(&kp).unwrap();
        assert!(msg.is_signed());
        assert_eq!(msg.signature_alg, Some(SignatureAlgorithm::Ed25519));
        assert!(msg.key_id.is_some());

        // Verify
        let result = msg.verify_signature(&kp.public_key());
        assert!(result.is_ok());
    }

    #[test]
    fn test_message_verify_with_wrong_key() {
        let from = Identifier::new("participant", "alice").clone();
        let to = Identifier::new("participant", "bob").clone();

        let mut msg = MessageBuilder::new(from, to)
            .payload(serde_json::json!({"action": "buy"}))
            .build();

        let kp1 = Ed25519Keypair::generate();
        let kp2 = Ed25519Keypair::generate();

        msg.sign(&kp1).unwrap();
        // Verify with wrong key should fail
        assert!(msg.verify_signature(&kp2.public_key()).is_err());
    }

    #[test]
    fn test_message_verify_tampered() {
        let from = Identifier::new("participant", "alice").clone();
        let to = Identifier::new("participant", "bob").clone();

        let mut msg = MessageBuilder::new(from, to)
            .payload(serde_json::json!({"amount": 100}))
            .build();

        let kp = Ed25519Keypair::generate();
        msg.sign(&kp).unwrap();

        // Tamper with payload
        msg.payload = serde_json::json!({"amount": 99999});

        // Verification should fail
        assert!(msg.verify_signature(&kp.public_key()).is_err());
    }

    #[test]
    fn test_unsigned_message_verify_fails() {
        let from = Identifier::new("participant", "alice").clone();
        let to = Identifier::new("participant", "bob").clone();

        let msg = MessageBuilder::new(from, to).build();
        let kp = Ed25519Keypair::generate();

        // Verifying an unsigned message should fail
        assert!(msg.verify_signature(&kp.public_key()).is_err());
    }

    #[test]
    fn test_cbor_signing_deterministic() {
        let from = Identifier::new("participant", "alice");
        let to = Identifier::new("participant", "bob");
        let msg_id = Identifier::new("message", "test-001");
        let op_id = Identifier::new("logical-operation", "test-op-001");

        let mut msg1 = MessageBuilder::new(from.clone(), to.clone())
            .id(msg_id.clone())
            .operation_id(op_id.clone())
            .payload(serde_json::json!({"action": "buy", "product_id": "12345"}))
            .build();

        let mut msg2 = MessageBuilder::new(from, to)
            .id(msg_id)
            .operation_id(op_id)
            .payload(serde_json::json!({"action": "buy", "product_id": "12345"}))
            .build();

        let kp = Ed25519Keypair::generate();
        msg1.sign(&kp).unwrap();
        msg2.sign(&kp).unwrap();
        assert_eq!(msg1.signature.unwrap().bytes, msg2.signature.unwrap().bytes);
    }

    #[test]
    fn test_cbor_canonical_bytes_deterministic() {
        let from = Identifier::new("participant", "alice");
        let to = Identifier::new("participant", "bob");
        let msg_id = Identifier::new("message", "test-002");
        let op_id = Identifier::new("logical-operation", "test-op-002");

        let msg1 = MessageBuilder::new(from.clone(), to.clone())
            .id(msg_id.clone())
            .operation_id(op_id.clone())
            .payload(serde_json::json!({"action": "search", "query": "laptop"}))
            .build();

        let msg2 = MessageBuilder::new(from, to)
            .id(msg_id)
            .operation_id(op_id)
            .payload(serde_json::json!({"action": "search", "query": "laptop"}))
            .build();

        let bytes1 = msg1.canonical_signable_bytes().unwrap();
        let bytes2 = msg2.canonical_signable_bytes().unwrap();
        assert_eq!(bytes1, bytes2, "canonical CBOR bytes must be deterministic");
    }
}
