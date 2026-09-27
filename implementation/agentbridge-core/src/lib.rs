//! AgentBridge Core Library
//!
//! This crate implements the foundational types and operations for the AgentBridge protocol,
//! based on the AA-2 Abstract Information Model (AIM) and AA-4 Binding Contract (BC v1.1.0).
//!
//! # Key components
//!
//! - [`aim`] — AIM primitive types: `Identifier`, `Reference`, `Instant`, `Duration`, `WallclockInstant`
//! - [`cbor_tags`] — CBOR tag assignments for AgentBridge types (RFC 8949)
//! - [`crypto`] — Ed25519 PureEdDSA signing (RFC 8032, direct signing, no pre-hash)
//! - [`message`] — COSE-style message envelope (PQ-ready, variable-length signatures)
//! - [`error`] — Error types
//!
//! # References
//!
//! - AIM v1.0.1: Abstract Information Model
//! - BC v1.1.0: Binding Contract (Rust, HTTP/2, CBOR, Ed25519, SHA-256, TLS 1.3)

pub mod aim;
pub mod cbor_encoding;
pub mod cbor_tags;
pub mod crypto;
pub mod error;
pub mod message;
pub mod transport;

pub use aim::{
    Duration, Identifier, Instant, Reference, ValueState, WallclockInstant,
};
pub use crypto::{Ed25519Keypair, Ed25519PublicKey, Ed25519Signature, SignatureAlgorithm};
pub use error::{CoreError, Result};
pub use message::{Message, MessageBuilder, MessageType};
