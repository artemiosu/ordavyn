//! Ordavyn local protocol primitives and protected loopback HTTP/1.1 transport.
//! Native, role-neutral prototype; TLS, delegation, negotiation and PQ are not implemented.

pub mod aim;
pub mod cbor_encoding;
pub mod cbor_tags;
pub mod crypto;
pub mod error;
pub mod message;
pub mod transport;

pub use aim::{Duration, Identifier, Instant, Reference, ValueState, WallclockInstant};
pub use crypto::{Ed25519Keypair, Ed25519PublicKey, Ed25519Signature, SignatureAlgorithm};
pub use error::{CoreError, Result};
pub use message::{Message, MessageBuilder, MessageType};

pub mod security;

mod json;

pub mod wire;
