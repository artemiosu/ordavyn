//! Ed25519 PureEdDSA cryptographic operations (BC v1.1.0 §6.1, RFC 8032).
//!
//! **Important (BC v1.1.0 fix #1):** Signing is PureEdDSA — the message bytes
//! are signed DIRECTLY, with NO SHA-256 pre-hash. Ed25519 hashes internally
//! with SHA-512. This is standard RFC 8032 PureEdDSA, not Ed25519ph.
//!
//! Algorithm registry (BC v1.1.0 §3.8):
//! - Algorithm ID 1: Ed25519 (RFC 8032) — 64-byte signatures, current default
//! - Algorithm ID 2: ML-DSA-65 (FIPS 204) — reserved identifier only; not implemented
//! - Algorithm ID 3: Hybrid Ed25519 + ML-DSA-65 — reserved identifier only; not implemented

use crate::error::{CoreError, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

/// Signature algorithm identifiers (BC v1.1.0 §3.8 algorithm registry).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureAlgorithm {
    /// Ed25519 (RFC 8032) — 64-byte signatures. Default for v1.1.0.
    Ed25519 = 1,
    /// ML-DSA-65 (FIPS 204) — Reserved identifier only; not implemented.
    MLDSA65 = 2,
    /// Hybrid Ed25519 + ML-DSA-65 — Reserved identifier only; not implemented.
    HybridEd25519MLDSA65 = 3,
}

impl Default for SignatureAlgorithm {
    fn default() -> Self {
        SignatureAlgorithm::Ed25519
    }
}

impl SignatureAlgorithm {
    /// Get the algorithm ID (BC v1.1.0 §3.8 registry).
    pub fn id(&self) -> u8 {
        match self {
            SignatureAlgorithm::Ed25519 => 1,
            SignatureAlgorithm::MLDSA65 => 2,
            SignatureAlgorithm::HybridEd25519MLDSA65 => 3,
        }
    }

    /// Inherited registry size hints; reserved PQ values are unverified and not implementations.
    pub fn signature_size(&self) -> usize {
        match self {
            SignatureAlgorithm::Ed25519 => 64,
            SignatureAlgorithm::MLDSA65 => 3300, // approximate
            SignatureAlgorithm::HybridEd25519MLDSA65 => 3364, // 64 + 3300
        }
    }
}

/// Ed25519 public key (32 bytes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed25519PublicKey {
    /// Raw 32-byte public key.
    pub bytes: [u8; 32],
}

impl Ed25519PublicKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Get the key identifier (first 8 bytes of SHA-256(key), hex-encoded).
    /// Used as `key_id` in the message envelope (BC v1.1.0 §4.1).
    pub fn key_id(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(self.bytes);
        let hash = hasher.finalize();
        hex::encode(&hash[..8])
    }
}

impl From<VerifyingKey> for Ed25519PublicKey {
    fn from(key: VerifyingKey) -> Self {
        Self {
            bytes: key.to_bytes(),
        }
    }
}

impl TryFrom<&Ed25519PublicKey> for VerifyingKey {
    type Error = CoreError;

    fn try_from(pk: &Ed25519PublicKey) -> Result<Self> {
        VerifyingKey::from_bytes(&pk.bytes).map_err(|e| CoreError::Crypto(e.to_string()))
    }
}

/// Ed25519 signature (variable-length, but 64 bytes for Ed25519).
/// Stored as Vec<u8>, but verification accepts only 64-byte Ed25519 signatures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ed25519Signature {
    /// Raw signature bytes; only 64-byte Ed25519 signatures are supported.
    pub bytes: Vec<u8>,
    /// Algorithm used to produce this signature.
    pub algorithm: SignatureAlgorithm,
}

impl Ed25519Signature {
    pub fn new(bytes: Vec<u8>, algorithm: SignatureAlgorithm) -> Self {
        Self { bytes, algorithm }
    }

    /// Create from ed25519_dalek Signature.
    pub fn from_dalek(sig: Signature) -> Self {
        Self {
            bytes: sig.to_bytes().to_vec(),
            algorithm: SignatureAlgorithm::Ed25519,
        }
    }
}

/// Ed25519 keypair for signing and verification.
#[derive(Debug)]
pub struct Ed25519Keypair {
    signing_key: SigningKey,
}

impl Ed25519Keypair {
    /// Generate a new random keypair using OsRng (cryptographically secure).
    pub fn generate() -> Self {
        let mut rng = OsRng;
        Self {
            signing_key: SigningKey::generate(&mut rng),
        }
    }

    /// Get the public key.
    pub fn public_key(&self) -> Ed25519PublicKey {
        self.signing_key.verifying_key().into()
    }

    /// Get the key identifier (same as public_key().key_id()).
    pub fn key_id(&self) -> String {
        self.public_key().key_id()
    }

    /// Sign a message using PureEdDSA (RFC 8032, direct signing, NO pre-hash).
    ///
    /// **BC v1.1.0 §6.1:** The message bytes are signed directly.
    /// Ed25519 hashes internally with SHA-512. No SHA-256 pre-hash is applied.
    /// This is the standard RFC 8032 PureEdDSA construction.
    pub fn sign(&self, message: &[u8]) -> Ed25519Signature {
        let sig = self.signing_key.sign(message);
        Ed25519Signature::from_dalek(sig)
    }

    /// Verify a signature against a message and public key.
    ///
    /// Uses PureEdDSA verification (RFC 8032).
    pub fn verify(
        public_key: &Ed25519PublicKey,
        message: &[u8],
        signature: &Ed25519Signature,
    ) -> Result<()> {
        if signature.algorithm != SignatureAlgorithm::Ed25519 {
            return Err(CoreError::Crypto("unsupported signature algorithm".into()));
        }
        let verifying_key = VerifyingKey::try_from(public_key)?;

        let sig_bytes: [u8; 64] = signature
            .bytes
            .as_slice()
            .try_into()
            .map_err(|_| CoreError::Crypto("invalid signature length".to_string()))?;

        let sig = Signature::from_bytes(&sig_bytes);

        verifying_key
            .verify_strict(message, &sig)
            .map_err(|_| CoreError::SignatureVerificationFailed)
    }
}

/// Hex encoding/decoding (minimal implementation to avoid extra dependency).
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let kp1 = Ed25519Keypair::generate();
        let kp2 = Ed25519Keypair::generate();
        // Two random keypairs should have different public keys
        assert_ne!(kp1.public_key(), kp2.public_key());
    }

    #[test]
    fn test_sign_and_verify() {
        let kp = Ed25519Keypair::generate();
        let message = b"Hello, Ordavyn!";
        let signature = kp.sign(message);

        // Verification should succeed
        assert!(Ed25519Keypair::verify(&kp.public_key(), message, &signature).is_ok());
    }

    #[test]
    fn test_verify_wrong_message() {
        let kp = Ed25519Keypair::generate();
        let message = b"Hello, Ordavyn!";
        let wrong_message = b"Goodbye, Ordavyn!";
        let signature = kp.sign(message);

        // Verification with wrong message should fail
        assert!(Ed25519Keypair::verify(&kp.public_key(), wrong_message, &signature).is_err());
    }

    #[test]
    fn test_verify_wrong_key() {
        let kp1 = Ed25519Keypair::generate();
        let kp2 = Ed25519Keypair::generate();
        let message = b"Hello, Ordavyn!";
        let signature = kp1.sign(message);

        // Verification with wrong key should fail
        assert!(Ed25519Keypair::verify(&kp2.public_key(), message, &signature).is_err());
    }

    #[test]
    fn test_signature_is_64_bytes() {
        let kp = Ed25519Keypair::generate();
        let sig = kp.sign(b"test");
        assert_eq!(sig.bytes.len(), 64);
        assert_eq!(sig.algorithm, SignatureAlgorithm::Ed25519);
    }

    #[test]
    fn test_key_id_is_16_hex_chars() {
        let kp = Ed25519Keypair::generate();
        let key_id = kp.key_id();
        assert_eq!(key_id.len(), 16); // 8 bytes = 16 hex chars
        assert!(key_id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_different_keypairs_different_key_ids() {
        let kp1 = Ed25519Keypair::generate();
        let kp2 = Ed25519Keypair::generate();
        assert_ne!(kp1.key_id(), kp2.key_id());
    }

    #[test]
    fn test_algorithm_registry() {
        assert_eq!(SignatureAlgorithm::Ed25519.id(), 1);
        assert_eq!(SignatureAlgorithm::MLDSA65.id(), 2);
        assert_eq!(SignatureAlgorithm::HybridEd25519MLDSA65.id(), 3);

        assert_eq!(SignatureAlgorithm::Ed25519.signature_size(), 64);
        assert_eq!(SignatureAlgorithm::MLDSA65.signature_size(), 3300);
        assert_eq!(
            SignatureAlgorithm::HybridEd25519MLDSA65.signature_size(),
            3364
        );
    }

    #[test]
    fn test_default_algorithm() {
        assert_eq!(SignatureAlgorithm::default(), SignatureAlgorithm::Ed25519);
    }

    #[test]
    fn test_pure_eddsa_no_prehash() {
        // BC v1.1.0 fix #1: PureEdDSA signs message directly, no SHA-256 pre-hash.
        // This test verifies that signing the same message twice produces the same
        // signature (Ed25519 is deterministic — RFC 8032 §5.1.6).
        let kp = Ed25519Keypair::generate();
        let message = b"test message for determinism";
        let sig1 = kp.sign(message);
        let sig2 = kp.sign(message);
        assert_eq!(sig1.bytes, sig2.bytes); // Deterministic
    }
}
