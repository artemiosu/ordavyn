"""Ed25519 PureEdDSA cryptographic operations (BC v1.1.0 §6.1, RFC 8032).

IMPORTANT (BC v1.1.0 fix #1): Signing is PureEdDSA — message bytes are signed
DIRECTLY, with NO SHA-256 pre-hash. Ed25519 hashes internally with SHA-512.

Algorithm registry (BC v1.1.0 §3.8):
- Algorithm ID 1: Ed25519 (current default)
- Algorithm ID 2: ML-DSA-65 (reserved; not implemented)
- Algorithm ID 3: Hybrid Ed25519 + ML-DSA-65 (reserved; not implemented)
"""

import hashlib
from dataclasses import dataclass
from typing import Optional

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives import serialization
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


# Algorithm IDs (BC v1.1.0 §3.8 registry)
ALG_ED25519 = 1
ALG_ML_DSA_65 = 2
ALG_HYBRID = 3

ALGORITHM_NAMES = {
    ALG_ED25519: "ed25519",
    ALG_ML_DSA_65: "ml-dsa-65",
    ALG_HYBRID: "hybrid-ed25519-ml-dsa-65",
}

# Inherited registry hints; PQ values are unverified and not implementations.
SIGNATURE_SIZES = {
    ALG_ED25519: 64,
    ALG_ML_DSA_65: 3300,
    ALG_HYBRID: 3364,
}


class Ed25519Keypair:
    """Ed25519 keypair for signing and verification (RFC 8032 PureEdDSA)."""

    def __init__(self, private_key=None):
        """Create a new keypair. If private_key is None, generate a random one."""
        if not HAS_CRYPTO:
            raise ImportError("cryptography library required: pip install cryptography")
        if private_key is None:
            self._private_key = Ed25519PrivateKey.generate()
        else:
            self._private_key = private_key

    @classmethod
    def generate(cls) -> "Ed25519Keypair":
        """Generate a new random keypair."""
        return cls()

    def public_key_bytes(self) -> bytes:
        """Get the 32-byte public key."""
        return self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def key_id(self) -> str:
        """Get key identifier (first 8 bytes of SHA-256(public_key), hex)."""
        pk_bytes = self.public_key_bytes()
        digest = hashlib.sha256(pk_bytes).digest()
        return digest[:8].hex()

    def sign(self, message: bytes) -> bytes:
        """Sign a message using PureEdDSA (RFC 8032, direct, NO pre-hash).

        BC v1.1.0 §6.1: message bytes are signed directly.
        Ed25519 hashes internally with SHA-512.
        """
        return self._private_key.sign(message)

    @staticmethod
    def verify(public_key_bytes: bytes, message: bytes, signature: bytes) -> bool:
        """Verify a signature. Returns True if valid, False otherwise."""
        if not HAS_CRYPTO:
            raise ImportError("cryptography library required")
        try:
            public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
            public_key.verify(signature, message)
            return True
        except Exception:
            return False


def sha256_digest(data: bytes) -> bytes:
    """Compute SHA-256 digest of data."""
    return hashlib.sha256(data).digest()


def canonical_json_bytes(obj: dict) -> bytes:
    """Compatibility helper for deterministic transport JSON, never signing bytes."""
    from .wire import json_bytes
    return json_bytes(obj)
