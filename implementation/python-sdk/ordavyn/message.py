"""Local Ordavyn message envelope with Ed25519-authenticated metadata.

Python signs deterministic JSON; no COSE encoding, PQ or negotiation is implemented.
"""

import json
import time
import uuid
import hashlib
from dataclasses import dataclass, field
from typing import Optional, Any

from .aim import Identifier, Reference, Instant
from .crypto import Ed25519Keypair, canonical_json_bytes, ALG_ED25519


class MessageType:
    """Message type (BC v1.1.0 §4.1)."""
    REQUEST = "request"
    RESPONSE = "response"
    EVENT = "event"
    ERROR = "error"


@dataclass
class Message:
    """Local envelope; only Ed25519 and the fixed JSON signing format are supported."""
    version: int = 1
    msg_type: str = MessageType.REQUEST
    id: Identifier = field(default_factory=lambda: Identifier("message", "placeholder"))
    operation_id: Identifier = field(default_factory=lambda: Identifier("logical-operation", "placeholder"))
    subject: Reference = field(default_factory=lambda: Reference("DecisionSubject", Identifier("decision-subject", "placeholder")))
    from_id: Identifier = field(default_factory=lambda: Identifier("participant", "placeholder"))
    to_id: Identifier = field(default_factory=lambda: Identifier("participant", "placeholder"))
    epoch: Identifier = field(default_factory=lambda: Identifier("epoch", "current"))
    payload: Any = None
    signature_alg: Optional[int] = None
    key_id: Optional[str] = None
    signature: Optional[str] = None  # hex-encoded
    timestamp: Instant = field(default_factory=lambda: Instant(nanos=0))
    encoding: str = "json"

    def is_signed(self) -> bool:
        return self.signature is not None

    def sign(self, keypair: Ed25519Keypair) -> None:
        """Sign this message with an Ed25519 keypair.

        Uses PureEdDSA (RFC 8032, direct signing, NO pre-hash).
        Signs the canonical JSON encoding of the signable fields.
        """
        self.signature_alg = ALG_ED25519
        self.key_id = keypair.key_id()
        signable = self._signable_bytes()
        sig_bytes = keypair.sign(signable)
        self.signature = sig_bytes.hex()

    def verify_signature(self, public_key_bytes: bytes) -> bool:
        """Verify this message's signature."""
        try:
            if (self.signature_alg != ALG_ED25519 or type(self.signature_alg) is not int
                    or self.encoding != "json" or not isinstance(self.signature, str)
                    or len(self.signature) != 128
                    or self.key_id != hashlib.sha256(public_key_bytes).digest()[:8].hex()):
                return False
            return Ed25519Keypair.verify(public_key_bytes, self._signable_bytes(), bytes.fromhex(self.signature))
        except (ValueError, TypeError, OverflowError):
            return False

    def _signable_bytes(self) -> bytes:
        """Get canonical bytes that are signed (message without the signature value)."""
        signable = {
            "version": self.version,
            "signature_alg": self.signature_alg,
            "key_id": self.key_id,
            "encoding": self.encoding,
            "type": self.msg_type,
            "id": self.id.to_dict(),
            "operation_id": self.operation_id.to_dict(),
            "subject": self.subject.to_dict(),
            "from": self.from_id.to_dict(),
            "to": self.to_id.to_dict(),
            "epoch": self.epoch.to_dict(),
            "payload": self.payload,
            "timestamp": self.timestamp.to_dict(),
        }
        return canonical_json_bytes(signable)

    def to_dict(self) -> dict:
        """Serialize message to dict for JSON transport."""
        d = {
            "version": self.version,
            "type": self.msg_type,
            "id": self.id.to_dict(),
            "operation_id": self.operation_id.to_dict(),
            "subject": self.subject.to_dict(),
            "from": self.from_id.to_dict(),
            "to": self.to_id.to_dict(),
            "epoch": self.epoch.to_dict(),
            "payload": self.payload,
            "timestamp": self.timestamp.to_dict(),
            "encoding": self.encoding,
        }
        if self.signature_alg is not None:
            d["signature_alg"] = self.signature_alg
        if self.key_id is not None:
            d["key_id"] = self.key_id
        if self.signature is not None:
            d["signature"] = self.signature
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Message":
        """Deserialize message from dict."""
        required = {"version", "type", "id", "operation_id", "subject", "from", "to", "epoch", "payload", "timestamp", "encoding"}
        if not isinstance(d, dict) or not required <= d.keys() or d.keys() - required - {"signature_alg", "key_id", "signature"}:
            raise ValueError("invalid envelope fields")
        if (type(d['version']) is not int or d['version'] != 1
                or type(d['type']) is not str or d['type'] not in ('request', 'response', 'event', 'error')
                or d['encoding'] != 'json'
                or (d.get('signature_alg') is not None and type(d['signature_alg']) is not int)
                or (d.get('key_id') is not None and type(d['key_id']) is not str)
                or (d.get('signature') is not None and type(d['signature']) is not str)):
            raise ValueError("invalid envelope metadata")
        canonical_json_bytes(d)
        msg = cls(
            version=d["version"],
            msg_type=d["type"],
            id=Identifier.from_dict(d["id"]),
            operation_id=Identifier.from_dict(d["operation_id"]),
            subject=Reference.from_dict(d["subject"]),
            from_id=Identifier.from_dict(d["from"]),
            to_id=Identifier.from_dict(d["to"]),
            epoch=Identifier.from_dict(d["epoch"]),
            payload=d.get("payload"),
            timestamp=Instant.from_dict(d.get("timestamp", {"nanos": 0})),
            encoding=d["encoding"],
        )
        if "signature_alg" in d:
            msg.signature_alg = d["signature_alg"]
        if "key_id" in d:
            msg.key_id = d["key_id"]
        if "signature" in d:
            msg.signature = d["signature"]
        for ident, namespace in ((msg.id, 'message'), (msg.operation_id, 'logical-operation'),
                                 (msg.from_id, 'participant'), (msg.to_id, 'participant'), (msg.epoch, 'epoch')):
            if ident.namespace != namespace:
                raise ValueError("invalid envelope identifier namespace")
        return msg

    def to_json(self) -> str:
        """Serialize to JSON string."""
        return canonical_json_bytes(self.to_dict()).decode("utf-8")


class MessageBuilder:
    """Builder for constructing messages."""

    def __init__(self, from_id: Identifier, to_id: Identifier):
        self._msg = Message(
            from_id=from_id,
            to_id=to_id,
            id=Identifier("message", f"id-{uuid.uuid4().hex}"),
            operation_id=Identifier("logical-operation", f"op-{uuid.uuid4().hex}"),
            timestamp=Instant(nanos=int(time.time() * 1e9)),
        )

    def msg_type(self, t: str) -> "MessageBuilder":
        self._msg.msg_type = t
        return self

    def id(self, id: Identifier) -> "MessageBuilder":
        self._msg.id = id
        return self

    def operation_id(self, id: Identifier) -> "MessageBuilder":
        self._msg.operation_id = id
        return self

    def subject(self, subject: Reference) -> "MessageBuilder":
        self._msg.subject = subject
        return self

    def epoch(self, epoch: Identifier) -> "MessageBuilder":
        self._msg.epoch = epoch
        return self

    def payload(self, payload: Any) -> "MessageBuilder":
        self._msg.payload = payload
        return self

    def timestamp(self, ts: Instant) -> "MessageBuilder":
        self._msg.timestamp = ts
        return self

    def build(self) -> Message:
        return self._msg
