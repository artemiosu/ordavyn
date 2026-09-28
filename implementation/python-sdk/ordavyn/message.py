"""Local Ordavyn message envelope with Ed25519-authenticated metadata.

Python signs domain-separated deterministic CBOR v3; transport is JSON.
"""

import time
import uuid
import hashlib
from dataclasses import dataclass, field
from typing import Optional, Any

from .aim import Identifier, Reference, Instant
from .crypto import Ed25519Keypair, ALG_ED25519
from .wire import ENCODING, json_bytes, signable_bytes, validate_envelope


class MessageType:
    """Message type (BC v1.1.0 §4.1)."""
    REQUEST = "request"
    RESPONSE = "response"
    EVENT = "event"
    ERROR = "error"


@dataclass
class Message:
    """Local envelope; only Ed25519 and the fixed CBOR v3 signing format are supported."""
    version: int = 3
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
    encoding: str = ENCODING

    reply_to: Optional[Identifier] = None
    request_digest: Optional[str] = None

    def is_signed(self) -> bool:
        return self.signature is not None

    def sign(self, keypair: Ed25519Keypair) -> None:
        """Sign this message with an Ed25519 keypair.

        Uses PureEdDSA (RFC 8032, direct signing, NO pre-hash).
        Signs the canonical CBOR encoding of the signable fields.
        """
        import copy
        candidate = copy.copy(self)
        candidate.signature_alg = ALG_ED25519
        candidate.key_id = keypair.key_id()
        candidate.signature = None
        candidate.signature = keypair.sign(candidate._signable_bytes()).hex()
        validate_envelope(candidate._raw_dict())
        self.signature_alg = candidate.signature_alg
        self.key_id = candidate.key_id
        self.signature = candidate.signature

    def verify_signature(self, public_key_bytes: bytes) -> bool:
        """Verify this message's signature."""
        try:
            if (self.signature_alg != ALG_ED25519 or type(self.signature_alg) is not int
                    or self.encoding != ENCODING or not isinstance(self.signature, str)
                    or len(self.signature) != 128
                    or self.key_id != hashlib.sha256(public_key_bytes).digest()[:8].hex()):
                return False
            return Ed25519Keypair.verify(public_key_bytes, self._signable_bytes(), bytes.fromhex(self.signature))
        except (ValueError, TypeError, OverflowError):
            return False

    def _signable_bytes(self) -> bytes:
        """Get canonical bytes that are signed (message without the signature value)."""
        return signable_bytes(self._raw_dict())

    def _raw_dict(self) -> dict:
        """Serialize message to dict for JSON transport."""
        d = {
            "version": self.version,
            "reply_to": self.reply_to.to_dict() if self.reply_to is not None else None,
            "request_digest": self.request_digest,
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
        d.update(signature_alg=self.signature_alg, key_id=self.key_id, signature=self.signature)
        return d

    def to_dict(self) -> dict:
        d = self._raw_dict()
        validate_envelope(d)
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Message":
        """Deserialize message from dict."""
        validate_envelope(d)
        msg = cls(
            version=d["version"],
            reply_to=Identifier.from_dict(d["reply_to"]) if d["reply_to"] is not None else None,
            request_digest=d["request_digest"],
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
        return json_bytes(self.to_dict()).decode("utf-8")


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
