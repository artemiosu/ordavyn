"""Ordavyn local SDK: authenticated requests, explicit local grants, selectable local replay protection.

HTTP/1.1 loopback only. No TLS, delegation, negotiation or PQ implementation.
"""

from .aim import Identifier, Reference, Instant, Duration, WallclockInstant, ValueState
from .crypto import Ed25519Keypair, sha256_digest, ALG_ED25519
from .message import Message, MessageBuilder, MessageType
from .client import OrdavynClient
from .server import Ordavyn
from .journal import MemoryJournal, SQLiteJournal, JournalError

__version__ = "0.1.0"

__all__ = [
    "Ordavyn",
    "MemoryJournal",
    "SQLiteJournal",
    "JournalError",
    "Identifier",
    "Reference",
    "Instant",
    "Duration",
    "WallclockInstant",
    "ValueState",
    "Ed25519Keypair",
    "sha256_digest",
    "ALG_ED25519",
    "Message",
    "MessageBuilder",
    "MessageType",
    "OrdavynClient",
]
