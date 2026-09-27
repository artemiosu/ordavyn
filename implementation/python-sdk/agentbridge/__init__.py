"""AgentBridge Python SDK

Protocol for safe, efficient, standardized interaction in the future internet.

Based on:
- AIM v1.0.1: Abstract Information Model
- BC v1.1.0: Binding Contract (HTTP/2, CBOR+JSON, Ed25519, SHA-256, TLS 1.3)
"""

from .aim import Identifier, Reference, Instant, Duration, WallclockInstant, ValueState
from .crypto import Ed25519Keypair, sha256_digest, ALG_ED25519
from .message import Message, MessageBuilder, MessageType
from .client import AgentBridgeClient
from .fastapi_integration import AgentBridge

__version__ = "0.1.0"

__all__ = [
    "AgentBridge",
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
    "AgentBridgeClient",
]
