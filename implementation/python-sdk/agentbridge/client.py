"""HTTP client for AgentBridge (BC v1.1.0 §3.2, §4.2).

Simple HTTP/1.1 client for prototype. Production will use HTTP/2 with httpx.
localhost only per AB-PROTO-001 AD-21.
"""

import json
import socket
from typing import Optional

from .message import Message
from .crypto import Ed25519Keypair


PROTOCOL_VERSION = 1
VERSION_HEADER = "x-agentbridge-version"
PATH_PREFIX = "/agentbridge/v1"
CONTENT_TYPE = "application/json"


class AgentBridgeClient:
    """Simple HTTP client for AgentBridge (prototype).

    Production will use HTTP/2 with httpx. For prototype, HTTP/1.1 on localhost.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 8080):
        self.host = host
        self.port = port
        self._keypair: Optional[Ed25519Keypair] = None

    def with_keypair(self, keypair: Ed25519Keypair) -> "AgentBridgeClient":
        """Set the Ed25519 keypair for signing messages."""
        self._keypair = keypair
        return self

    def send(self, endpoint: str, msg: Message, sign: bool = True) -> Message:
        """Send a message to a specific endpoint and get the response.

        Args:
            endpoint: Path after /agentbridge/v1/ (e.g., "/binding")
            msg: Message to send
            sign: If True and keypair is set, sign the message before sending

        Returns:
            Response message from server
        """
        # Sign if keypair is available
        if sign and self._keypair is not None and not msg.is_signed():
            msg.sign(self._keypair)

        # Serialize message
        body = msg.to_json()
        path = f"{PATH_PREFIX}{endpoint}"

        # Build HTTP request
        request = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            f"Content-Type: {CONTENT_TYPE}\r\n"
            f"{VERSION_HEADER}: {PROTOCOL_VERSION}\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"{body}"
        )

        # Connect and send
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.host, self.port))
            s.sendall(request.encode("utf-8"))

            # Read response
            response_data = b""
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                response_data += chunk

        # Parse response
        response_str = response_data.decode("utf-8")
        body_start = response_str.find("\r\n\r\n")
        if body_start == -1:
            raise ValueError("invalid HTTP response: no body separator")

        response_body = response_str[body_start + 4:]
        response_dict = json.loads(response_body)
        return Message.from_dict(response_dict)
