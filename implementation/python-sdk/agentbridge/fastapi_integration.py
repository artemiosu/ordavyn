"""FastAPI integration for AgentBridge.

Makes any FastAPI service AgentBridge-ready with minimal code:

    from agentbridge import AgentBridge
    from fastapi import FastAPI

    app = FastAPI()
    bridge = AgentBridge(app)

    @bridge.expose("/search")
    def search_products(query: str):
        return {"results": [...]}

    @bridge.expose("/buy", consequential=True)
    def buy_product(product_id: str, quantity: int = 1):
        return {"order_id": "..."}

That's it. Your FastAPI service is now accessible to AI agents via AgentBridge protocol.
"""

import json
import socket
import threading
import time
from typing import Callable, Optional, Any
from functools import wraps

from .aim import Identifier, Reference, Instant
from .crypto import Ed25519Keypair
from .message import Message, MessageBuilder, MessageType
from .client import AgentBridgeClient, PROTOCOL_VERSION, VERSION_HEADER, PATH_PREFIX


class AgentBridge:
    """AgentBridge integration for FastAPI (or any Python web framework).

    Usage:
        from agentbridge import AgentBridge
        from fastapi import FastAPI

        app = FastAPI()
        bridge = AgentBridge(app)

        @bridge.expose("/search")
        def search(query: str):
            return {"results": [...]}

    This registers AgentBridge endpoints at /agentbridge/v1/search, etc.
    """

    def __init__(self, app=None, host: str = "127.0.0.1", port: int = 8080):
        """Initialize AgentBridge integration.

        Args:
            app: FastAPI/Flask app (optional — can be used standalone)
            host: Host for standalone server
            port: Port for standalone server
        """
        self.app = app
        self.host = host
        self.port = port
        self._handlers: dict[str, dict] = {}
        self._server_thread: Optional[threading.Thread] = None
        self._server_sock: Optional[socket.socket] = None
        self._running = False

    def expose(self, path: str, consequential: bool = False):
        """Decorator to expose a function as an AgentBridge endpoint.

        Args:
            path: Endpoint path (e.g., "/search" → /agentbridge/v1/search)
            consequential: If True, requires signed messages (for buy, delete, etc.)

        Usage:
            @bridge.expose("/search")
            def search(query: str):
                return {"results": [...]}

            @bridge.expose("/buy", consequential=True)
            def buy(product_id: str, quantity: int = 1):
                return {"order_id": "order-123"}
        """
        def decorator(func: Callable):
            full_path = f"{PATH_PREFIX}{path}"
            self._handlers[full_path] = {
                "func": func,
                "consequential": consequential,
                "path": path,
            }

            @wraps(func)
            def wrapper(*args, **kwargs):
                return func(*args, **kwargs)
            return wrapper
        return decorator

    def _handle_request(self, msg: Message) -> Message:
        """Handle an incoming AgentBridge message."""
        # Extract action and parameters from payload
        payload = msg.payload or {}
        action = payload.pop("action", None)

        # Find handler by path (we match on action for simplicity in prototype)
        # In production, this would be based on the HTTP path
        handler_info = None
        for path, info in self._handlers.items():
            if info["path"].lstrip("/") == action or action is None:
                handler_info = info
                break

        if handler_info is None:
            # Try matching by the endpoint path in the message
            # For prototype, we just use the first handler if only one
            if len(self._handlers) == 1:
                handler_info = list(self._handlers.values())[0]

        if handler_info is None:
            msg.msg_type = MessageType.ERROR
            msg.payload = {"error": "no_handler", "action": action}
            return msg

        # Check signature for consequential actions
        if handler_info["consequential"] and not msg.is_signed():
            msg.msg_type = MessageType.ERROR
            msg.payload = {
                "error": "unsigned_consequential_action",
                "message": f"Action '{action}' requires a signed message",
            }
            return msg

        # Call the handler function
        try:
            # Pass payload fields as kwargs
            result = handler_info["func"](**payload)

            # Build response
            msg.msg_type = MessageType.RESPONSE
            if isinstance(result, dict):
                msg.payload = result
            else:
                msg.payload = {"result": result}
        except Exception as e:
            msg.msg_type = MessageType.ERROR
            msg.payload = {"error": "handler_error", "message": str(e)}

        return msg

    def _run_server(self, ready_event: threading.Event):
        """Run the HTTP server (simple HTTP/1.1 for prototype)."""
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind((self.host, self.port))
        self._server_sock.listen(5)
        self._server_sock.settimeout(1.0)
        self._running = True
        ready_event.set()

        while self._running:
            try:
                conn, addr = self._server_sock.accept()
                self._handle_connection(conn)
            except socket.timeout:
                continue
            except OSError:
                break

    def _handle_connection(self, conn: socket.socket):
        """Handle a single HTTP connection."""
        try:
            data = conn.recv(65536).decode("utf-8")

            # Parse HTTP
            first_line = data.split("\r\n")[0]
            parts = first_line.split(" ")
            if len(parts) < 2:
                conn.close()
                return

            method, path = parts[0], parts[1]

            if method != "POST":
                conn.sendall(b"HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n")
                conn.close()
                return

            # Extract body
            body_start = data.find("\r\n\r\n") + 4
            body = data[body_start:]

            # Parse message
            msg_dict = json.loads(body)
            msg = Message.from_dict(msg_dict)

            # Find handler for this path
            handler_info = self._handlers.get(path)
            if handler_info is None:
                # Try action-based matching
                action = msg.payload.get("action", "") if msg.payload else ""
                for p, info in self._handlers.items():
                    if info["path"].lstrip("/") == action:
                        handler_info = info
                        break

            if handler_info is None:
                response_body = json.dumps({
                    "error": "not_found",
                    "path": path,
                })
                conn.sendall(f"HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: {len(response_body)}\r\nConnection: close\r\n\r\n{response_body}".encode())
                conn.close()
                return

            # Check consequential
            if handler_info["consequential"] and not msg.is_signed():
                msg.msg_type = MessageType.ERROR
                msg.payload = {"error": "unsigned_consequential_action"}
            else:
                # Call handler
                payload = msg.payload or {}
                action = payload.pop("action", None)
                try:
                    result = handler_info["func"](**payload)
                    msg.msg_type = MessageType.RESPONSE
                    msg.payload = result if isinstance(result, dict) else {"result": result}
                except Exception as e:
                    msg.msg_type = MessageType.ERROR
                    msg.payload = {"error": "handler_error", "message": str(e)}

            # Send response
            response_body = json.dumps(msg.to_dict())
            conn.sendall(f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {len(response_body)}\r\nConnection: close\r\n\r\n{response_body}".encode())
        except Exception:
            pass
        finally:
            conn.close()

    def start(self):
        """Start the AgentBridge server in background thread."""
        ready = threading.Event()
        self._server_thread = threading.Thread(target=self._run_server, args=(ready,))
        self._server_thread.daemon = True
        self._server_thread.start()
        ready.wait(timeout=5)
        print(f"  AgentBridge server running on http://{self.host}:{self.port}")
        return self

    def stop(self):
        """Stop the AgentBridge server."""
        self._running = False
        if self._server_sock:
            self._server_sock.close()
        if self._server_thread:
            self._server_thread.join(timeout=2)

    def client(self, keypair: Optional[Ed25519Keypair] = None) -> AgentBridgeClient:
        """Get a client to connect to this server."""
        c = AgentBridgeClient(self.host, self.port)
        if keypair:
            c = c.with_keypair(keypair)
        return c
