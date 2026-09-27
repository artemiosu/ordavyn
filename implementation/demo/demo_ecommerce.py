#!/usr/bin/env python3
"""Mock AgentBridge E-Commerce Demo

This demo shows a complete AgentBridge interaction:
1. Mock e-commerce service starts (sells products)
2. Mock agent connects and searches for a product
3. Agent buys the product (consequential action — signed)
4. Service confirms the purchase
5. All communication uses AgentBridge protocol with Ed25519 signatures

Per AB-PROTO-001 AD-21: localhost only, synthetic data, no external effects.
"""

import sys
import os
import json
import time
import threading
import socket

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "python-sdk"))

from agentbridge import (
    Identifier, Reference, Instant, Duration,
    Ed25519Keypair, Message, MessageBuilder, MessageType,
)
from agentbridge.client import AgentBridgeClient

# ============================================================================
# Mock E-Commerce Service
# ============================================================================

# Synthetic product catalog (AB-PROTO-001: synthetic data only)
PRODUCTS = [
    {"id": "laptop-001", "name": "ProBook 15", "price": 999.99, "currency": "USD", "stock": 5},
    {"id": "phone-002", "name": "Galaxy S25", "price": 799.99, "currency": "USD", "stock": 10},
    {"id": "headphones-003", "name": "AirPods Pro 3", "price": 249.99, "currency": "USD", "stock": 20},
    {"id": "watch-004", "name": "Apple Watch Ultra 3", "price": 799.00, "currency": "USD", "stock": 3},
]

# In-memory order store (ephemeral, no persistence)
ORDERS = {}


def handle_search(msg: Message) -> Message:
    """Handle product search requests."""
    query = msg.payload.get("query", "").lower()
    results = [p for p in PRODUCTS if query in p["name"].lower() or query in p["id"].lower()]

    response = msg
    response.msg_type = MessageType.RESPONSE
    response.payload = {
        "action": "search_results",
        "query": msg.payload.get("query"),
        "results": results,
        "count": len(results),
    }
    return response


def handle_buy(msg: Message) -> Message:
    """Handle purchase requests (consequential action — signed message expected)."""
    product_id = msg.payload.get("product_id")
    quantity = msg.payload.get("quantity", 1)

    # Find product
    product = next((p for p in PRODUCTS if p["id"] == product_id), None)
    if product is None:
        response = msg
        response.msg_type = MessageType.ERROR
        response.payload = {
            "error": "product_not_found",
            "product_id": product_id,
        }
        return response

    # Check stock
    if product["stock"] < quantity:
        response = msg
        response.msg_type = MessageType.ERROR
        response.payload = {
            "error": "insufficient_stock",
            "product_id": product_id,
            "requested": quantity,
            "available": product["stock"],
        }
        return response

    # Check signature (consequential action requires signed message)
    if not msg.is_signed():
        response = msg
        response.msg_type = MessageType.ERROR
        response.payload = {
            "error": "unsigned_consequential_action",
            "message": "Purchase requires a signed message",
        }
        return response

    # Process purchase
    product["stock"] -= quantity
    order_id = f"order-{len(ORDERS) + 1:04d}"
    total = product["price"] * quantity

    order = {
        "order_id": order_id,
        "product_id": product_id,
        "product_name": product["name"],
        "quantity": quantity,
        "total": total,
        "currency": product["currency"],
        "status": "confirmed",
        "timestamp": int(time.time()),
    }
    ORDERS[order_id] = order

    response = msg
    response.msg_type = MessageType.RESPONSE
    response.payload = {
        "action": "purchase_confirmed",
        "order": order,
    }
    return response


def handle_get_order(msg: Message) -> Message:
    """Handle order status requests."""
    order_id = msg.payload.get("order_id")
    order = ORDERS.get(order_id)

    response = msg
    response.msg_type = MessageType.RESPONSE
    if order:
        response.payload = {"action": "order_status", "order": order}
    else:
        response.msg_type = MessageType.ERROR
        response.payload = {"error": "order_not_found", "order_id": order_id}
    return response


# ============================================================================
# Simple HTTP Server (inline, no external deps)
# ============================================================================

def run_server(host: str, port: int, ready_event: threading.Event):
    """Run a simple HTTP server with AgentBridge handlers."""
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((host, port))
    server_sock.listen(5)
    server_sock.settimeout(10)

    ready_event.set()
    print(f"  [SERVICE] Mock e-commerce service running on http://{host}:{port}")

    handlers = {
        "/agentbridge/v1/search": handle_search,
        "/agentbridge/v1/buy": handle_buy,
        "/agentbridge/v1/order": handle_get_order,
    }

    # Handle 3 requests (search, buy, get_order)
    for i in range(3):
        try:
            conn, addr = server_sock.accept()
            data = conn.recv(65536).decode("utf-8")

            # Parse HTTP
            first_line = data.split("\r\n")[0]
            method, path, _ = first_line.split(" ", 2)
            body_start = data.find("\r\n\r\n") + 4
            body = data[body_start:]

            # Find handler
            handler = handlers.get(path)
            if handler is None:
                response_body = json.dumps({"error": "not_found", "path": path})
                conn.sendall(f"HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: {len(response_body)}\r\nConnection: close\r\n\r\n{response_body}".encode())
                conn.close()
                continue

            # Parse and handle message
            msg_dict = json.loads(body)
            msg = Message.from_dict(msg_dict)
            response_msg = handler(msg)
            response_body = json.dumps(response_msg.to_dict())

            conn.sendall(f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {len(response_body)}\r\nConnection: close\r\n\r\n{response_body}".encode())
            conn.close()

        except socket.timeout:
            break
        except Exception as e:
            print(f"  [SERVICE] Error: {e}")
            break

    server_sock.close()
    print("  [SERVICE] Mock e-commerce service stopped.")


# ============================================================================
# Mock Agent
# ============================================================================

def run_agent(host: str, port: int):
    """Run the mock agent that searches and buys a product."""
    print("\n  [AGENT] Starting mock agent...")

    # Generate agent's Ed25519 keypair
    kp = Ed25519Keypair.generate()
    print(f"  [AGENT] Generated Ed25519 keypair (key_id: {kp.key_id()})")

    # Create AgentBridge client
    client = AgentBridgeClient(host=host, port=port).with_keypair(kp)

    agent_id = Identifier("participant", "agent-001")
    service_id = Identifier("participant", "shop-service-001")

    # Step 1: Search for a product
    print("\n  [AGENT] Step 1: Searching for 'laptop'...")
    search_msg = (MessageBuilder(agent_id, service_id)
                  .id(Identifier("message", "search-001"))
                  .operation_id(Identifier("logical-operation", "search-op-001"))
                  .payload({"action": "search", "query": "laptop"})
                  .build())

    response = client.send("/search", search_msg, sign=True)

    results = response.payload.get("results", [])
    print(f"  [AGENT] Found {len(results)} product(s):")
    for p in results:
        print(f"         - {p['name']} (${p['price']}) [stock: {p['stock']}]")

    if not results:
        print("  [AGENT] No products found. Demo failed.")
        return False

    # Step 2: Buy the first product (consequential action — MUST be signed)
    product = results[0]
    print(f"\n  [AGENT] Step 2: Buying {product['name']} (${product['price']})...")

    buy_msg = (MessageBuilder(agent_id, service_id)
               .id(Identifier("message", "buy-001"))
               .operation_id(Identifier("logical-operation", "buy-op-001"))
               .payload({"action": "buy", "product_id": product["id"], "quantity": 1})
               .build())

    response = client.send("/buy", buy_msg, sign=True)

    if response.msg_type == MessageType.ERROR:
        print(f"  [AGENT] Purchase FAILED: {response.payload}")
        return False

    order = response.payload.get("order", {})
    order_id = order.get("order_id")
    total = order.get("total")
    print(f"  [AGENT] Purchase CONFIRMED!")
    print(f"         Order ID: {order_id}")
    print(f"         Total: ${total:.2f}")
    print(f"         Status: {order.get('status')}")

    # Step 3: Verify order status
    print(f"\n  [AGENT] Step 3: Verifying order {order_id}...")
    verify_msg = (MessageBuilder(agent_id, service_id)
                  .id(Identifier("message", "verify-001"))
                  .operation_id(Identifier("logical-operation", "verify-op-001"))
                  .payload({"action": "get_order", "order_id": order_id})
                  .build())

    response = client.send("/order", verify_msg, sign=True)

    verified_order = response.payload.get("order", {})
    print(f"  [AGENT] Order verified: {verified_order.get('status', 'unknown')}")

    return True


# ============================================================================
# Main demo runner
# ============================================================================

def main():
    print("=" * 70)
    print("  AgentBridge E-Commerce Demo")
    print("  Protocol for safe, efficient, standardized interaction")
    print("=" * 70)
    print()
    print("  This demo shows:")
    print("  1. Agent searches for a product via AgentBridge protocol")
    print("  2. Agent buys the product (consequential action, Ed25519 signed)")
    print("  3. Agent verifies the order status")
    print()
    print("  All communication uses:")
    print("  - AgentBridge message envelope (COSE-style, PQ-ready)")
    print("  - Ed25519 PureEdDSA signatures (RFC 8032, no pre-hash)")
    print("  - Canonical JSON encoding (deterministic)")
    print()

    HOST = "127.0.0.1"
    PORT = 18090

    # Start server in background
    ready = threading.Event()
    server_thread = threading.Thread(target=run_server, args=(HOST, PORT, ready))
    server_thread.daemon = True
    server_thread.start()

    # Wait for server to be ready
    ready.wait(timeout=5)
    time.sleep(0.2)

    # Run agent
    success = run_agent(HOST, PORT)

    # Wait for server to finish
    server_thread.join(timeout=5)

    print()
    print("=" * 70)
    if success:
        print("  ✅ Demo SUCCESS! Agent successfully purchased a product via AgentBridge.")
    else:
        print("  ❌ Demo FAILED. Check output above for errors.")
    print("=" * 70)

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
