#!/usr/bin/env python3
"""AgentBridge Multi-Demo: E-Commerce + Booking + Search

Shows AgentBridge working across 3 different domains using the
FastAPI-style @bridge.expose() decorator.

Run: python3 demo/demo_multi.py
"""

import sys
import os
import time
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "python-sdk"))

from agentbridge import (
    AgentBridge, AgentBridgeClient, Ed25519Keypair,
    Identifier, MessageBuilder, MessageType,
)

# ============================================================================
# Service 1: E-Commerce (search + buy)
# ============================================================================

PRODUCTS = [
    {"id": "laptop-001", "name": "ProBook 15 Laptop", "price": 999.99, "stock": 5},
    {"id": "phone-002", "name": "Galaxy S25 Phone", "price": 799.99, "stock": 10},
]

shop = AgentBridge(host="127.0.0.1", port=18091)

@shop.expose("/search")
def search_products(query: str):
    results = [p for p in PRODUCTS if query.lower() in p["name"].lower()]
    return {"results": results, "count": len(results)}

@shop.expose("/buy", consequential=True)
def buy_product(product_id: str, quantity: int = 1):
    product = next((p for p in PRODUCTS if p["id"] == product_id), None)
    if not product:
        return {"error": "not_found", "product_id": product_id}
    if product["stock"] < quantity:
        return {"error": "out_of_stock", "available": product["stock"]}
    product["stock"] -= quantity
    return {
        "order_id": f"order-{int(time.time())}",
        "product": product["name"],
        "total": product["price"] * quantity,
        "status": "confirmed",
    }


# ============================================================================
# Service 2: Hotel Booking (search + book)
# ============================================================================

HOTELS = [
    {"id": "h1", "name": "Grand Hotel Tokyo", "price": 250, "rooms": 3},
    {"id": "h2", "name": "Park Hyatt Tokyo", "price": 400, "rooms": 2},
]

hotel = AgentBridge(host="127.0.0.1", port=18092)

@hotel.expose("/search")
def search_hotels(city: str = "Tokyo", guests: int = 1):
    results = [h for h in HOTELS if h["rooms"] >= 1]
    return {"hotels": results, "city": city}

@hotel.expose("/book", consequential=True)
def book_hotel(hotel_id: str, checkin: str, checkout: str, guests: int = 1):
    h = next((h for h in HOTELS if h["id"] == hotel_id), None)
    if not h:
        return {"error": "not_found"}
    if h["rooms"] < 1:
        return {"error": "no_rooms"}
    h["rooms"] -= 1
    return {
        "booking_id": f"booking-{int(time.time())}",
        "hotel": h["name"],
        "checkin": checkin,
        "checkout": checkout,
        "total": h["price"],
        "status": "confirmed",
    }


# ============================================================================
# Service 3: Knowledge Search (search only)
# ============================================================================

KNOWLEDGE = [
    {"topic": "rust", "title": "Why Rust is great for protocols", "url": "https://rust-lang.org"},
    {"topic": "agents", "title": "Building AI agents with AgentBridge", "url": "https://github.com/artemiosu/agentbridge-protocol"},
]

knowledge = AgentBridge(host="127.0.0.1", port=18093)

@knowledge.expose("/search")
def search_knowledge(query: str):
    results = [k for k in KNOWLEDGE if query.lower() in k["topic"].lower() or query.lower() in k["title"].lower()]
    return {"results": results, "count": len(results)}


# ============================================================================
# Agent: interacts with all 3 services
# ============================================================================

def run_agent():
    """Agent interacts with e-commerce, hotel booking, and knowledge search."""
    print("\n  [AGENT] Starting multi-service agent...")

    kp = Ed25519Keypair.generate()
    print(f"  [AGENT] Identity: {kp.key_id()}")

    agent_id = Identifier("participant", "agent-multi")
    time.sleep(0.3)  # Wait for servers

    # === E-Commerce ===
    print("\n  ─── E-Commerce Service ───")
    shop_client = AgentBridgeClient("127.0.0.1", 18091).with_keypair(kp)

    # Search
    msg = (MessageBuilder(agent_id, Identifier("participant", "shop"))
           .id(Identifier("message", "s1"))
           .operation_id(Identifier("op", "s1"))
           .payload({"action": "search", "query": "laptop"})
           .build())
    resp = shop_client.send("/search", msg, sign=True)
    print(f"  [AGENT] Search 'laptop': {resp.payload['count']} result(s)")
    for p in resp.payload["results"]:
        print(f"         → {p['name']} (${p['price']})")

    # Buy
    msg = (MessageBuilder(agent_id, Identifier("participant", "shop"))
           .id(Identifier("message", "b1"))
           .operation_id(Identifier("op", "b1"))
           .payload({"action": "buy", "product_id": "laptop-001", "quantity": 1})
           .build())
    resp = shop_client.send("/buy", msg, sign=True)
    print(f"  [AGENT] Bought: {resp.payload.get('product', 'FAILED')} — ${resp.payload.get('total', 0)}")

    # === Hotel Booking ===
    print("\n  ─── Hotel Booking Service ───")
    hotel_client = AgentBridgeClient("127.0.0.1", 18092).with_keypair(kp)

    # Search
    msg = (MessageBuilder(agent_id, Identifier("participant", "hotel"))
           .id(Identifier("message", "h1"))
           .operation_id(Identifier("op", "h1"))
           .payload({"action": "search", "city": "Tokyo", "guests": 1})
           .build())
    resp = hotel_client.send("/search", msg, sign=True)
    print(f"  [AGENT] Hotels in Tokyo: {len(resp.payload['hotels'])} found")
    for h in resp.payload["hotels"]:
        print(f"         → {h['name']} (${h['price']}/night, {h['rooms']} rooms)")

    # Book
    msg = (MessageBuilder(agent_id, Identifier("participant", "hotel"))
           .id(Identifier("message", "hb1"))
           .operation_id(Identifier("op", "hb1"))
           .payload({"action": "book", "hotel_id": "h1", "checkin": "2026-10-15", "checkout": "2026-10-18", "guests": 1})
           .build())
    resp = hotel_client.send("/book", msg, sign=True)
    print(f"  [AGENT] Booked: {resp.payload.get('hotel', 'FAILED')} — ${resp.payload.get('total', 0)}/night")

    # === Knowledge Search ===
    print("\n  ─── Knowledge Search Service ───")
    knowledge_client = AgentBridgeClient("127.0.0.1", 18093).with_keypair(kp)

    msg = (MessageBuilder(agent_id, Identifier("participant", "knowledge"))
           .id(Identifier("message", "k1"))
           .operation_id(Identifier("op", "k1"))
           .payload({"action": "search", "query": "agents"})
           .build())
    resp = knowledge_client.send("/search", msg, sign=True)
    print(f"  [AGENT] Knowledge search 'agents': {resp.payload['count']} result(s)")
    for k in resp.payload["results"]:
        print(f"         → {k['title']}")

    return True


# ============================================================================
# Main
# ============================================================================

def main():
    print("=" * 70)
    print("  AgentBridge Multi-Demo")
    print("  3 services · 1 agent · 5 operations · all signed")
    print("=" * 70)

    # Start all services
    print("\n  Starting services...")
    shop.start()
    hotel.start()
    knowledge.start()
    time.sleep(0.5)

    # Run agent
    success = run_agent()

    # Stop services
    print("\n  Stopping services...")
    shop.stop()
    hotel.stop()
    knowledge.stop()

    print()
    print("=" * 70)
    if success:
        print("  ✅ Multi-Demo SUCCESS!")
        print("  Agent interacted with 3 different services:")
        print("    1. E-Commerce: searched + bought a laptop")
        print("    2. Hotel Booking: searched + booked a hotel in Tokyo")
        print("    3. Knowledge Search: found articles about agents")
        print("  All operations used Ed25519-signed AgentBridge messages.")
    else:
        print("  ❌ Demo FAILED.")
    print("=" * 70)

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
