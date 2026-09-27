# AgentBridge — 10-Minute Tutorial

**Make your service accessible to AI agents in 10 minutes.**

This tutorial shows you how to:
1. Install AgentBridge
2. Create an agent-ready service (e-commerce)
3. Create an AI agent that buys from it
4. Run it and see it work

No prior knowledge of AgentBridge needed. Basic Python required.

---

## Step 1: Install (1 minute)

```bash
pip install agentbridge
```

That's it. AgentBridge uses the `cryptography` library for Ed25519 signatures — it installs automatically.

**Verify:**
```bash
python3 -c "import agentbridge; print(agentbridge.__version__)"
# Output: 0.1.0
```

---

## Step 2: Create a Service (3 minutes)

Create a file `my_shop.py`:

```python
from agentbridge import AgentBridge

# Create an AgentBridge server
bridge = AgentBridge(host="127.0.0.1", port=8080)

# Your product catalog (use a real database in production)
products = [
    {"id": "p1", "name": "Wireless Headphones", "price": 99.99, "stock": 10},
    {"id": "p2", "name": "Mechanical Keyboard", "price": 149.99, "stock": 5},
    {"id": "p3", "name": "USB-C Hub", "price": 39.99, "stock": 20},
]

# Expose a search endpoint — any agent can call this
@bridge.expose("/search")
def search_products(query: str):
    """Search products by name."""
    results = [p for p in products if query.lower() in p["name"].lower()]
    return {"results": results, "count": len(results)}

# Expose a buy endpoint — consequential=True means it requires
# a cryptographically signed message (Ed25519).
# This prevents unauthorized purchases and provides non-repudiation.
@bridge.expose("/buy", consequential=True)
def buy_product(product_id: str, quantity: int = 1):
    """Buy a product. Requires signed message."""
    product = next((p for p in products if p["id"] == product_id), None)
    if not product:
        return {"error": "product_not_found"}
    if product["stock"] < quantity:
        return {"error": "out_of_stock", "available": product["stock"]}

    product["stock"] -= quantity
    return {
        "order_id": f"order-{product_id}-{quantity}",
        "product": product["name"],
        "total": round(product["price"] * quantity, 2),
        "status": "confirmed",
    }

# Start the server
if __name__ == "__main__":
    bridge.start()
    print("Shop running! Press Ctrl+C to stop.")
    print("Agents can now connect to http://127.0.0.1:8080")
    try:
        import time
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        bridge.stop()
        print("Shop stopped.")
```

**What just happened?**

- `@bridge.expose("/search")` — your search function is now accessible to any AgentBridge agent
- `@bridge.expose("/buy", consequential=True)` — purchases require a cryptographic signature. No signature = no purchase. This is how AgentBridge prevents fraud.
- `bridge.start()` — starts the server. Agents can connect.

---

## Step 3: Create an Agent (3 minutes)

Create a file `my_agent.py`:

```python
from agentbridge import (
    AgentBridgeClient, Ed25519Keypair,
    Identifier, MessageBuilder,
)

# Step 3a: Generate your agent's identity
# This Ed25519 keypair is your agent's cryptographic identity.
# Keep the private key secret. Share the public key with services.
keypair = Ed25519Keypair.generate()
print(f"Agent identity: {keypair.key_id()}")

# Step 3b: Create a client connected to the shop
client = AgentBridgeClient("127.0.0.1", 8080).with_keypair(keypair)

# Your agent's identity in the protocol
agent_id = Identifier("participant", "my-agent")
shop_id = Identifier("participant", "my-shop")

# Step 3c: Search for products
print("\n--- Searching for 'headphones' ---")
search_msg = (
    MessageBuilder(agent_id, shop_id)
    .id(Identifier("message", "search-001"))
    .operation_id(Identifier("logical-operation", "search-op-001"))
    .payload({"action": "search", "query": "headphones"})
    .build()
)

response = client.send("/search", search_msg, sign=True)
print(f"Found {response.payload['count']} product(s):")
for p in response.payload["results"]:
    print(f"  - {p['name']} (${p['price']}) [stock: {p['stock']}]")

# Step 3d: Buy a product (consequential action — automatically signed)
print("\n--- Buying Wireless Headphones ---")
buy_msg = (
    MessageBuilder(agent_id, shop_id)
    .id(Identifier("message", "buy-001"))
    .operation_id(Identifier("logical-operation", "buy-op-001"))
    .payload({"action": "buy", "product_id": "p1", "quantity": 1})
    .build()
)

response = client.send("/buy", buy_msg, sign=True)

if response.msg_type == "response":
    order = response.payload
    print(f"✅ Purchase confirmed!")
    print(f"   Order: {order['order_id']}")
    print(f"   Product: {order['product']}")
    print(f"   Total: ${order['total']}")
else:
    print(f"❌ Purchase failed: {response.payload}")
```

---

## Step 4: Run It (1 minute)

Open **two terminals**:

**Terminal 1 — start the shop:**
```bash
python3 my_shop.py
```
```
Shop running! Agents can now connect to http://127.0.0.1:8080
```

**Terminal 2 — run the agent:**
```bash
python3 my_agent.py
```
```
Agent identity: a1b2c3d4e5f6g7h8

--- Searching for 'headphones' ---
Found 1 product(s):
  - Wireless Headphones ($99.99) [stock: 10]

--- Buying Wireless Headphones ---
✅ Purchase confirmed!
   Order: order-p1-1
   Product: Wireless Headphones
   Total: $99.99
```

**🎉 Your agent just bought a product through AgentBridge!**

---

## What Just Happened?

```
Agent                              Shop
  │                                  │
  │  1. Search "headphones"          │
  │  (Ed25519 signed)                │
  │ ──────────────────────────────→  │
  │                                  │
  │  2. Results: Wireless Headphones │
  │  (response)                      │
  │ ←──────────────────────────────  │
  │                                  │
  │  3. Buy product p1, qty 1        │
  │  (Ed25519 signed)                │
  │ ──────────────────────────────→  │
  │                                  │
  │  4. Order confirmed              │
  │  (response)                      │
  │ ←──────────────────────────────  │
```

1. **Search** — agent asks the shop for products. Message is signed with Ed25519 so the shop knows who's asking.
2. **Results** — shop returns matching products.
3. **Buy** — agent sends a purchase request. Because `consequential=True`, the shop **verifies the Ed25519 signature** before processing. No signature = no purchase.
4. **Confirmation** — shop returns the order details.

---

## Key Concepts

### Cryptographic Identity

Every agent has an Ed25519 keypair:
- **Private key** — used to sign messages. Keep secret.
- **Public key** — used to verify signatures. Share freely.

```python
keypair = Ed25519Keypair.generate()
keypair.public_key_bytes()  # 32 bytes — share this
keypair.key_id()            # 16 hex chars — short identifier
```

### Signed Messages

Every message can be signed:
```python
msg = MessageBuilder(from_id, to_id).payload({"action": "buy"}).build()
msg.sign(keypair)  # signs with Ed25519
```

### Consequential Actions

Actions that change state (buy, delete, transfer) should be marked `consequential=True`:
```python
@bridge.expose("/buy", consequential=True)
def buy(...):
    ...
```

AgentBridge **rejects unsigned messages** for consequential actions. This prevents:
- Unauthorized purchases
- Replay attacks (same operation can't be executed twice)
- Fraud (every action is non-repudiable — signed = can't deny)

### Message Envelope

Every AgentBridge message contains:
- `from` / `to` — who is talking to whom
- `operation_id` — groups related messages (search → results → buy → confirmation)
- `payload` — the actual data
- `signature` — Ed25519 signature (for signed messages)
- `signature_alg` — algorithm ID (1 = Ed25519, future: ML-DSA-65, hybrid)
- `key_id` — identifies which key signed this

---

## Next Steps

1. **Run the included demos:**
   ```bash
   python3 demo/demo_ecommerce.py    # Single-service demo
   python3 demo/demo_multi.py        # Multi-service demo (3 services)
   ```

2. **Add AgentBridge to your existing FastAPI app:**
   ```python
   from agentbridge import AgentBridge
   from fastapi import FastAPI

   app = FastAPI()
   bridge = AgentBridge(app)

   @bridge.expose("/search")
   def search(query: str):
       return {"results": my_database.search(query)}
   ```

3. **Read the architecture:**
   - [Architecture Spine](../_bmad-output/planning-artifacts/architecture/architecture-agent-bridge-sdk-2026-09-15/ARCHITECTURE-SPINE.md)
   - [Binding Contract](../_bmad-output/planning-artifacts/architecture/architecture-agentbridge-aa4-2026-09-26/BC.md)

4. **Join the community:**
   - GitHub: https://github.com/artemiosu/agentbridge-protocol
   - Star the repo if you like it!

---

## FAQ

**Q: Is this production-ready?**
A: No. This is a Developer Preview. The protocol design is complete (24 architecture documents), but the implementation needs TLS, production-grade transport, and more testing before production use.

**Q: How is this different from REST/GraphQL?**
A: REST carries data. AgentBridge carries **meaning**: who is authorized, what is permitted, what effect occurred, and what proves it. This makes it suitable for consequential actions (payments, bookings, legal) where REST is insufficient.

**Q: Do I need Rust?**
A: No. The Python SDK is pure Python (with `cryptography` for Ed25519). Rust is the reference implementation; Python SDK works standalone.

**Q: Can I use this with LangChain/AutoGen/CrewAI?**
A: Yes. AgentBridge is a protocol, not a framework. Your agent framework talks to AgentBridge, which talks to services. LangChain integration plugin is planned.

**Q: Is it free?**
A: Yes. Apache 2.0 licensed. The protocol will remain free and open forever. Commercial services (AgentBridge Cloud) are optional.

---

*Built with ❤️ for the future internet.*
