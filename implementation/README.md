# AgentBridge

**Protocol for safe, efficient, standardized interaction in the future internet.**

AgentBridge is an open protocol that lets AI agents, services, APIs, and backend systems interact safely — with cryptographic signatures, authority delegation, evidence trails, and compensation mechanics.

Think of it as **HTTP for the next generation of the internet** — where agents, services, and humans all need to interact with each other, and "just sending data" isn't enough. AgentBridge carries **meaning**: who is authorized, what is permitted, what effect occurred, and what proves it.

## Why AgentBridge?

Today's internet is built for humans clicking buttons. But the future is:

- **AI agents** that need to buy, book, search, and negotiate
- **Services** that need to verify who is asking and what they're allowed to do
- **B2B systems** that need auditable, non-repudiable transactions
- **Multi-party flows** with delegation, approval, and compensation

REST/GraphQL/gRPC carry **data**. AgentBridge carries **semantics**: authority, effect, evidence.

## Quick Start

```bash
pip install agentbridge
```

### Agent: search and buy a product

```python
from agentbridge import AgentBridgeClient, Ed25519Keypair

# Generate your agent's identity
keypair = Ed25519Keypair.generate()

# Connect to an AgentBridge-enabled service
client = AgentBridgeClient("127.0.0.1", 8080).with_keypair(keypair)

# Search for products
response = client.send("/search", {
    "action": "search",
    "query": "laptop"
})

# Buy a product (cryptographically signed)
response = client.send("/buy", {
    "action": "buy",
    "product_id": "laptop-001",
    "quantity": 1
})
```

### Service: expose your API to agents

```python
from agentbridge import Message, MessageType

def handle_search(msg: Message) -> Message:
    query = msg.payload.get("query", "")
    products = search_database(query)

    msg.msg_type = MessageType.RESPONSE
    msg.payload = {"results": products}
    return msg

# Register with AgentBridge server
server.handle("/agentbridge/v1/search", handle_search)
```

## Key Features

- **🔐 Cryptographic signatures** — Every consequential action is signed with Ed25519 (RFC 8032). Non-repudiation built-in.
- **🛡️ Authority delegation** — Delegates, approvers, policy authorities. Monotonic attenuation prevents privilege escalation.
- **📜 Evidence trails** — Every action produces verifiable evidence. Conflicts don't disappear silently.
- **🔄 Lifecycle management** — Retry, replay, cancel, compensation. `unknown` never becomes `success`.
- **🌐 Role-neutral** — Agent↔service, agent↔agent, service↔service, B2B, multi-party. No client-server assumption.
- **🧩 Extensible** — Profiles and Extensions without breaking the Core. Version negotiation built-in.
- **⚡ PQ-ready** — Message envelope supports variable-length signatures and algorithm negotiation. Post-quantum migration path defined.

## Architecture

```
AgentBridge Protocol Suite (Semantic Hourglass)

┌──────────────────────────────────────────────┐
│              Profiles & Extensions            │
├──────────────────────────────────────────────┤
│  AIM · RCM · DSM · AAM · LOM · ECM · CEM     │
│              APM · AFC (Core)                 │
├──────────────────────────────────────────────┤
│         BC (Binding Contract)                 │
│  HTTP/2 · CBOR+JSON · Ed25519 · SHA-256      │
├──────────────────────────────────────────────┤
│           Bridges (optional)                  │
└──────────────────────────────────────────────┘
```

## Technology Stack

| Component | Choice | Standard |
|-----------|--------|----------|
| Reference implementation | Rust | stable, edition 2021+ |
| Transport | HTTP/2 bidirectional streams | RFC 9113 |
| Encoding | CBOR (primary) + JSON (debug) | RFC 8949 / RFC 8785 |
| Signatures | Ed25519 PureEdDSA | RFC 8032 |
| Hashing | SHA-256 | FIPS 180-4 |
| Transport security | TLS 1.3 (mTLS) | RFC 8446 |

## Status

**Current: Developer Preview (Phase 0)**

- ✅ Architecture complete (AA-1..AA-6, 24 artifacts)
- ✅ Rust reference implementation (`agentbridge-core`)
- ✅ Python SDK
- ✅ E-commerce demo (agent buys product)
- ✅ Conformance tests (148 tests, all pass)
- ⏳ FastAPI/Flask/Django integration (planned)
- ⏳ AgentBridge Cloud (planned)

## Running the Demo

```bash
cd implementation
python3 demo/demo_ecommerce.py
```

Output:
```
[AGENT] Step 1: Searching for 'laptop'...
[AGENT] Found 1 product(s): ProBook 15 ($999.99)
[AGENT] Step 2: Buying ProBook 15...
[AGENT] Purchase CONFIRMED! Order ID: order-0001
[AGENT] Step 3: Verifying order...
[AGENT] Order verified: confirmed
✅ Demo SUCCESS!
```

## Running Tests

### Python SDK
```bash
cd implementation/python-sdk
python3 tests/test_sdk.py
# 32 tests pass
```

### Conformance Tests
```bash
cd implementation
python3 tests/test_conformance.py
# 59 tests pass
```

### Rust Core
```bash
cd implementation
cargo test
# 57 tests pass
```

## Documentation

- [Architecture Spine](../_bmad-output/planning-artifacts/architecture/architecture-agent-bridge-sdk-2026-09-15/ARCHITECTURE-SPINE.md)
- [Binding Contract (BC v1.1.0)](../_bmad-output/planning-artifacts/architecture/architecture-agentbridge-aa4-2026-09-26/BC.md)
- [Security Architecture (STA)](../_bmad-output/planning-artifacts/architecture/architecture-agentbridge-aa3-2026-09-26/STA.md)
- [Business Strategy](../_bmad-output/planning-artifacts/business-strategy-2026-09-26/BES.md)

## License

Apache License 2.0 — see [LICENSE](LICENSE).

## Contributing

Contributions welcome! This is an open protocol — the specification is free and the reference implementation is open source.

Protocol-Platform Firewall: the protocol is and will remain free, open, and neutral. Commercial services built on top of AgentBridge are optional and replaceable.

## Links

- [GitHub](https://github.com/artemiosu/agentbridge-protocol)
- [Architecture Documentation](../_bmad-output/)
- [Business Strategy](../_bmad-output/planning-artifacts/business-strategy-2026-09-26/BES.md)
