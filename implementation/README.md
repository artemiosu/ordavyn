# Ordavyn implementation

Local prototype, not an approved release. Native Architecture-First describes a
standalone, role-neutral protocol; the current code implements a small local subset.

- Rust crate: `ordavyn-core`; Python distribution/import: `ordavyn`.
- HTTP/1.1 JSON transport on loopback only; route `/ordavyn/v1/<action>` and
  mandatory header `x-ordavyn-version: 1`. Previous wire names are incompatible.
- Every action requires Ed25519 authentication and an explicit local grant tying
  its public key to a participant, this server's recipient and allowed actions.
- Message ID and logical operation ID are atomically reserved before the handler.
  Failed actions stay reserved. Journal capacity defaults to 10,000 requests and
  fails closed without eviction. Restart clears it; this is not durable exactly-once execution.
- HTTP header limit 8 KiB, body limit 64 KiB, network deadline 3 seconds.
  Handlers must be short local operations; arbitrary handler execution is not sandboxed.
- Responses are new unsigned envelopes. Clients validate version, type, recipient
  and operation correlation, but no authenticated remote-response channel is provided.

## Signed formats

Python signs sorted compact UTF-8 JSON including all envelope fields except the
signature itself. Rust signs a fixed-order CBOR array containing version, type,
message ID, operation ID, subject, sender, recipient, epoch, payload, timestamp,
algorithm ID, key ID and encoding. AIM values use CBOR tags; JSON objects become
CBOR maps and arrays stay arrays. Algorithm, key ID and encoding are authenticated.
Rust's JSON envelope represents signatures and message types differently from
Python. These SDKs are **not signature- or wire-interoperable** with each other;
shared interoperable serialization is future work. Encoding identifies signing
representation (`cbor` in Rust, `json` in Python), while transport is JSON in both.

## Local verification

From `implementation/`:

```sh
cargo test --workspace --locked
cargo build --workspace --release --locked
python -m pip install ./python-sdk pytest build
python -m pytest python-sdk/tests -q
python tests/test_conformance.py
python -m build python-sdk
```

See [TUTORIAL.md](TUTORIAL.md) for clean-environment installation and demos.
The conformance runner executes behavioral tests and reports unsupported features
explicitly; it is not conformance certification. Delegation, negotiation, PQ,
TLS and durable replay protection are unsupported.

Licensing is unresolved: `LICENSE` is a status notice, not a new license grant.
See the repository's `docs/PROVENANCE.md` and `docs/RELEASE-STATUS.md` before any
publication or redistribution. Private planning is intentionally absent from packages.

CBOR transport decoding, CBOR decoder resource-limit enforcement and streaming
transport are unsupported. Rust CBOR depth/collection constants are proposed
values only; they are not enforced decoder limits and their values do not prove
resource protection. The implemented HTTP JSON byte limits are separate.
HTTP/2 streams and concurrent-stream limits are also unsupported.
