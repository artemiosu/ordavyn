# Ordavyn implementation

Local prototype, not an approved release. Native Architecture-First describes a
standalone, role-neutral protocol; the current code implements a small local subset.

- Rust crate: `ordavyn-core`; Python distribution/import: `ordavyn`.
- HTTP/1.1 JSON transport on loopback only; route `/ordavyn/v2/<action>` and
  mandatory header `x-ordavyn-version: 2`. Previous wire names are incompatible.
- Every action requires Ed25519 authentication and an explicit local grant tying
  its public key to a participant, this server's recipient and allowed actions.
- Message ID and logical operation ID are atomically reserved before the handler.
  Failed actions stay reserved. Journal capacity defaults to 10,000 requests and
  fails closed without eviction. The default memory mode clears on restart; explicitly
  selected SQLite persists reservations. Neither provides exactly-once external effects.
- HTTP header limit 8 KiB, body limit 64 KiB, network deadline 3 seconds.
  Handlers must be short local operations; arbitrary handler execution is not sandboxed.
- Responses are new unsigned envelopes. Clients validate version, type, recipient
  and operation correlation, but no authenticated remote-response channel is provided.

## Persistent local journal

Rust uses `Journal::create` for exclusive provisioning and `Journal::open` for
recovery, then `OrdavynServer::with_journal(recipient, capacity, Arc::new(journal))`.
`Journal::memory` is explicitly temporary. Unknown outcomes require application
reconciliation; neither failure nor restart allows replay. See the shared
[local journal guide](../docs/LOCAL-JOURNAL.md) for both SDKs and limitations.

## Signed formats

Both SDKs use the experimental [local wire v2 contract](../docs/LOCAL-WIRE-V2.md).
They sign the ASCII domain `ordavyn:v2:message\0` followed by the deterministic
CBOR map of all envelope fields except `signature`. JSON remains the only network
format. All envelope and AIM fields are required, including explicit optional nulls.
Algorithm 1, lowercase key IDs and signature hex are shared by both SDKs.
Version 1 and previous signing encodings are rejected without fallback.
The complete JSON tree has a depth limit of 32 and fixed integer/float rules.

Python pins cbor2 5.9.0 and uses its Python canonical encoder: its C accelerator
fails the shortest-float rule for 65504.0. Frozen vectors cover this boundary.
Legacy tagged AIM CBOR helpers are separate from wire v2 and are not its codec.

## Local verification

From `implementation/`:

```sh
cargo test --workspace --locked
cargo build --workspace --release --locked
python -m pip install ./python-sdk pytest build
python -m pytest python-sdk/tests -q
cargo build --locked --example interop_peer
python tests/test_conformance.py
python -m build python-sdk
```

See [TUTORIAL.md](TUTORIAL.md) for clean-environment installation and demos.
The conformance runner executes behavioral tests and reports unsupported features
explicitly; it is not conformance certification. Delegation, negotiation, PQ,
TLS and exactly-once external effects are unsupported.

The owner selected Apache-2.0 on 2026-09-27; `LICENSE` contains its standard text.
Rights to inherited material and required attribution still need verification.
See the repository's `docs/PROVENANCE.md` and `docs/RELEASE-STATUS.md` before any
publication or redistribution. Private planning is intentionally absent from packages.

CBOR transport decoding, CBOR decoder resource-limit enforcement and streaming
transport are unsupported. Rust CBOR depth/collection constants are proposed
values only; they are not enforced decoder limits and their values do not prove
resource protection. The implemented HTTP JSON byte limits are separate.
HTTP/2 streams and concurrent-stream limits are also unsupported.


## Local admission lifecycle

Both SDKs support explicit permission updates, key revocation and atomic key
rotation. Stop closes direct and HTTP admission and waits for current work with a
bounded timeout; resume preserves permissions and replay barriers. A timeout does
not cancel an admitted handler. See the [local lifecycle guide](../docs/LOCAL-LIFECYCLE.md)
for Python/Rust methods, examples and process-restart boundaries.
