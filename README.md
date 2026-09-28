# Ordavyn — local protocol prototype

Ordavyn explores a native protocol and SDK ecosystem for agent↔service,
agent↔agent and service↔service interaction. Native Architecture-First and
role-neutral scope remain the design direction; commercial services are optional.

The local Rust and Python implementations authenticate requests with Ed25519,
require explicit local permissions and reserve message/operation IDs before
handlers run. They use bounded loopback HTTP/1.1, temporary memory journals by
default, and an optional [persistent local SQLite journal](docs/LOCAL-JOURNAL.md).
Local [admission controls](docs/LOCAL-LIFECYCLE.md) support key revocation, rotation
and bounded shutdown without clearing replay protection.
Unknown outcomes require application reconciliation; external effects are not exactly-once.

This is not an approved release, security certification or production service.
The owner selected Apache-2.0; provenance and attribution review remains open. No real operations, TLS, delegation, negotiation,
or post-quantum cryptography are implemented.

See [implementation guide](implementation/README.md),
[tutorial](implementation/TUTORIAL.md), [release status](docs/RELEASE-STATUS.md)
and [provenance](docs/PROVENANCE.md). Private planning and old Git history are
excluded from the publishable file set. Publication requires a separate decision.
