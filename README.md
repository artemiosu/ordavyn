# Ordavyn — local protocol prototype

Ordavyn explores a native protocol and SDK ecosystem for agent↔service,
agent↔agent and service↔service interaction. Native Architecture-First and
role-neutral scope remain the design direction; commercial services are optional.

The local Rust and Python implementations authenticate requests and request-bound
responses with Ed25519,
require explicit local permissions and reserve message/operation IDs before
handlers run. They use bounded loopback HTTP/1.1 with explicitly configured TLS 1.3
or a plain HTTP test mode, temporary memory journals by
default, and an optional [persistent local SQLite journal](docs/LOCAL-JOURNAL.md).
Local [admission controls](docs/LOCAL-LIFECYCLE.md) support key revocation, rotation
and bounded shutdown without clearing replay protection.
Unknown outcomes require application reconciliation; external effects are not exactly-once.

This is not an approved release, security certification or production service.
The owner selected Apache-2.0 and states that they created the code only with AI assistance; dependency and attribution review remains separate. No real operations, delegation, negotiation,
or post-quantum cryptography are implemented.

See [implementation guide](implementation/README.md),
[tutorial](implementation/TUTORIAL.md), [release status](docs/RELEASE-STATUS.md)
and [provenance](docs/PROVENANCE.md). Private planning and old Git history are
excluded from the publishable file set. Publication requires a separate decision.

See the [authenticated v3 exchange guide](docs/LOCAL-WIRE-V3.md) for explicit TLS 1.3 configuration,
protocol pins, HTTP test mode without confidentiality and the threat model.

The [local candidate procedure](release/README.md) records exact source/package
contents and verification inputs. See [third-party evidence](docs/THIRD-PARTY.md)
and the concrete release blockers before considering any distribution.
