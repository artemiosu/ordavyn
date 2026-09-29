# Ordavyn local candidate status

Publication is **BLOCKED**. Preparation of a verifiable local candidate is not
permission to publish. Cargo retains `publish = false`, Python retains
`Private :: Do Not Upload`, and the local pre-push control remains in place.

## Current capabilities

The experimental wire v3 profile implements strict JSON and deterministic CBOR
signing, Ed25519 request authentication, explicit participant/action permissions,
message and operation replay barriers, signed request-bound responses, explicit
protocol pins, and optionally configured TLS 1.3. HTTP is limited to loopback;
plain HTTP is a local test mode without confidentiality. Both SDKs offer temporary
memory journals or explicitly provisioned persistent local SQLite journals.
Local revoke/rotate, permission replacement, stop and resume preserve barriers.
An already admitted handler may still complete its effect.

Native Architecture-First and role-neutral scope remain the direction. Commercial
services are optional and replaceable. Delegation, negotiation, post-quantum
cryptography, streaming, HTTP/2 streams, CBOR transport decoding and decoder
resource enforcement are not implemented. Unknown outcomes require application
reconciliation. There are no automatic retries or exactly-once external effects.
Client errors after sending still lack a separate structured unknown-outcome
result with identifiers; applications must retain and reconcile the request.

## What this preparation establishes

The [local verification procedure](../release/README.md) selects exact Git blobs,
classifies every tracked file, produces a deterministic source archive without Git
history, and checks every wheel/sdist path and byte against sources and expected
builder metadata. Results identify the commit, file modes, sizes, SHA-256 hashes
and environment. The full evidence remains local and private. Success applies
only to the recorded artifacts and Linux x86_64 environment, not other platforms.
Wheel bit-for-bit reproducibility is not claimed.

The previous wire v3 baseline passed 96 Rust tests and 249 SDK +35 recovery +119
TLS/response checks in each package installation. These are historical counts;
only a newly generated private result report records the candidate's fresh run.

## Remaining decisions and blockers

- Owner approval for publication and a concrete public release is absent.
- RustSec [RUSTSEC-2025-0134](https://rustsec.org/advisories/RUSTSEC-2025-0134.html)
  identifies `rustls-pemfile 2.2.0` as **unmaintained**. This is a maintenance
  advisory, not evidence of an exploit. It requires a separately reviewed
  dependency decision; this preparation does not update dependencies.
- Eight additional locked-version RustSec advisory matches remain **UNKNOWN**
  under the deliberately restricted stable full-version parser. They require
  separate evaluation before release approval; results from the earlier matcher
  do not establish that these versions are unaffected.
- Dependency obligations, nested components and any future redistribution of
  compiled dependencies need review. See [third-party evidence](THIRD-PARTY.md).
  Missing evidence is UNKNOWN, never a clean bill of health.
- The owner's declaration that they wrote the code only with AI assistance is
  recorded in [provenance](PROVENANCE.md). Independent similarity/rights review
  and legal conclusions are not supplied by that declaration or by this tooling.
- Registry observations on 2026-09-29 are time-limited: public endpoints returned
  HTTP 404 for `ordavyn` on PyPI and `ordavyn-core` on crates.io. No registration,
  name reservation, domain ownership or trademark right follows from this.
- Public protocol specification, architectural acceptance, governance, a real
  maintainer/security contact and disclosure process require owner decisions.
  No contact identity or commitment is invented. Historical architecture approval
  and private planning are not evidence that these conditions have been met.
- Secret scans are bounded pattern checks with explicit public test fixtures;
  they are not proof that every possible secret or copied source was detected.
  Historical former names are kept in private reports; history is unchanged.

Tests, review and package checks do not constitute a security audit, legal
clearance, protocol certification or permission for production operations.

Verification evidence now binds both lock files and the dependency report to the
source snapshot, and records hashes of the executing verifier modules. Rust builds
use fresh source extraction from lock-verified archives with an active Linux graph;
cached source audit compares directly to archive bytes. Installed Ordavyn bytes
are checked after both wheel and sdist installations. These controls do not
remove publication blockers or establish hermetic builds.
