# Ordavyn release status

The source repository is public and experimental. There is no supported package
release on crates.io or PyPI, and no production support commitment. Cargo retains
`publish = false` and Python retains `Private :: Do Not Upload`; these controls
separate public source review from package publication.

[Draft 0.1](../spec/README.md) and its conformance map document the implemented
profile. Tagged v0.1.x snapshots are experimental source-only GitHub prereleases,
not supported package releases. Governance is documented as single-maintainer
stewardship. DCO 1.1 applies only after
`1fe370a0b64cbfa5a302c1a6a881f1d99a503c48`. The protected `main` ruleset requires
linear rebase integration plus successful repository and CodeQL checks; the
repository verifier checks the fixed baseline through each descendant head.

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

The reviewed candidate's private result records 97 Rust and 55 verification-tool
tests, plus 249 SDK and 159 recovery/TLS checks for each independent wheel and
sdist installation. Skipped, ignored, filtered or deselected tests are rejected.

## Remaining evidence and package-release gates

- No crates.io or PyPI publication, compiled release asset, or supported package
  release is provided. GitHub prereleases contain source snapshots only.
- The unmaintained `rustls-pemfile 2.2.0` wrapper has been removed. The existing
  `rustls-pki-types` dependency now parses PEM without changing the public TLS API.
  RustSec conditions use pinned Rust `semver 1.0.28`; invalid data or helper failure
  remains UNKNOWN. The fresh official snapshot evaluates to 46 NOT_AFFECTED and
  one WITHDRAWN, with no UNKNOWN or BLOCKER; the private verifier independently
  reproduced all 47 rows with the same helper binary hash.
- Dependency obligations, nested components and any future redistribution of
  compiled dependencies need review. See [third-party evidence](THIRD-PARTY.md).
  Missing evidence is UNKNOWN, never a clean bill of health.
- The owner's declaration that they wrote the code only with AI assistance is
  recorded in [provenance](PROVENANCE.md). Independent similarity/rights review
  and legal conclusions are not supplied by that declaration or by this tooling.
- Registry observations on 2026-09-29 are time-limited: public endpoints returned
  HTTP 404 for `ordavyn` on PyPI and `ordavyn-core` on crates.io. No registration,
  name reservation, domain ownership or trademark right follows from this.
- Independent review of the specification, architectural acceptance, additional
  maintainers, a reviewed IPR/patent policy, a real identity beyond the GitHub
  profile, and broader disclosure remain open. Public project contact is
  [artem@ordavyn.tech](mailto:artem@ordavyn.tech).
  GitHub Private Vulnerability Reporting is enabled for sensitive reports, without
  a promised response SLA. No contact identity or commitment is invented.
  Historical architecture decisions are not evidence that these conditions have
  been met.
- Secret scans are bounded pattern checks with explicit public test fixtures;
  they are not proof that every possible secret or copied source was detected.
  Historical former names are kept in private reports; history is unchanged.

Tests, review and package checks do not constitute a security audit, legal
clearance, protocol certification or permission for production operations.

The repository package adds pinned GitHub Actions, structured contribution forms
and local fail-closed workflow checks. CI runs the existing Rust, Python,
interoperability, guide and repository-tool suites with read-only contents access.
CodeQL is limited to Python and Rust and has only the additional
`security-events: write` permission required to upload its result. The public
[security policy](../SECURITY.md) records that no release is supported and directs
sensitive reports to GitHub Private Vulnerability Reporting without promising a
response SLA.

Verification evidence now binds both lock files and the dependency report to the
source snapshot, and records hashes of the executing verifier modules. Rust builds
use fresh source extraction from lock-verified archives with an active Linux graph;
cached source audit compares directly to archive bytes. Installed Ordavyn bytes
are checked after both wheel and sdist installations. These controls do not
establish a supported package release or hermetic builds.
