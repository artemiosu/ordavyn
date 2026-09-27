# Release preparation status

Ordavyn is a local migration candidate, not a production-ready protocol release.

## Preserved baseline

The implementation is the owner-supplied AgentBridge snapshot, imported without source-code changes. Legacy package names, import paths and wire identifiers are still present. A name change is not a protocol compatibility change by itself.

Baseline verification on 2026-09-27: 57 Rust tests and 32 Python SDK tests passed; the inherited conformance script reported 59 successful checks. Four resource-limit checks are constant-true placeholders. These results do not certify security or protocol conformance.

## Before publication or release

- Enforce signature authenticity and explicit authorization before consequential handlers execute; add negative tests.
- Replace placeholder conformance checks with behavioral tests and state unsupported capabilities honestly.
- Reconcile implemented transport with README claims; do not claim TLS/HTTP/2 from the current raw-socket prototype.
- Verify SDK package installation and examples, including referenced README and license files.
- Resolve Cargo's MIT OR Apache-2.0 declaration versus the supplied Apache-2.0 license text. Migration does not choose or grant an additional license.
- Perform controlled package, documentation and branding migration; treat wire identifiers separately.
- Curate a public specification/governance set and review name, licensing, provenance, dependencies and secrets.
- Obtain owner authorization for the exact public file set and publish only that reviewed set.

No production service, real transaction, sensitive data or public network exposure is authorized by this preparation. A successful test run is not evidence that all these items are complete.
