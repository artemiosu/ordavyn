# Ordavyn protocol specification

This directory contains the **Ordavyn Draft 0.1** contract for the experimental
local wire-v3 profile. Tagged snapshots are source-only GitHub prereleases unless
explicitly stated otherwise. This is not a standard, certification, production
profile, supported package, or independent implementation.

- [Normative wire-v3 specification](ORDAVYN-WIRE-V3.md)
- [Requirement evidence and unsupported inventory](CONFORMANCE.md)
- [Versioned shared wire-v3 vectors](../implementation/tests/fixtures/wire-v3.json)
  and their [provenance/readme](../implementation/tests/fixtures/README.md)
- [Release status](../docs/RELEASE-STATUS.md)
- [Threat model](../docs/LOCAL-THREAT-MODEL.md)

The profile is role-neutral. The Rust and Python SDKs are reference
implementations with shared provenance, not evidence of independent adoption.
The shared vectors are fixed cross-language regression fixtures produced within
that same provenance. They are useful interoperability evidence, not an
independent specification oracle or independent implementation.
