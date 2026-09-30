# Ordavyn roadmap

Ordavyn is a public protocol experiment, not a standard or a production-ready
system. Progress is measured by evidence gates rather than dates, adoption
promises, or feature counts. A later gate does not pass until its listed evidence
is public and independently reproducible.

## 1. Reproducible local profile — current

The repository contains Rust and Python implementations of the experimental
loopback wire-v3 profile, shared vectors, live cross-SDK tests, bounded verification
tools, and public documentation of known limits. No package release is supported.

Exit evidence:

- a clean source checkout runs the documented demos and verification;
- every present-tense protocol claim links to code, a test, or a public document;
- repository status and package-release status remain distinct;
- wire, lifecycle, journal, and threat boundaries are documented together.

## 2. Reviewable protocol specification — not yet

Move the wire contract from an implementation guide to a versioned, implementation-
independent specification with precise state machines, error semantics, extension
rules, and compatibility policy.

Exit evidence:

- public specification review and resolved issue history;
- test vectors derived from the specification rather than one SDK;
- explicit versioning, extension, and deprecation rules;
- documented privacy, resource, and failure semantics.

## 3. Independent implementations and conformance — not yet

A shared repository containing two SDKs is useful interoperability evidence, but it
is not independence. This gate requires implementations developed and maintained
independently from the reference code.

Exit evidence:

- at least two independent implementations;
- a reusable conformance suite with positive and negative cases;
- published, reproducible conformance results with known deviations;
- cross-implementation interoperability over the same protocol version.

## 4. Deployment and ecosystem interoperability — not yet

Define and test profiles beyond the current loopback HTTP/1.1 experiment without
weakening authentication, admission, replay, or response-binding properties.

Exit evidence:

- reviewed discovery, transport, deployment, and operational profiles;
- failure-injection and multi-party interoperability results;
- explicit integration boundaries with adjacent protocols and observability tools;
- migration tests across supported protocol versions.

## 5. Security and operational maturity — not yet

The current threat model and automated checks are engineering evidence, not a
security audit or an operational readiness claim.

Exit evidence:

- independent security review with tracked remediation;
- deployment guidance, key lifecycle, incident handling, and disclosure process;
- performance and resource-exhaustion characterization;
- supported release policy and maintained package distribution.

## 6. Open governance and standards consideration — not yet

Standards work becomes credible only after independent use and review demonstrate
that the protocol solves a shared problem. Repository ownership alone is not open
governance.

Exit evidence:

- documented decision process and transparent change control;
- public contribution licensing plus an explicit IPR and patent policy reviewed
  for the chosen governance process;
- multiple independent maintainers and implementation stakeholders;
- neutral stewardship or another openly reviewed governance model;
- submission to an appropriate standards venue only after conformance,
  interoperability, and security evidence exists.
