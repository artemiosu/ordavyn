# Governance

Ordavyn currently uses transparent single-maintainer stewardship. The maintainer
is GitHub account [artemiosu](https://github.com/artemiosu); public project contact
is [artem@ordavyn.tech](mailto:artem@ordavyn.tech). This is not neutral,
multi-stakeholder, or open governance, and no response/decision SLA is promised.

Normative changes start with a public proposal describing compatibility,
security/privacy, migration, both SDKs, vectors, and conformance impact. The
maintainer records the decision in the issue or pull request. Incompatible wire
changes require a new version; silent fallback and implementation-only protocol
changes are rejected. Sensitive findings follow [SECURITY.md](SECURITY.md).

Apache-2.0 remains the project license. DCO 1.1 applies prospectively after commit
`1fe370a0b64cbfa5a302c1a6a881f1d99a503c48`; the preceding 34 commits are
preserved and not represented as DCO-compliant. Every later contribution commit
needs at least one well-formed `Signed-off-by` matching its author. Additional
distinct valid co-sign-offs are allowed; malformed and duplicate sign-offs fail.

The repository verifier owns that immutable baseline and checks every commit from
it through the proposed head on every CI run; event-relative ranges are insufficient.
The head MUST descend from the baseline. The `main` ruleset requires pull requests,
linear history, rebase integration, and successful repository and CodeQL checks.
Squash and merge commits are disabled because a platform-generated final commit
would not be the commit checked for DCO. A release target MUST be a checked commit
on protected `main`. DCO is not an independent legal, provenance, IPR, or patent
review.
