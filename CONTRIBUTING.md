# Contributing to Ordavyn

Ordavyn is an experimental protocol in a public repository. Contributions should preserve Native Architecture-First design and role-neutral agent, service, and B2B interaction. Open a defect report for reproducible behavior or a change proposal for new scope. Suspected vulnerabilities follow [SECURITY.md](SECURITY.md), not public issues.

Read [GOVERNANCE.md](GOVERNANCE.md). DCO 1.1 applies to commits after
`1fe370a0b64cbfa5a302c1a6a881f1d99a503c48`. Every new commit needs at least one
well-formed author-matching trailer; distinct valid co-sign-offs are allowed,
while malformed or duplicate sign-offs are rejected:

```text
Signed-off-by: Your Name <your-email@example.com>
```

Use `git commit -s`. CI always validates every commit from the fixed adoption
baseline through the proposed head, and rejects a head outside that ancestry.
Until a repository ruleset checks final integration commits, use rebase/fast-forward,
or ensure a squash commit itself has an author-matching sign-off and validate the
new head from the same baseline. Do not release an unsigned generated merge.

Keep changes focused. Explain compatibility, security, replay, and migration effects; update Rust and Python behavior together where the protocol requires parity. Do not include private planning, credentials, production data, or claims of certification or release readiness.

Before a pull request, run:

```sh
python3 -m pytest -q tools/tests
python3 tools/verify_guides.py --root .
python3 tools/export_release.py --check
cargo +1.98.1 test --manifest-path implementation/Cargo.toml --locked
python3 -m pytest -q implementation/python-sdk/tests implementation/tests
git diff --check
```

The complete local candidate procedure is documented in [release/README.md](release/README.md). Passing checks does not create a supported package release or a production-readiness claim.
