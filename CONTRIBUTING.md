# Contributing to Ordavyn

Ordavyn is an experimental, unpublished protocol candidate. Contributions should preserve Native Architecture-First design and role-neutral agent, service, and B2B interaction. Open a defect report for reproducible behavior or a change proposal for new scope. Suspected vulnerabilities follow [SECURITY.md](SECURITY.md), not public issues.

Keep changes focused. Explain compatibility, security, replay, and migration effects; update Rust and Python behavior together where the protocol requires parity. Do not include private planning, credentials, production data, or claims of certification or release readiness.

Before a pull request, run:

```sh
python3 -m pytest -q tools/tests
python3 tools/verify_guides.py --root .
cargo +1.98.1 test --manifest-path implementation/Cargo.toml --locked
python3 -m pytest -q implementation/python-sdk/tests implementation/tests
git diff --check
```

The complete local candidate procedure is documented in [release/README.md](release/README.md). Passing checks does not authorize publication.
