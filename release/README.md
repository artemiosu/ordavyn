# Reproduce the local candidate

This procedure creates local evidence only. It never publishes, edits Git history,
configures a remote, removes protective metadata or authorizes a release.
Use a clean reviewed commit containing `release/files.json`; every tracked path
must have an explicit include/exclude classification. Ignored local materials are
not read by the exporter. New untracked nonignored or changed tracked files cause
refusal. Output directories must not exist; choose new names for later runs.

The verification profile is Linux x86_64, CPython **3.13.15**, Rust **1.98.1**.
The default `rust-toolchain.toml` remains unchanged; all verification commands
explicitly select the pinned Rust version. Python runtime, build and development
versions are fixed solely for verification and do not narrow SDK requirements.
The hash-locked requirements include runtime (cryptography/cbor2/cffi/pycparser),
build (build/setuptools/wheel/pyproject_hooks), and development
(pytest/iniconfig/pluggy/Pygments/pip). Packaging is shared build/development input.
The installed interpreters, OS, C toolchain, SSL and SQLite versions/hashes are
recorded in the private environment report; these are host prerequisites, not a
claim of a portable fully hermetic build.

From the clean repository root, using CPython 3.13.15:

```sh
python3 -m venv /tmp/ordavyn-verify-env
/tmp/ordavyn-verify-env/bin/python -m pip install --require-hashes -r release/verification-requirements.txt
/tmp/ordavyn-verify-env/bin/python -m pip download --require-hashes --only-binary=:all: --no-deps -r release/verification-requirements.txt -d /tmp/ordavyn-verify-wheels
python3 tools/release_candidate.py export --commit HEAD --output .ordavyn-private/release-candidate/source-a
python3 tools/release_candidate.py export --commit HEAD --output .ordavyn-private/release-candidate/source-b
cmp .ordavyn-private/release-candidate/source-a/source.tar.gz .ordavyn-private/release-candidate/source-b/source.tar.gz
mkdir /tmp/ordavyn-source-verify
tar -xzf .ordavyn-private/release-candidate/source-a/source.tar.gz -C /tmp/ordavyn-source-verify
/tmp/ordavyn-verify-env/bin/python /tmp/ordavyn-source-verify/tools/verify_candidate.py --root /tmp/ordavyn-source-verify --manifest .ordavyn-private/release-candidate/source-a/manifest.json --wheelhouse /tmp/ordavyn-verify-wheels --output .ordavyn-private/release-candidate/verification-a
```

Only unpack an archive produced by the exporter or first independently verified
against its manifest. `verify-archive` accepts an expected path→SHA-256 JSON map
and rejects duplicate/traversal/link/private/key/journal paths, unknown files and
changed content. Source export additionally records size and executable mode.
`COMPOSITION-PASS` means source composition only; a successful `result.json` means
tests passed. Neither marks publication approved. A failed run has no success
result; retain it as evidence and create a new output directory after fixing cause.

The test runner builds Rust tests/release/examples with `--locked --offline`,
builds fresh wheel/sdist with the pinned builder, validates every archive member
and generated metadata byte, and installs each separately without fetching new
dependencies. It executes SDK, recovery, TLS, interoperability, demos and documented
examples from the unpacked candidate. A local Cargo cache for the locked Linux
build is required. Loopback networking must be available for behavioral tests.

For dependency evidence (only explicitly listed public Python names and locked
crates are sent to official endpoints):

```sh
/tmp/ordavyn-verify-env/bin/python tools/audit_dependencies.py --root . --online --download-cargo --output .ordavyn-private/release-candidate/dependency-audit-new
```

Cargo archives are matched to lock checksums, read without executing, and retained
privately when previously missing. Graph/conditions and all source/notice hashes
are retained. RustSec matching can additionally read the separately fetched
`.ordavyn-private/release-candidate/rustsec.tar.gz`; record its official URL, commit
and SHA-256 in `rustsec.tar.json` alongside it. The immutable official URL,
commit and archive hash must agree; freshness is UNKNOWN unless the freshly
fetched official HEAD also matches. A fetched index alone is not an advisory scan. The
limited matcher returns UNKNOWN for unsupported syntax. Name endpoint HTTP 404
is an observation, not a right to use a name. See [release blockers](../docs/RELEASE-STATUS.md).

History/secret scan, environment inventory, official download hashes and nested
component review are separate private evidence. Public fixture keys in the two
explicit `implementation/tests/fixtures/wire-v*.json` files are nonproduction
vectors; their exact hashes are recorded privately. Generated TLS private keys
live only in temporary test directories. Pattern scanning cannot certify that
arbitrary secrets or source similarity are absent. Wheel reproducibility is not
claimed; only repeated source-archive bytes are compared.
