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
/tmp/ordavyn-verify-env/bin/python tools/verify_candidate.py --repo . --commit "$(git rev-parse HEAD)" --archive .ordavyn-private/release-candidate/source-a/source.tar.gz --root /tmp/ordavyn-source-verify --manifest .ordavyn-private/release-candidate/source-a/manifest.json --wheelhouse /tmp/ordavyn-verify-wheels --output .ordavyn-private/release-candidate/verification-a
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
/tmp/ordavyn-verify-env/bin/python tools/audit_dependencies.py --root . --online --download-cargo --wheelhouse /tmp/ordavyn-verify-wheels --output .ordavyn-private/release-candidate/dependency-audit-new
```

Cargo archives are matched to lock checksums, read without executing, and retained
privately when previously missing. Graph/conditions and all source/notice hashes
are retained. RustSec matching can additionally read the separately fetched
`.ordavyn-private/release-candidate/rustsec.tar.gz`; record its official URL, commit
and SHA-256 in `rustsec.tar.json` alongside it. Online audit fetches the immutable official URL and compares response bytes with
the archive; only then can a freshly fetched matching HEAD establish freshness.
Offline sidecars are LOCAL_DECLARATION with UNKNOWN freshness, even when their
self-declared hash and commit agree. A fetched index alone is not an advisory scan. The
limited matcher accepts only stable full x.y.z comparisons and returns UNKNOWN
for partial, prerelease, build and unsupported syntax; malformed records are
reported separately without dropping the rest of the audit. Name endpoint HTTP 404
is an observation, not a right to use a name. See [release blockers](../docs/RELEASE-STATUS.md).

History/secret scan, environment inventory, official download hashes and nested
component review are separate private evidence. Public fixture keys in the two
explicit `implementation/tests/fixtures/wire-v*.json` files are nonproduction
vectors; their exact hashes are recorded privately. Generated TLS private keys
live only in temporary test directories. Pattern scanning cannot certify that
arbitrary secrets or source similarity are absent. Wheel reproducibility is not
claimed; only repeated source-archive bytes are compared.

The runner is launched from the trusted repository, not from an unverified archive.
Before any build or test it binds the archive SHA-256, unique manifest paths,
sizes, modes and all bytes to the explicitly supplied repository commit. It
rechecks the unpacked files. The output directory must be outside the unpacked
source and must not exist.

Each run creates a new HOME and Cargo configuration directory, allows only an
explicit environment, disables pytest plugin autoload and pip configuration,
and uses umask 022. Ancestor Cargo configuration is rejected. The existing
`~/.cargo/registry` and `~/.cargo/git` caches and `~/.rustup` toolchains are host
prerequisites; they are reused, not claimed hermetic. User PATH, PYTHON*, pytest
options, compiler flags/wrappers and Cargo environment overrides are not inherited.
Use a trusted CPython interpreter when launching these tools; runtime initialization
before the runner starts is outside its environment sanitization boundary.

The runner first selects all 14 concrete offline wheels by lock digest, copies
only verified wheels to a private run directory, creates a separate clean build
venv and installs with `--require-hashes --only-binary=:all:`. Every installed wheel
payload file (except pip-regenerated RECORD) is compared to those exact wheel
bytes; installed name/version alone is insufficient. Build-input evidence and the
automatically created environment inventory are hash-linked in result.json.
Environment evidence includes interpreter/toolchain binary paths, SHA-256 and
versions, SSL/SQLite versions and extension hashes, plus allowed settings.

Wheel/sdist file permissions must be 0644 and directory permissions 0755.
Verification records each archive member's mode, size and SHA-256. Separate command
logs establish 96 Rust tests and 249 SDK plus 154 recovery/TLS tests in each package
installation; skipped, ignored or filtered suites cannot produce TESTS_PASS.
Python dependency license/notice evidence comes from hash-verified wheels, not
mutable installed distributions. Missing/mismatched components stay UNKNOWN while
other available evidence remains in the report.
