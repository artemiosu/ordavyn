# Reproduce the local candidate

This procedure creates local evidence only. It never publishes, edits Git history,
configures a remote, removes protective metadata or authorizes a release.
Use a clean reviewed commit containing `release/files.json`; every tracked path
must have an explicit include/exclude classification. Ignored local materials are
not read by the exporter. New untracked nonignored or changed tracked files cause
refusal. Output directories must not exist; choose new names for later runs.

Before the heavier candidate procedure, validate public guides and the GitHub
repository package locally:

```sh
python3 -m pytest -q tools/tests
python3 tools/verify_guides.py --root .
```

The second command rejects missing community files, mutable Action references,
unapproved write permissions, secret references and publication-capable triggers.
It uses only the public checkout and does not publish or inspect private paths.

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
/tmp/ordavyn-verify-env/bin/python tools/audit_dependencies.py --root . --online --download-cargo --wheelhouse /tmp/ordavyn-verify-wheels --output .ordavyn-private/release-candidate/dependency-audit-new
python3 tools/release_candidate.py export --commit HEAD --output .ordavyn-private/release-candidate/source-a
python3 tools/release_candidate.py export --commit HEAD --output .ordavyn-private/release-candidate/source-b
cmp .ordavyn-private/release-candidate/source-a/source.tar.gz .ordavyn-private/release-candidate/source-b/source.tar.gz
mkdir /tmp/ordavyn-source-verify
tar -xzf .ordavyn-private/release-candidate/source-a/source.tar.gz -C /tmp/ordavyn-source-verify
/tmp/ordavyn-verify-env/bin/python tools/verify_candidate.py --dependency-report .ordavyn-private/release-candidate/dependency-audit-new/dependencies.json --repo . --commit "$(git rev-parse HEAD)" --archive .ordavyn-private/release-candidate/source-a/source.tar.gz --root /tmp/ordavyn-source-verify --manifest .ordavyn-private/release-candidate/source-a/manifest.json --wheelhouse /tmp/ordavyn-verify-wheels --output .ordavyn-private/release-candidate/verification-a
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
are retained. RustSec matching uses pinned Rust `semver` through the freshly built
verification-only helper; malformed input or helper failure remains UNKNOWN. It
can additionally read the separately fetched
`.ordavyn-private/release-candidate/rustsec.tar.gz`; record its official URL, commit
and SHA-256 in `rustsec.tar.json` alongside it. Online audit fetches the immutable official URL and compares response bytes with
the archive; only then can a freshly fetched matching HEAD establish freshness.
Prepare the reviewed immutable snapshot before the online audit. This example
writes only to a local private directory; it neither publishes nor changes Git:

```sh
python3 - <<'PYTHON'
from pathlib import Path
import hashlib, json, urllib.request
commit = "f23b768236fe2880e4cfa167da662cad8ca79240"
url = "https://api.github.com/repos/RustSec/advisory-db/tarball/" + commit
output = Path(".ordavyn-private/release-candidate")
output.mkdir(parents=True, exist_ok=True)
# These exclusive writes preserve any previous evidence. Use a fresh workspace
# or retain the already reviewed files when they already exist.
with urllib.request.urlopen(url, timeout=30) as response:
    archive = response.read()
with (output / "rustsec.tar.gz").open("xb") as target:
    target.write(archive)
with (output / "rustsec.tar.json").open("x") as target:
    json.dump({"url": url, "commit": commit,
               "sha256": hashlib.sha256(archive).hexdigest()}, target, indent=2)
PYTHON
```

The explicit URL is the official RustSec GitHub repository at the reviewed commit.
If the download is unavailable, retain the failure and run the audit with missing
evidence: its RustSec status remains UNKNOWN. The example does not assert that
this snapshot is still current; the online audit separately compares official
archive bytes and current HEAD.

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
`~/.cargo/registry/index` and `~/.rustup` toolchains are host prerequisites.
Only Cargo.lock-verified crate archives are copied into a fresh Cargo cache. Cargo
extracts source anew; registry/src is never linked to the host. Active Linux
graph and extracted payload hashes are recorded in rust-inputs.json and bound to
the result. Unused target dependencies remain untested; this is not hermetic. User PATH, PYTHON*, pytest
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

Wheel/sdist source and generated file permissions must be 0644 and directory
permissions 0755, with one exact exception: the pinned wheel writer explicitly
sets `ordavyn-0.1.0.dist-info/RECORD` to 0664 regardless of umask. That path must
have exactly 0664; the exception does not apply to any other archive member.
Verification records each archive member's mode, size and SHA-256. Separate command
logs establish 97 Rust tests and 249 SDK plus 159 recovery/TLS tests in each package
installation; skipped, ignored or filtered suites cannot produce TESTS_PASS.
Python dependency license/notice evidence comes from hash-verified wheels, not
mutable installed distributions. Missing/mismatched components stay UNKNOWN while
other available evidence remains in the report.

Commit the reviewed tools and locks before generating fresh dependency evidence.
The required dependency report carries its source commit, both lock hashes, the
audit/helper source hashes and the helper binary hash. The runner verifies these
against Git and binds its report
hash to the result. Evidence from another commit is explicitly identified and
accepted only with identical lock bytes and an auditor hash matching both
commits. Executing
verifier modules must match the chosen source commit. Each Ordavyn installation
records the requested wheel or sdist digest and compares installed payload bytes
with the already verified reference wheel. Public Python allowlist drift blocks
audit completeness; unreviewed names are never queried. Cached Rust source checks
compare directly with the lock-verified archive, not a mutable checksum map.
