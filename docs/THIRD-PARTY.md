# Third-party dependency evidence

Ordavyn's own code is Apache-2.0 by the owner's selection. This does not relicense
its dependencies. The source archive and Ordavyn wheel/sdist contain no vendored
Cargo registry sources, dependency wheels or compiled Rust binaries. They retain
the project's LICENSE. Dependency downloads and built test binaries are private
verification inputs, not approved distribution artifacts.

The exact Rust versions and registry SHA-256 checksums are in
[Cargo.lock](../implementation/Cargo.lock). The exact Python verification versions
and allowed upstream hashes are in
[verification requirements](../release/verification-requirements.txt); SDK runtime
requirements remain unchanged. The private inventory retains dependency graph,
features, target conditions, original license expressions (including AND/OR),
archive hashes, and LICENSE/NOTICE file hashes. Runtime, build and development
inputs are separate roles; a shared input may serve more than one role.
All 135 locked registry archives matched their lock SHA-256 on 2026-09-29.
Separate notice files were not found in r-efi 5.3.0/6.0.0 and rsqlite-vfs 0.1.1;
those notice checks remain UNKNOWN despite matching archive hashes.
Only Linux x86_64 is exercised. Downloading another target's source does not test it.

## Nested components requiring distinct treatment

| Input | Nested component evidence | Distribution implication |
| --- | --- | --- |
| ring 0.17.14 | `LICENSE` directs readers to ISC `LICENSE-other-bits`, Apache-2.0 `LICENSE-BoringSSL`, file-level notices, once_cell MIT/Apache texts and fiat-crypto's Apache-2.0 text | Preserve all applicable notices and attribution when redistributing those sources or binaries; the wrapper license alone is insufficient. |
| libsqlite3-sys 0.36.0 | Bundled SQLite amalgamation reports 3.51.1; source and header hashes are recorded. SQLite has its own [public-domain declaration](https://www.sqlite.org/copyright.html). | The wrapper's license is not SQLite's declaration. Python's system SQLite is a separately recorded environment component. |
| cryptography 50.0.1 Linux wheel | Runtime reports OpenSSL 4.0.2. PyCA documents [statically linked wheels](https://cryptography.io/en/latest/installation/#static-wheels). The wheel contains cryptography's Apache/BSD texts; upstream OpenSSL has its own [Apache-2.0 license](https://github.com/openssl/openssl/blob/openssl-4.0.2/LICENSE.txt). | OpenSSL and other binary internals need their own attribution review. The attempted versioned OpenSSL NOTICE URL was unavailable; complete binary notice mapping remains UNKNOWN. |
| Build/development wheels | Tools such as setuptools and pip contain vendored components with their own notice files | These are not embedded in the Ordavyn wheel. Their own redistribution is outside the approved candidate. |

No dependency or its notice is removed because it contains an old name. No
upstream source has been copied into Ordavyn as part of this preparation. If a
future artifact embeds dependency code, its notice bundle must be determined for
that actual artifact before distribution; this summary cannot substitute for it.

## Dated advisory checks

On 2026-09-29, official PyPI JSON was fetched for the 14 pinned verification inputs;
its vulnerability arrays were empty. The official RustSec database snapshot is
`f23b768236fe2880e4cfa167da662cad8ca79240`; matching considers every locked version,
including multiple versions of a crate. The unsupported `rustls-pemfile` wrapper
has been removed; PEM parsing uses the already present `rustls-pki-types` API.
RustSec conditions are evaluated by pinned Rust `semver 1.0.28`, with source and
helper hashes recorded in private evidence. Invalid conditions, invalid versions,
helper failures and inaccessible sources remain UNKNOWN. The reviewed candidate's
fresh private audit and independent verifier both classify 46 matches
NOT_AFFECTED and one withdrawn informational advisory WITHDRAWN, with no UNKNOWN
or BLOCKER; both record the same helper binary hash.
A dated absence of matching
vulnerability records is not a security guarantee. No new runtime requirement is
introduced.
