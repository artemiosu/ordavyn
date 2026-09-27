# Ordavyn release status

Local migration candidate only. Publication remains blocked by unresolved provenance/attribution
and the need for a separately approved public file set. No push or publication was
performed; the local pre-push hook remains a blocking control.

Implemented locally: protected request dispatch in Python and Rust; Ed25519 signature
and metadata verification; explicit participant/recipient/action bindings; atomic,
bounded message and operation replay reservation; separate unsigned responses; exact
routes; bounded loopback HTTP/1.1; Ordavyn package and incompatible wire names; repaired
wheel/sdist contents; simulations using the SDK's protected server.

Limitations: journal state lasts one process and is never evicted; a restart loses
replay protection. Handler failure does not undo an effect and does not release its
reservation. Handlers themselves are application code and have no execution timeout.
Rust CBOR and Python JSON signatures/envelopes are not interoperable. Responses are
unsigned. Delegation, negotiation, PQ and TLS are not implemented. No production,
real transactions or public network exposure is authorized.

Verification evidence is retained in the excluded local implementation report.
Passing tests is not a security audit, legal clearance or protocol certification.
The original Apache text and conflicting Cargo declaration are preserved externally;
see [PROVENANCE.md](PROVENANCE.md). On 2026-09-27 the owner selected Apache-2.0.
Standard license files and package metadata now reflect that selection; no
rights-holder identity was invented and no third-party rights were established.

CBOR transport decoding, CBOR decoder resource-limit enforcement and streaming
transport are unsupported. Rust CBOR depth/collection constants are proposed
values only; they are not enforced decoder limits and their values do not prove
resource protection. The implemented HTTP JSON byte limits are separate.
HTTP/2 streams and concurrent-stream limits are also unsupported.

Further release checks remain open. Migration does not establish name or trademark
rights, domain availability, or public package-name availability. Provenance,
dependency and secret checks for the exact proposed public snapshot must still be
completed. Public specifications and governance documents require separate curation
and review. Earlier AD-15/AD-16 release conditions are not declared satisfied by this
work. The license selection and explicit owner publication approval do not replace
these checks; no legal determination is made here.

Deferred limitations B4/B6: grants are static local configuration, not a complete
runtime key-revocation mechanism. Stopping the Python server closes its listener
but does not cancel an already running handler; that handler may still finish its
effect. Do not restart while a handler is active; start rejects an existing live
server thread. These limits are not resolved by the current request protections.

Final local verification (2026-09-27): 66 Rust tests and release build passed;
97 Python behavioral tests passed against each independently installed wheel and
sdist. Both demos and the SDK README example passed in both environments. Three
BMAD review lenses were completed and accepted fixes were verified. The two
deferred lifecycle limitations above remain open. These are local test results,
not release approval or independent protocol certification.

License-selection follow-up (2026-09-27): standard Apache-2.0 text was checked
byte-for-byte in all four local LICENSE files, the rebuilt wheel and sdist.
Wheel metadata declares Apache-2.0 and retains its private classifier; Cargo
metadata declares Apache-2.0 and retains `publish = false`. The Rust package
file list includes LICENSE. No runtime code changed; the behavioral test counts
above refer to the preceding implementation verification, not a new test run.
The pre-push hook is byte-for-byte unchanged.
