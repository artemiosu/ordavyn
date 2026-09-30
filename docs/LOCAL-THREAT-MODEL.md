# Local authenticated-exchange threat model

This describes only the implemented v3 loopback simulation profile. It does not
complete the historical AA-3 architecture or approve production use. Ordavyn remains
Native Architecture-First and role-neutral; trust is configured locally, with no
central authority or mandatory commercial service.

| Threat | Implemented boundary | Remaining limitation |
|---|---|---|
| Network observation/modification | TLS 1.3 with explicit CA, validity and SAN checking | Explicit plain HTTP test mode has no confidentiality |
| Impersonated response author | Ed25519 signature and locally pinned full key/participant | Trusted key compromise defeats that identity boundary |
| Response substitution/replay across requests | Signed reply ID and digest of complete signed request | Identical request/answer replay is indistinguishable |
| Untrusted participant asks for an action | Explicit key/participant/action grant and atomic admission | A permitted handler is trusted application code |
| Duplicate message or logical action | Memory or optional durable SQLite barriers before handler | Physical journal rollback and external exactly-once are not prevented |
| Disconnect, delay or error after effect | No automatic retry; retained reservation and uncertain-outcome errors | Application must reconcile the external outcome |
| Bad configuration | Missing signer/pin rejected, explicit TLS roots, no insecure contexts/downgrade | An owner can explicitly configure the wrong trusted party |
| Resource exhaustion | Fixed model/body/header limits, deadlines, sequential network worker ownership | Global DoS, CPU exhaustion and unbounded handler execution are not prevented |

TLS identifies the configured endpoint under CA/SAN trust. It does not establish
protocol grants or the response participant. The protocol pin identifies the
message author. It does not establish external truth or authorize every action.
Grants decide admission. The journal records local admission and normal return,
not proof of external settlement. A handler can cause an effect before it fails,
before signing/serialization fails, or before a connection disappears. Client
transport/validation failures currently use ordinary SDK errors, not a dedicated
unknown-outcome result carrying request IDs. Applications must retain their request
identifiers for reconciliation; an exception does not mean that no effect occurred.

Local revoke/rotate/stop closes future admission according to lock ordering. Already
admitted handlers may finish. Rust cancellation retains blocking-worker accounting;
Python retains its accepted connection until handshake/handler completion. Resume
requires completion. There is no distributed revocation, remote cancellation,
transactional external-effect rollback, mTLS, discovery, delegation or exactly-once.

A compromised trusted process/key, malicious trusted handler, physical journal
rollback or global DoS remains outside this profile's protection. Test keys and
certificates are synthetic. No real operations, external deployment, package
release, remote configuration or pre-push changes are part of this work.
