# Experimental local wire v3

Both SDKs implement this incompatible local profile. Both participants must upgrade
together. v1/v2, their routes, headers and signing formats are rejected without
negotiation or fallback. The [v2 document](LOCAL-WIRE-V2.md) remains historical.
Native Architecture-First and role-neutral participant scope are unchanged.

## Envelope and signing

Transport is strict JSON over HTTP/1.1, route `/ordavyn/v3/<action>`, header
`x-ordavyn-version: 3`, content type `application/json`. `version` is integer 3;
`encoding` is `ordavyn-cbor-v3`. All v2 envelope and AIM fields, numeric types,
canonicalization and limits remain: explicit optional nulls, no unknown/duplicate
fields, tree depth 32, 64 KiB deterministic CBOR model and 64 KiB JSON body,
8 KiB HTTP headers. Signed actions must equal the route exactly.

Two additional fields are mandatory:

| Field | request/event | response/error |
|---|---|---|
| `reply_to` | null | complete AIM message identifier of request |
| `request_digest` | null | 64 lowercase hexadecimal SHA-256 characters |

Sign with Ed25519 PureEdDSA over ASCII `ordavyn:v3:message` + one zero byte +
length-first deterministic CBOR of every envelope field except `signature`.
The algorithm (1), key ID, both new fields and all metadata are signed. JSON
formatting does not affect signing bytes. The Python canonical cbor2 encoder and
Rust encoder retain the v2 shortest-float rules.

The binding digest is SHA-256 of ASCII `ordavyn:v3:request-binding` + one zero
byte + deterministic CBOR of the **complete signed request including signature**.
Clients retain the final request snapshot sent on the wire. An operation or
message ID alone is insufficient to bind a response.

## Trust and error contract

Each server requires an explicitly configured Ed25519 signing key for its local
participant. Python requires `signer=` at construction. Rust uses
`.with_signer(keypair)` before use/cloning; an unconfigured server cannot admit a
request. A signer cannot be replaced on a configured object; stop it and construct
a new object, optionally reopening the same journal. Incoming grant rotation and
revocation do not change the response signer.

Before sending, clients require the **full public key** and participant of the
expected responder, configured with `with_response_key(key, participant)` or the
Python constructor's `response_key=` and `participant=`. No key is learned from a
message or TLS certificate. Python `server.client(keypair, tls=...)` explicitly
pins that server's configured key/participant.

Clients verify signature, full key pin, response/error type, `reply_to`, digest,
reversed participants, operation, subject and epoch before returning anything to
the application. There is no automatic action retry. A byte-identical old answer
to an identical signed request is indistinguishable: freshness beyond a unique
request is not promised.

Every produced protocol response/error is signed and uses HTTP 200. Admission
refusals for a structurally valid signed request addressed to this server are
correlated signed errors. Malformed input may receive a bounded transport error
without an envelope; that is never an authenticated application result. Direct
APIs may raise/return transport errors for malformed input. Invalid handler values,
serialization limits and journal failures yield a signed error or unknown outcome;
they never release replay barriers. Oversize fallbacks are signed again and checked
against both budgets. Signer failure cannot produce an unsigned success.

## TLS and explicit HTTP test mode

TLS requires TLS 1.3, ALPN `http/1.1`, a PEM certificate chain/key on the server,
and explicit PEM CA roots plus an expected SAN DNS name/IP on the client. Chain,
validity and SAN checks are mandatory; CN-only matching and system-root trust are
not used. Early data and insecure verifier/context injection are unavailable.
Rust uses tokio-rustls 0.26 with rustls 0.23, locked dependencies and the ring provider.
Python uses stdlib ssl. Certificates and protocol pins protect separate boundaries.

Connections use loopback addresses only. A certificate name never initiates DNS.
Rust TLS URLs use `https://127.0.0.1:PORT`; Python selects TLS with `tls=`.
Plain HTTP remains an explicit local test mode **without confidentiality**. It still
requires signatures and pins. There is no automatic downgrade in either direction.

A single 3-second network budget includes connect/accept, handshake, read and write.
`serve_one` includes waiting for accept. Handshakes do not reset the budget. A bad
TLS peer does not terminate a persistent listener. Synchronous handlers cannot be
forcibly cancelled: [stop/resume](LOCAL-LIFECYCLE.md) accounts for handshakes, queued
workers, handlers and response preparation. A short stop may return false.

## Python TLS configuration

The application supplies temporary local test certificate files and an out-of-band
protocol public key. Never use the test fixture keys for real operations.

```python
from pathlib import Path
from ordavyn import Ordavyn, OrdavynClient, Ed25519Keypair, Identifier, ServerTLS, ClientTLS
service = Identifier('participant', 'service')
signer = Ed25519Keypair.generate()
server = Ordavyn(port=0, participant=service, signer=signer,
                 tls=ServerTLS('/tmp/test-chain.pem', '/tmp/test-key.pem'))
server.start()
client = OrdavynClient(port=server.port,
    response_key=signer.public_key_bytes(), participant=service,
    tls=ClientTLS(Path('/tmp/test-ca.pem').read_text(), 'test.local'))
# Add explicit caller grants/handlers and sign requests as in the SDK examples.
server.stop()
```

Rust equivalent configuration:

```rust
use ordavyn_core::{ClientTls, ServerTls, Ed25519Keypair, Identifier};
use ordavyn_core::transport::{OrdavynServer, OrdavynClient};
# fn configured() -> Result<(), Box<dyn std::error::Error>> {
let signer = Ed25519Keypair::generate();
let pin = signer.public_key();
let service = Identifier::new("participant", "service");
let server = OrdavynServer::with_policy(service.clone(), 10000)
    .with_signer(signer).with_tls(ServerTls::from_pem(
        &std::fs::read("/tmp/test-chain.pem")?, &std::fs::read("/tmp/test-key.pem")?)?);
let client = OrdavynClient::new("https://127.0.0.1:8443")
    .with_response_key(pin, service).with_tls(ClientTls::from_pem(
        &std::fs::read("/tmp/test-ca.pem")?, "test.local")?);
# Ok(()) }
```

The shared fixed vectors include signed requests, success/error replies and the
full-request digest. Live tests generate temporary certificates and test self/cross
SDK pairs, failed verification, uncertain effects and lifecycle limits. Passing
these checks is not certification or public release approval.
