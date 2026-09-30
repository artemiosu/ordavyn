# Ordavyn local wire v3 — Draft 0.1

## Status and scope

This prepared draft specifies only the implemented loopback wire-v3 profile. The
capitalized key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and
**MAY** use RFC 2119/RFC 8174 meanings. The profile is experimental, role-neutral,
and neither a standard nor a production or remote-deployment profile.

## Data and trust model

An Identifier is exactly `{namespace, value, version}`. Namespace uses non-empty
lower-case ASCII letters, digits, `-`, `.`, or `:`; value is a non-empty string;
version is unsigned 64-bit or null. Namespace and value are at most 256 UTF-8
bytes. A Reference is exactly `{target_type, target_id, closure_version}` with a
non-empty target type of at most 256 UTF-8 bytes and unsigned-64-or-null closure.
An Instant is exactly `{nanos}` with an unsigned 64-bit value. Trust is local and
explicit: receivers bind a full 32-byte Ed25519 key to one participant and action
set; clients separately pin the responder's full key and participant.

#### ORD-ENV-001 — Strict envelope and JSON values

A message MUST be one UTF-8 JSON object containing exactly `version`, `reply_to`,
`request_digest`, `type`, `id`, `operation_id`, `subject`, `from`, `to`, `epoch`,
`payload`, `signature_alg`, `key_id`, `signature`, `timestamp`, and `encoding`.
Unknown/duplicate fields, duplicate keys, lone surrogates, non-finite numbers,
integers outside `[-2^63,2^64-1]`, integer `-0`, and depth over 32 MUST fail.
Strings, booleans, null, arrays, string-keyed objects, bounded integers, and finite
binary64 floats are supported. Fraction/exponent syntax makes a float: integer
`1`, float `1.0`, float `-0.0`, and float `0.0` remain distinct signed values.
No Unicode normalization occurs. Optional fields remain present as null.

#### ORD-ENV-002 — Envelope semantics

Version MUST be integer `3`; encoding MUST be `ordavyn-cbor-v3`; type MUST be
`request`, `response`, `event`, or `error`. The ID namespaces are respectively
`message`, `logical-operation`, `participant`, `participant`, and `epoch` for
`id`, `operation_id`, `from`, `to`, and `epoch`. Request/event binding fields MUST
be null; response/error `reply_to` MUST be a message ID and `request_digest` 64
lower-case SHA-256 hex characters. Event is codec-only in Draft 0.1: dispatch,
delivery, acknowledgement, and event replay semantics are unsupported. Signed and
unsigned event envelopes can be codec-valid, but Draft 0.1 consumers MUST reject
them at admission and MUST NOT dispatch them.

`timestamp.nanos` is an opaque application-supplied logical instant. Admission
does not compare it with wall-clock time, enforce freshness, or establish expiry.

#### ORD-CAN-001 — Deterministic signing input

The signing input MUST be ASCII `ordavyn:v3:message`, a zero byte, then RFC 8949
deterministic CBOR of the complete envelope with only `signature` removed.
Containers are definite; integers and exact floats use their shortest encoding;
float values never become integers; signed floating zeros remain distinct. Map
keys sort first by encoded-key byte length and, for equal lengths, by
lexicographic encoded bytes. Tags are not emitted. JSON formatting/order has no
effect.

#### ORD-SIG-001 — Ed25519 authentication

Signed messages MUST use algorithm integer `1`, a key ID equal to the first eight
SHA-256 bytes of the raw key as 16 lower-case hex characters, and a 64-byte RFC
8032 PureEdDSA signature as 128 lower-case hex characters. PureEdDSA signs the
input directly. Admitted requests and every produced protocol result MUST be
signed; the three signing fields are otherwise all null.

#### ORD-BIND-001 — Complete request binding

The response digest MUST be SHA-256 of ASCII `ordavyn:v3:request-binding`, a zero
byte, and deterministic CBOR of the complete final signed request, signature
included. Results copy request `id` to `reply_to`. Clients MUST bind to the exact
retained request snapshot; an operation/message ID alone is insufficient.

## Admission, replay, and lifecycle

#### ORD-ADM-001 — Admission order

An executable request payload MUST be an object containing string `action`.
`"/" + action` is non-empty, at most 256 ASCII bytes, uses letters, digits, `/`,
`_`, `-`, has no `//`, and does not end `/`; internal segments are allowed. The
route MUST exactly equal `/ordavyn/v3/<action>`. Before reservation or handler
execution, the receiver MUST validate envelope/model budgets, request/recipient,
route/action, registered handler, open gate, full key/participant/action grant,
and signature. Revoked, unknown, mismatched, or unauthorized input fails closed.

#### ORD-REP-001 — Replay barrier

Admission MUST atomically reserve `(sender,message-id)` and
`(sender,operation-id)`. Either collision rejects the request. Initial state is
`outcome_unknown`; a returned, serializable success becomes `handler_returned`.
Handler, serialization, signing, journal, and send failures MUST NOT remove the
barrier. Default capacity is 10,000; a configured positive capacity is journal
metadata. Full capacity fails closed without eviction or handler execution.
Memory is process-local; explicitly provisioned SQLite preserves barriers.

#### ORD-LIFE-001 — Local lifecycle

Stop closes admission before waiting. Already admitted handlers MAY finish;
bounded stop MAY report incomplete. Resume requires no active work and preserves
barriers. Grant replacement/revocation/rotation affects later admission, not an
admitted handler or the response signer.

#### ORD-RESP-001 — Correlated results

Produced response/error envelopes MUST be signed and use HTTP 200. They reverse
participants and copy operation, subject, epoch, reply-to, and digest. Before
returning a result, clients MUST verify type, all correlation fields, full key and
participant pins, key ID, and signature. Missing signer or pins fails closed.

#### ORD-ERR-001 — Errors and unknown outcomes

An implementation-generated protocol error payload MUST be an object containing
a string `error`. Exact wording, stable error codes/classes, and localization are
not specified. Error payloads deliberately returned by an application handler are
application-defined. A valid addressed signed refusal is correlated and signed
when a bounded result can be made. Malformed transport MAY get an unauthenticated
non-200 response, never an application result. Post-send failure is an unknown
outcome; clients retain and reconcile the request. No retry or exactly-once effect
is promised.

## Transport and resource profile

#### ORD-HTTP-001 — Local HTTP/1.1

Transport MUST use loopback TCP. Requests MUST use HTTP/1.1 POST, the exact action
route, `Content-Type: application/json`, `x-ordavyn-version: 3`, exactly one
positive decimal `Content-Length`, no transfer encoding, and connection-close
semantics. Responses MUST use HTTP/1.1, `Content-Type: application/json`,
`x-ordavyn-version: 3`, exactly one positive decimal `Content-Length`, and
connection-close semantics; authenticated protocol results use status 200, while
malformed transport can use non-200. Receivers of either direction MUST reject
duplicate header names case-insensitively. Cleartext is an explicit local test
mode without confidentiality. No v1/v2 or TLS/cleartext fallback exists.
SDK-specific malformed non-200 formatting is outside authenticated conformance.

#### ORD-TLS-001 — Optional TLS

TLS MUST be 1.3 with ALPN `http/1.1`, explicit server PEM chain/key, and explicit
client PEM roots plus expected DNS/IP SAN. Chain, validity, and SAN are checked;
CN-only matching, system roots, early data, insecure verifiers, and mTLS are
unsupported. Connections target numeric loopback. The expected DNS/IP name is
only a SAN input and never initiates DNS. TLS identity and protocol pin are
separate checks.

#### ORD-LIM-001 — Budgets

JSON body and deterministic-CBOR model are each at most 65,536 bytes; headers at
most 8,192 bytes. A client has one end-to-end three-second budget across connect,
TLS handshake, request write, and response read. A one-shot server has one
three-second budget across waiting for accept, TLS handshake, read, and write. A
persistent server's pre-accept wait is outside the budget; each accepted connection
gets a new three-second handshake/read/write budget. These budgets do not reset.
Handler execution is outside the I/O budget and is not forcibly cancelled, but it
can consume all time remaining before the response write. Oversize fallbacks are
re-signed and checked against both size budgets.

## Evolution, privacy, and evidence

#### ORD-VER-001 — Versioning and extensions

V3 is incompatible with v1/v2. There is no negotiation, fallback, ignored/vendor
field, or extension registry. Wire/canonicalization/signing/binding/admission or
transport changes require reviewed revision plus Rust, Python, vector, migration,
security, and conformance updates. Unknown fields fail closed.

#### ORD-PRIV-001 — Privacy boundary

Signatures do not provide confidentiality. Cleartext exposes data locally; TLS
protects loopback transport only. Implementations SHOULD minimize payload/logs,
MUST NOT treat journals as secret stores, and MUST exclude journals, keys,
certificates, private planning, and production data from source export.
Automated path, extension, and byte-pattern checks only detect their enumerated
cases; they do not prove arbitrary prose is free of private or production data.
A manual review of the exact release contents remains required.

#### ORD-CONF-001 — Evidence boundary

Claims require applicable positive and negative tests, using published vectors
where applicable. Lifecycle, storage, governance, and export requirements may use
tests without wire vectors. Shared vectors and repository SDKs are regression
evidence, not an independent oracle, certification, audit, or independent
implementation. The versioned unsupported inventory MUST remain explicit.
