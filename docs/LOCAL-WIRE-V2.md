# Experimental local wire v2

Historical local profile, retained for reference. The current implementation uses
[incompatible wire v3](LOCAL-WIRE-V3.md); the statements below describe v2.

This is a local, role-neutral protocol experiment, not a final standard or release
approval. Both Rust and Python use this contract. It is incompatible with v1;
there is no version negotiation or fallback. Apache-2.0 applies to the implementation.

## Transport and envelope

Only UTF-8 JSON over bounded loopback HTTP/1.1 is accepted. POST requests use
`/ordavyn/v2/<action>`, `x-ordavyn-version: 2`, and
`Content-Type: application/json`. No CBOR network input is accepted. HTTP headers
are limited to 8 KiB, bodies to 64 KiB, and network waiting to 3 seconds.

Every envelope has exactly these mandatory fields:

| Field | Value |
| --- | --- |
| `version` | integer 2 |
| `type` | `request`, `response`, `event`, or `error` |
| `id`, `operation_id`, `from`, `to`, `epoch` | AIM Identifier |
| `subject` | AIM Reference |
| `payload` | JSON value |
| `timestamp` | AIM Instant |
| `encoding` | `ordavyn-cbor-v2` |
| `signature_alg` | integer 1, or null in an unsigned message |
| `key_id` | 16 lowercase hex characters, or null in an unsigned message |
| `signature` | 128 lowercase hex characters, or null in an unsigned message |

Unsigned messages have all three signature fields null. Requests require a valid
Ed25519 signature before dispatch. The key ID is the first eight bytes of SHA-256
of the raw 32-byte public key, rendered in lowercase hex. There are no field aliases.
An Identifier has exactly `namespace`, `value`, `version`; a Reference has exactly
`target_type`, `target_id`, `closure_version`; an Instant has exactly `nanos`.
Optional AIM versions are always present as null or u64, including distinct zero.
All AIM numbers are integers in [0, 2^64-1]. Envelope namespaces are respectively
`message`, `logical-operation`, `participant`, `participant`, and `epoch`.
Identifier namespaces retain the lowercase ASCII a-z, 0-9, hyphen, dot and colon
alphabet. Namespace, value and Reference target type are nonempty and at most
256 UTF-8 bytes each. Subject target identifiers retain normal namespace checks.

## JSON value rules

Only Unicode scalar strings, booleans, null, arrays, objects with string keys,
integers in [-2^63, 2^64-1], and finite binary64 floats are supported. A fraction or
exponent in a JSON number denotes a float. Integer tokens outside the range and
the token `-0` are rejected before rounding; `-0.0` is valid and keeps its sign.
Integers, floats and booleans remain distinct. Rust uses exact float roundtrip
parsing. Duplicates are rejected at every object depth before conversion. Unknown
fields are rejected in envelope/AIM objects; payload objects allow arbitrary
string keys. No Unicode normalization is performed; lone surrogates are invalid.
The full value tree has depth at most 32, with the envelope root at depth 1 and
object/array child values increasing depth by one. Keys are strings, not child
containers. The same checks run on signing, verification, send and receive.

The complete envelope, including signature, has an independent 64 KiB deterministic
CBOR model budget, enforced for direct APIs, signing, verification and dispatch.
HTTP limits apply to the actual received or emitted JSON bytes. A receiver never
uses its own JSON formatting to decide whether an incoming model is admissible;
float spelling can differ between implementations. `to_json` limits its output,
while `from_json` limits its input. Internal dispatch uses only the model budget.

## Signed bytes

The signature input is ASCII `ordavyn:v2:message` followed by one zero byte,
followed by the CBOR envelope map with only `signature` removed. This includes
`signature_alg`, `key_id`, `encoding` and every other envelope field.

CBOR follows [RFC 8949 section 4.2.3](https://www.rfc-editor.org/rfc/rfc8949.html#section-4.2.3):
definite containers, shortest integers, shortest exact float16/32/64, and map keys
ordered by (encoded key byte length, encoded key bytes). Float values never become
integers. Positive and negative floating zero remain distinct. Arrays and maps
remain distinct. Tags are never emitted. Legacy tagged AIM helper encodings are
not part of this contract.

Rust uses ciborium with explicit recursive key ordering. Python pins cbor2 5.9.0
and uses `cbor2._encoder.dumps(..., canonical=True)`. Its pure Python encoder is
intentional: the C accelerator emits float32 for 65504.0 instead of exact float16.
The fixed float-boundary vector tests the workaround. Dependency upgrades require
rechecking these vectors; this is not a claim about untested cbor2 versions.
See [cbor2 API](https://cbor2.readthedocs.io/en/latest/api.html).

## Dispatch and refusal behavior

An executable request has `type="request"` and an object payload with a string
`action`. The endpoint `"/" + action` is at most 256 ASCII characters, uses only
letters A-Z/a-z, digits, slash, underscore and hyphen, contains no `//`, and does
not end with a slash. Thus action is nonempty; internal slash-separated actions
are allowed. The HTTP path must equal `/ordavyn/v2/` plus that action exactly,
and a handler for that route must be registered. Python passes the remaining
payload fields as handler keyword arguments; Rust passes the request envelope.

Authentication and explicit local sender/key/recipient/action rights are checked
before atomically reserving both message and operation IDs, before any handler.
An invalid signature, metadata change, foreign key, missing right, route mismatch,
repeated ID or exhausted journal cannot produce a new handler effect. Rejected
syntax/shape/version/numeric input never reaches a handler. Exact error text and
HTTP refusal status differ between SDKs and are not a stable error taxonomy;
callers must treat non-success as refusal. No normalization repairs invalid input.

Responses are separate unsigned envelopes with reversed participants and matching
operation, subject and epoch. Clients check this correlation. Handler failures
retain reservations. A model-valid handler result can still exceed the outgoing
JSON byte cap (for example through escaped strings). In that case the server
returns a small correlated error envelope and retains the reservation. Such an
error does not imply that no effect occurred; retrying the same request cannot
run the handler again. Existing status conventions differ: Python uses HTTP 403
for error envelopes and its client decodes those envelopes, while Rust sends
handler error envelopes with HTTP 200. Rust's client treats any non-200 response
as a transport error, including a Python handler-error response.
The journal is bounded and never evicts. Its default memory mode loses replay
protection on restart; the optional [local SQLite adapter](LOCAL-JOURNAL.md)
preserves reservations without changing wire v2. Unknown outcomes need application
reconciliation; no exactly-once external effect is promised. Local [revocation, rotation and admission stopping](LOCAL-LIFECYCLE.md) use SDK
management methods and add no wire fields or HTTP management routes. TLS, signed
responses, real operations, delegation and negotiation remain unsupported.
Handlers have no execution timeout. No publication, pre-push change, private-source
import or public-network operation is authorized by this implementation.

## Evidence

`implementation/tests/fixtures/wire-v2.json` holds fixed Ed25519 test keys,
envelopes, literal expected signable hex and signature hex. Tests never recreate
expected bytes at runtime. Vectors include Unicode ordering, null/empty containers,
integer boundaries, subnormal/float64 values, the float16 boundary, signed zero,
integer 1 versus float 1.0, and optional null versus zero.
Rust and Python tests independently sign and cross-verify these vectors.
`implementation/tests/test_interop.py` starts the real SDKs on loopback in both
directions and checks counters after valid requests, malformed input, tampering,
permissions and replay refusals. Test processes have deadlines and cleanup.
Passing these checks does not establish production readiness or certification.
