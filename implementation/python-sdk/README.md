# Ordavyn Python SDK

Local, role-neutral protocol prototype for simulated participant interactions.
Every exposed action requires an Ed25519 signature and an explicit local permission.
Only loopback HTTP/1.1 with JSON is implemented. This is an experimental source
package with no supported registry release. LICENSE contains the standard
Apache-2.0 text. Rights and attribution remain separate from technical verification;
package metadata is not legal clearance.

## Install a local artifact

Python 3.10 or newer is required. From the directory containing a locally built
artifact, install either the wheel or the source archive into a fresh environment:

```sh
python -m venv /tmp/ordavyn-example-env
/tmp/ordavyn-example-env/bin/python -m pip install ./ordavyn-0.1.0-py3-none-any.whl
# Alternative: use ./ordavyn-0.1.0.tar.gz instead of the wheel above.
/tmp/ordavyn-example-env/bin/python -m pip check
```

To build artifacts from the SDK source directory containing this README and
`pyproject.toml`, run `python -m pip install build`, then `python -m build .`.
The resulting wheel and source archive are written to `dist/`. These commands
build locally and do not publish anything.

## Minimal working example

Save this as `/tmp/ordavyn_example.py`, then run it from any directory with
`/tmp/ordavyn-example-env/bin/python /tmp/ordavyn_example.py`:

```python
from ordavyn import Ordavyn, Ed25519Keypair, Identifier, MessageBuilder, MessageType

caller = Identifier('participant', 'caller')
service = Identifier('participant', 'service')
key = Ed25519Keypair.generate()
server = Ordavyn(port=0, participant=service, signer=Ed25519Keypair.generate())
server.trust(key.public_key_bytes(), caller, ['status'])

@server.expose('/status')
def status():
    return {'ready': True}

request = MessageBuilder(caller, service).payload({'action': 'status'}).build()
server.start()
try:
    client = server.client(key)
    response = client.send('/status', request)
    repeated = client.send('/status', request)
    assert response.msg_type == MessageType.RESPONSE
    assert response.payload == {'ready': True}
    assert repeated.msg_type == MessageType.ERROR
    print('Authorized request succeeded; replay rejected')
finally:
    server.stop()
```

The server chooses an available local port and keeps all data in memory. The
client signs a copy of the request; the original remains unchanged. Reusing its
message or operation ID is rejected even when a handler failed after beginning.

## Implemented boundaries

Requests use `/ordavyn/v3/<action>` and `x-ordavyn-version: 3`. The signed action
must match the exact route, and the key grant must match the sender, this server's
recipient and the action. The journal reserves IDs atomically before execution;
it holds at most 10,000 requests by default and fails closed without eviction.
HTTP headers are limited to 8 KiB, bodies to 64 KiB, network waiting to 3 seconds.
Handler execution itself is trusted application code and has no time limit.
Passing a framework app, such as `Ordavyn(app=...)`, is rejected: framework adapters
are not implemented.

Python and Rust share the experimental v3 envelope and domain-separated
canonical CBOR signatures (`ordavyn-cbor-v3`). Transport remains strict JSON.
All envelope/AIM fields are mandatory, with explicit nulls for optional values.
Versions 1/2, old encodings, duplicate or unknown envelope/AIM fields, invalid numeric
types, out-of-range integers and trees deeper than 32 are rejected.
The pinned cbor2 5.9.0 Python encoder supplies shortest exact floats; its C
accelerator is deliberately bypassed because of its 65504.0 boundary encoding.
Responses and errors are signed and bound to the full signed request. A local
response public-key/participant pin is required before network I/O.

Unsupported: delegation, negotiation, post-quantum cryptography, streaming
transport, CBOR transport decoding and CBOR decoder resource-limit enforcement.
Rust's CBOR nesting/collection constants are proposed values, not enforced limits.
Default memory replay protection disappears on restart. Explicit SQLite storage
preserves reservations across restarts and SDK changes. Passing local tests
is not security certification, protocol certification or legal clearance.

Local grants can be narrowed with `trust`, removed with `revoke(public_key)`, or
moved atomically with `rotate_key(old_key, new_key)`. `request_stop()` closes all
admission, including direct calls. `stop(timeout=4.0)` returns whether handlers and
network work finished; a timeout does not cancel a handler. `resume()` or `start()`
reopens admission only after completion. Grants and replay protection survive
stop/resume. See [local lifecycle](../../docs/LOCAL-LIFECYCLE.md) for examples and
restart rules.


## Persistent local journal

Provision once with `SQLiteJournal.create(path, recipient, capacity)`. After a
restart use `SQLiteJournal.open(path, recipient, capacity)`; opening a missing,
corrupt or mismatched journal fails. Pass the object to
`Ordavyn(participant=recipient, replay_capacity=capacity, journal=journal, signer=signer)`.
`MemoryJournal` is the explicitly temporary alternative. `journal.inspect()`
provides local records; `outcome_unknown` requires application reconciliation and
`handler_returned` only records a valid normal local return. Both block replay.
Storage failure never falls back to memory. `stop()` does not close the journal;
`journal.close()` rejects active handlers. See the
[shared journal guide](../../docs/LOCAL-JOURNAL.md) for a restart example and limits.

See the [authenticated v3 exchange guide](../../docs/LOCAL-WIRE-V3.md) for explicit TLS 1.3 configuration,
protocol pins, HTTP test mode without confidentiality and the threat model.
