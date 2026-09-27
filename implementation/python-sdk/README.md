# Ordavyn Python SDK

Local, role-neutral protocol prototype for simulated participant interactions.
Every exposed action requires an Ed25519 signature and an explicit local permission.
Only loopback HTTP/1.1 with JSON is implemented. This package is not an approved
release. The owner selected Apache-2.0 on 2026-09-27; LICENSE contains its standard
text. Rights to inherited material and attribution remain under review. Publication
of this candidate is not authorized; package metadata is not legal clearance.

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
server = Ordavyn(port=0, participant=service)
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

Requests use `/ordavyn/v1/<action>` and `x-ordavyn-version: 1`. The signed action
must match the exact route, and the key grant must match the sender, this server's
recipient and the action. The journal reserves IDs atomically before execution;
it holds at most 10,000 requests by default and fails closed without eviction.
HTTP headers are limited to 8 KiB, bodies to 64 KiB, network waiting to 3 seconds.
Handler execution itself is trusted application code and has no time limit.
Passing a framework app, such as `Ordavyn(app=...)`, is rejected: framework adapters
are not implemented.

Python signs sorted compact UTF-8 JSON, including signature algorithm, key ID and
encoding. Rust uses a different CBOR signing format and a different envelope;
these prototypes are not wire- or signature-interoperable. Responses are separate
unsigned messages. Clients validate correlation and metadata, but do not provide
an authenticated remote-response channel.

Unsupported: TLS, delegation, negotiation, post-quantum cryptography, streaming
transport, CBOR transport decoding and CBOR decoder resource-limit enforcement.
Rust's CBOR nesting/collection constants are proposed values, not enforced limits.
Replay protection is process-local and disappears on restart. Passing local tests
is not security certification, protocol certification or legal clearance.

Grants are static local configuration; full runtime key revocation is not
implemented (B4). `stop()` does not cancel a running handler, which may still
complete its effect (B6). Do not restart while a handler is active: `start()` rejects
an existing live server thread. Wait for application work to finish before reuse.
