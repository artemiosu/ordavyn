# Ordavyn local tutorial

Use only simulated data and loopback connections. Install the wheel into a fresh
environment and run demos from outside the source tree. With the repository at
`/home/art/projects/ordavyn`:

```sh
python -m venv /tmp/ordavyn-demo-env
/tmp/ordavyn-demo-env/bin/python -m pip install build
/tmp/ordavyn-demo-env/bin/python -m build /home/art/projects/ordavyn/implementation/python-sdk
/tmp/ordavyn-demo-env/bin/python -m pip install /home/art/projects/ordavyn/implementation/python-sdk/dist/ordavyn-0.1.0-py3-none-any.whl
/tmp/ordavyn-demo-env/bin/python -m pip check
cd /tmp
/tmp/ordavyn-demo-env/bin/python /home/art/projects/ordavyn/implementation/demo/demo_ecommerce.py
/tmp/ordavyn-demo-env/bin/python /home/art/projects/ordavyn/implementation/demo/demo_multi.py
```

An sdist can be installed instead using `dist/ordavyn-0.1.0.tar.gz`. Both package
formats include README and the unresolved licensing notice. Nothing is uploaded.

The first demo simulates one order and rejects its replay. The second exchanges
authorized requests in both directions between two services. Both allocate ephemeral
ports, create keys in memory and stop their servers on completion.

Minimal setup:

```python
from ordavyn import Ordavyn, Ed25519Keypair, Identifier, MessageBuilder

caller = Identifier('participant', 'caller')
service = Identifier('participant', 'service')
key = Ed25519Keypair.generate()
server = Ordavyn(port=0, participant=service)
server.trust(key.public_key_bytes(), caller, ['status'])

@server.expose('/status')
def status():
    return {'ready': True}

server.start()
try:
    request = MessageBuilder(caller, service).payload({'action': 'status'}).build()
    response = server.client(key).send('/status', request)
    print(response.payload)
finally:
    server.stop()
```

All exposed actions require explicit permissions, including read-only actions.
Passing a framework app to `Ordavyn(app=...)` raises an error: FastAPI/Flask adapters
are not implemented. The standalone server uses the same security gate as direct
`_handle_request` calls. Calling a decorated Python function yourself is ordinary
application code, outside protocol dispatch.
