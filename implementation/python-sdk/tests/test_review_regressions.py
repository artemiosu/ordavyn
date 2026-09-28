
from ordavyn import Ed25519Keypair, Identifier
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
TEST_SIGNER = Ed25519Keypair(Ed25519PrivateKey.from_private_bytes(bytes([99])*32))
import json
import socket
import threading
import time
import pytest
from ordavyn import Ed25519Keypair, Identifier, MessageBuilder, MessageType
from ordavyn.crypto import canonical_json_bytes
from ordavyn.security import SecurityPolicy
from ordavyn.client import OrdavynClient, VERSION_HEADER
from test_security import setup


def test_canonical_json_rejects_collisions_and_non_json_containers():
    for invalid in ({'nested': {1: 'value'}}, {'nested': (1, 2)}, {'nested': {1, 2}}, {'n': float('nan')}, {'n': float('inf')}):
        with pytest.raises(ValueError): canonical_json_bytes(invalid)
    valid = {'nested': [{'1': 'value', 'all': [None, True, False, 0, 1.5]}]}
    assert json.loads(canonical_json_bytes(valid)) == valid
    server, key, effects, new = setup()
    msg = new(); msg.payload['value'] = {'1': 'value'}; msg.sign(key)
    assert msg.verify_signature(key.public_key_bytes())
    msg.payload['value'] = {1: 'value'}
    assert not msg.verify_signature(key.public_key_bytes())
    with pytest.raises(ValueError): msg.sign(key)
    assert effects == []


@pytest.mark.parametrize('capacity', [float('nan'), float('inf'), 1.0, True, 0, -1, '1'])
def test_invalid_replay_capacity(capacity):
    with pytest.raises(ValueError): SecurityPolicy(Identifier('participant', 'service'), capacity)


@pytest.mark.parametrize('actions', ['read', b'read', ['read', 1], [], {'read': True}, ['bad action'], None])
def test_invalid_actions(actions):
    policy = SecurityPolicy(Identifier('participant', 'service'), 1)
    with pytest.raises(ValueError): policy.trust(Ed25519Keypair.generate().public_key_bytes(), Identifier('participant', 'caller'), actions)


def test_valid_action_collection_control():
    policy = SecurityPolicy(Identifier('participant', 'service'), 1)
    policy.trust(Ed25519Keypair.generate().public_key_bytes(), Identifier('participant', 'caller'), {'read', 'write'})


@pytest.mark.parametrize('bad_result', [object(), {'value': float('nan')}, {'value': float('inf')}, {'value': (1, 2)}, {'value': 'a' * 65536}])
@pytest.mark.parametrize('http', [False, True])
def test_handler_serialization_errors_keep_reservation(bad_result, http):
    server, key, effects, new = setup()
    server._handlers.clear()
    @server.expose('/act')
    def act(value=None):
        effects.append(value)
        return bad_result
    msg = new()
    if http: server.start()
    try:
        call = (lambda: server.client(key).send('/act', msg)) if http else (lambda: server._handle_request(msg))
        response = call()
        assert response.msg_type == MessageType.ERROR
        assert 'effect may have occurred' in response.payload['error']
        assert json.loads(response.to_json())['type'] == 'error'
        assert call().payload['error'] == 'replay'
        assert len(effects) == 1
    finally:
        if http: server.stop()


def fake_response(request, mutate, version=3):
    response = (MessageBuilder(request.to_id, request.from_id).msg_type(MessageType.RESPONSE)
                .operation_id(request.operation_id).subject(request.subject).epoch(request.epoch)
                .payload({'ok': True}).build())
    from ordavyn.wire import request_digest
    response.reply_to=request.id; response.request_digest=request_digest(request)
    response.sign(TEST_SIGNER)
    response=response.to_dict()
    mutate(response)
    body = json.dumps(response).encode()
    listener = socket.socket(); listener.bind(('127.0.0.1', 0)); listener.listen()
    port = listener.getsockname()[1]
    def serve():
        with listener:
            conn, _ = listener.accept()
            with conn:
                conn.recv(65536)
                conn.sendall((f'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{VERSION_HEADER}: {version}\r\nContent-Length: {len(body)}\r\n\r\n').encode() + body)
    thread = threading.Thread(target=serve); thread.start()
    try:
        return OrdavynClient(port=port, response_key=TEST_SIGNER.public_key_bytes(), participant=Identifier('participant', 'service')).send('/act', request)
    finally: thread.join()


@pytest.mark.parametrize('field', [None, 'operation_id', 'from', 'to', 'subject', 'epoch'])
def test_client_response_correlation(field):
    _, _, _, new = setup(); request = new()
    def mutate(data):
        if field == 'subject': data[field]['target_id']['value'] = 'different'
        elif field: data[field]['value'] = 'different'
    if field is None:
        assert fake_response(request, mutate).payload == {'ok': True}
    else:
        with pytest.raises(ValueError): fake_response(request, mutate)


@pytest.mark.parametrize('change', [
    lambda d: d['id'].update(value=['x']),
    lambda d: d['timestamp'].update(nanos='bad'),
    lambda d: d['id'].update(version=True),
    lambda d: d['subject'].update(target_type=[]),
    lambda d: d['subject'].update(closure_version=False),
    lambda d: d.update(version=True),
    lambda d: d['id'].update(namespace='wrong'),
])
def test_client_rejects_malformed_typed_metadata(change):
    _, _, _, new = setup()
    with pytest.raises(ValueError): fake_response(new(), change)


def test_response_write_uses_remaining_deadline(monkeypatch):
    import ordavyn.server as module
    server, _, effects, new = setup()
    body = new().to_json().encode()
    request = (f'POST /ordavyn/v3/act HTTP/1.1\r\nContent-Type: application/json\r\n{VERSION_HEADER}: 3\r\nContent-Length: {len(body)}\r\n\r\n').encode() + body
    clock = iter([10.0, 10.25, 12.0])
    monkeypatch.setattr(module.time, 'monotonic', lambda: next(clock))
    class Connection:
        def __init__(self): self.timeouts=[]; self.sent=None
        def recv(self, size): return request
        def settimeout(self, value): self.timeouts.append(value)
        def sendall(self, data): self.sent=data
        def close(self): pass
    conn=Connection();server._handle_connection(conn)
    assert conn.timeouts[-1] == 1.0
    assert b'200 Result' in conn.sent and len(effects) == 1


def test_restart_rejected_while_handler_active():
    server, key, _, new = setup()
    entered, release = threading.Event(), threading.Event()
    server._handlers.clear()
    @server.expose('/act')
    def act(value=None):
        entered.set();release.wait(5);return {'ok': True}
    server.start()
    errors=[]
    def call():
        try: server.client(key).send('/act', new())
        except (TimeoutError, ValueError, OSError): pass
    worker=threading.Thread(target=call);worker.start()
    assert entered.wait(1)
    # A stopped listener does not imply its handler thread has exited.
    server._running=False;server._server_sock.close()
    try:
        with pytest.raises(RuntimeError): server.start()
    finally:
        release.set();worker.join();server.stop()


def test_client_response_version_with_valid_correlated_body():
    _, _, _, new = setup()
    request = new()
    assert fake_response(request, lambda data: None, version=3).payload == {'ok': True}
    with pytest.raises(ValueError):
        fake_response(request, lambda data: None, version=1)


def test_http_oversized_json_response_is_correlated_and_keeps_effect():
    server,key,effects,new=setup()
    server._handlers.clear()
    @server.expose('/act')
    def act(value=None):
        effects.append(value)
        return {'value':'\n'*40000}
    request=new();server.start()
    try:
        response=server.client(key).send('/act',request)
        assert response.msg_type==MessageType.ERROR
        assert 'effect may have occurred' in response.payload['error']
        assert response.id!=request.id
        assert response.operation_id==request.operation_id
        assert response.subject==request.subject and response.epoch==request.epoch
        assert response.from_id==request.to_id and response.to_id==request.from_id
        assert server.client(key).send('/act',request).payload['error']=='replay'
        assert len(effects)==1
    finally:server.stop()
