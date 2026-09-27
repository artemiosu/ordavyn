import copy
import concurrent.futures
import socket
import json
import pytest
from ordavyn import Ordavyn, Identifier, MessageBuilder, MessageType, Ed25519Keypair
from ordavyn.client import PATH_PREFIX, VERSION_HEADER


def setup(capacity=10000, failing=False):
    key = Ed25519Keypair.generate()
    sender, recipient = Identifier('participant', 'caller'), Identifier('participant', 'service')
    server = Ordavyn(port=0, participant=recipient, replay_capacity=capacity)
    server.trust(key.public_key_bytes(), sender, ['act'])
    effects = []
    @server.expose('/act', consequential=True)
    def act(value=None):
        effects.append(value)
        if failing:
            raise RuntimeError('after effect')
        return {'ok': value}
    def message():
        msg = MessageBuilder(sender, recipient).payload({'action': 'act', 'value': 'тест'}).build()
        msg.sign(key)
        return msg
    return server, key, effects, message


def test_authorized_direct_and_request_unchanged():
    server, key, effects, new = setup()
    msg = new()
    before = copy.deepcopy(msg.to_dict())
    response = server._handle_request(msg)
    assert response.msg_type == MessageType.RESPONSE and effects == ['тест']
    assert msg.to_dict() == before and msg.verify_signature(key.public_key_bytes())
    assert response.id != msg.id and not response.is_signed()


@pytest.mark.parametrize('mutation', ['unsigned','forged','payload','key','algorithm','encoding','version','type','sender','recipient','action','id','operation','epoch'])
def test_rejected_before_effect(mutation):
    server, key, effects, new = setup()
    msg = new()
    if mutation == 'unsigned': msg.signature = None
    elif mutation == 'forged': msg.signature = '00' * 64
    elif mutation == 'payload': msg.payload['value'] = 'changed'
    elif mutation == 'key': msg.sign(Ed25519Keypair.generate())
    elif mutation == 'algorithm': msg.signature_alg = 2
    elif mutation == 'encoding': msg.encoding = 'cbor'
    elif mutation == 'version': msg.version = 2; msg.sign(key)
    elif mutation == 'type': msg.msg_type = 'response'; msg.sign(key)
    elif mutation == 'sender': msg.from_id = Identifier('participant','stranger'); msg.sign(key)
    elif mutation == 'recipient': msg.to_id = Identifier('participant','other'); msg.sign(key)
    elif mutation == 'action': msg.payload['action'] = 'other'; msg.sign(key)
    elif mutation == 'id': msg.id = Identifier('wrong','id'); msg.sign(key)
    elif mutation == 'operation': msg.operation_id = Identifier('wrong','op'); msg.sign(key)
    elif mutation == 'epoch': msg.epoch = Identifier('wrong','epoch'); msg.sign(key)
    assert server._handle_request(msg).msg_type == MessageType.ERROR
    assert effects == []


def test_trusted_key_without_action_permission():
    server, key, effects, new = setup()
    msg = new()
    server.trust(key.public_key_bytes(), msg.from_id, ['other'])
    assert server._handle_request(msg).msg_type == MessageType.ERROR
    assert effects == []


def test_concurrent_replay_and_operation_and_failure():
    server, key, effects, new = setup(failing=True)
    msg = new()
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda _: server._handle_request(msg), range(16)))
    assert effects == ['тест']
    retry = new(); retry.operation_id = msg.operation_id; retry.sign(key)
    assert server._handle_request(retry).msg_type == MessageType.ERROR
    assert len(effects) == 1
    retry = new(); retry.id = msg.id; retry.sign(key)
    assert server._handle_request(retry).msg_type == MessageType.ERROR
    assert len(effects) == 1


def test_capacity_does_not_evict():
    server, key, effects, new = setup(capacity=1)
    first = new()
    assert server._handle_request(first).msg_type == MessageType.RESPONSE
    assert server._handle_request(new()).msg_type == MessageType.ERROR
    assert server._handle_request(first).msg_type == MessageType.ERROR
    assert len(effects) == 1


def test_object_array_signature_distinct():
    _, key, _, new = setup()
    msg = new(); msg.payload = {'a': 1}; msg.sign(key)
    msg.payload = ['a', 1]
    assert not msg.verify_signature(key.public_key_bytes())


def raw(server, msg, path='/ordavyn/v1/act', version='1', extra='', fragments=False):
    body = msg.to_json().encode()
    request = (f'POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n{VERSION_HEADER}: {version}\r\nContent-Length: {len(body)}\r\n{extra}\r\n').encode()+body
    with socket.create_connection((server.host,server.port),timeout=4) as sock:
        if fragments:
            for i in range(0,len(request),7): sock.sendall(request[i:i+7])
        else: sock.sendall(request)
        response=b''
        while True:
            chunk=sock.recv(4096)
            if not chunk: break
            response+=chunk
    return response


def test_http_matrix_and_fragmented_unicode():
    server, key, effects, new = setup()
    server.start()
    try:
        first = new()
        assert b'200 Result' in raw(server,first,fragments=True)
        assert b'403 Result' in raw(server,first)
        assert b'403 Result' in raw(server,new(),path='/ordavyn/v1/wrong')
        assert b'400 Result' in raw(server,new(),version='2')
        assert b'400 Result' in raw(server,new(),extra='Transfer-Encoding: chunked\r\n')
        bad = new(); bad.signature='ff'*64
        assert b'403 Result' in raw(server,bad)
        assert len(effects)==1
        response = server.client(key).send('/act',new())
        assert response.payload == {'ok':'тест'} and len(effects)==2
    finally: server.stop()


def test_input_limits_and_fake_app():
    with pytest.raises(ValueError): Ordavyn(app=object())
    server, key, effects, new = setup()
    msg=new(); msg.payload['value']='a'*65536; msg.sign(key)
    assert msg.verify_signature(key.public_key_bytes())
    result = server._handle_request(msg)
    assert result.msg_type == MessageType.ERROR and result.payload['error'] == 'message too large'
    assert effects == []
    assert server._handle_request(new()).msg_type == MessageType.RESPONSE
    assert len(effects) == 1
    server.start()
    try:
        assert b'400 Result' in raw(server,new(),extra='Content-Length: 99999\r\n')
    finally: server.stop()


def test_http_header_body_limits_and_timeout(monkeypatch):
    import ordavyn.server as module
    import time
    monkeypatch.setattr(module, 'TIMEOUT', 0.15)
    server, key, effects, new = setup()
    server.start()
    try:
        for request in (
            b'POST /ordavyn/v1/act HTTP/1.1\r\nX-Padding: '+b'a'*9000+b'\r\n\r\n',
            b'POST /ordavyn/v1/act HTTP/1.1\r\nContent-Type: application/json\r\nx-ordavyn-version: 1\r\nContent-Length: 65537\r\n\r\n',
            b'POST /ordavyn/v1/act HTTP/1.1\r\n',
        ):
            with socket.create_connection((server.host,server.port),timeout=1) as conn:
                conn.sendall(request)
                started=time.monotonic()
                result = conn.recv(1024)
                assert b'400 Result' in result or (request.endswith(b'HTTP/1.1\r\n') and result == b'')
                assert time.monotonic()-started < 1
        assert effects == []
    finally: server.stop()


def test_client_rejects_version_limits_and_slow_response(monkeypatch):
    import ordavyn.client as module
    import threading
    import time
    monkeypatch.setattr(module, 'TIMEOUT', 0.15)
    _, _, _, new = setup()
    for reply in (
        b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nx-ordavyn-version: 2\r\nContent-Length: 2\r\n\r\n{}',
        b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nx-ordavyn-version: 1\r\nContent-Length: 65537\r\n\r\n',
        b'HTTP/1.1 200 OK\r\nX-Padding: '+b'a'*9000+b'\r\n\r\n',
        b'HTTP/1.1 200 OK\r\n',
    ):
        listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen()
        def serve():
            with listener:
                conn,_=listener.accept()
                with conn:
                    conn.recv(4096);conn.sendall(reply);time.sleep(0.2)
        thread=threading.Thread(target=serve);thread.start()
        try:
            with pytest.raises((ValueError,TimeoutError,OSError)):
                module.OrdavynClient(port=listener.getsockname()[1]).send('/act',new())
        finally: thread.join()


def test_duplicate_and_unknown_metadata_rejected():
    from ordavyn.server import strict_json
    from ordavyn import Message
    _, _, _, new = setup()
    with pytest.raises(ValueError): strict_json('{"payload":{"action":"wrong","action":"act"}}')
    data=new().to_dict();data['from']['extra']='unsigned'
    with pytest.raises(ValueError): Message.from_dict(data)
    data=new().to_dict();data['unexpected']='unsigned'
    with pytest.raises(ValueError): Message.from_dict(data)
