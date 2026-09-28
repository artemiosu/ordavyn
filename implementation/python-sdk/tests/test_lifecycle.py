"""Local admission ordering; synchronization never relies on random sleeps."""

from ordavyn import Ed25519Keypair, Identifier
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
TEST_SIGNER = Ed25519Keypair(Ed25519PrivateKey.from_private_bytes(bytes([99])*32))
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
import pytest
from ordavyn import (Ordavyn, Identifier, Ed25519Keypair, MessageBuilder, MessageType,
                     MemoryJournal, SQLiteJournal, JournalError)

SENDER = Identifier('participant', 'caller')
RECIPIENT = Identifier('participant', 'service')


@pytest.fixture(params=['memory', 'sqlite'])
def setup(request, tmp_path):
    path = tmp_path / 'lifecycle.sqlite'
    journal = (MemoryJournal(RECIPIENT, 100) if request.param == 'memory' else
               SQLiteJournal.create(path, RECIPIENT, 100))
    server = Ordavyn(port=0, participant=RECIPIENT, replay_capacity=100, journal=journal, signer=TEST_SIGNER)
    key = Ed25519Keypair.generate()
    server.trust(key.public_key_bytes(), SENDER, ['act', 'other'])
    yield server, key, journal, path
    assert server.stop()
    journal.close()


def message(key, action='act'):
    msg = MessageBuilder(SENDER, RECIPIENT).payload({'action': action}).build()
    msg.sign(key)
    return msg


def accepted(server, msg):
    return server._handle_request(msg).msg_type == MessageType.RESPONSE


@pytest.mark.parametrize('operation', ['revoke', 'rotate', 'narrow', 'stop'])
@pytest.mark.parametrize('http', [False, True])
def test_admission_first(setup, operation, http):
    server, key, journal, _ = setup
    entered, release = threading.Event(), threading.Event()
    @server.expose('/act')
    def act():
        entered.set()
        assert release.wait(5)
        return {'ok': True}
    msg = message(key)
    new_key = Ed25519Keypair.generate()
    if http:
        server.start()
    with ThreadPoolExecutor() as pool:
        future = pool.submit(server.client().send, '/act', msg) if http else pool.submit(server._handle_request, msg)
        assert entered.wait(5)
        try:
            if operation == 'revoke':
                assert server.revoke(key.public_key_bytes())
            elif operation == 'rotate':
                server.rotate_key(key.public_key_bytes(), new_key.public_key_bytes())
            elif operation == 'narrow':
                server.trust(key.public_key_bytes(), SENDER, ['other'])
            else:
                server.request_stop()
                assert not server.stop(0)
                with pytest.raises(RuntimeError): server.resume()
                with pytest.raises(RuntimeError): server.start()
            with pytest.raises(JournalError): journal.close()
            assert not accepted(server, message(key))
        finally:
            release.set()
        assert future.result(5).msg_type == MessageType.RESPONSE
    assert server.stop()
    server.resume()
    if operation == 'revoke':
        assert not accepted(server, message(key))
        server.trust(key.public_key_bytes(), SENDER, ['act'])
    if operation == 'rotate':
        msg.sign(new_key)
    assert not accepted(server, msg)


@pytest.mark.parametrize('operation', ['revoke', 'rotate', 'narrow', 'stop'])
def test_management_first_has_no_reservation(setup, operation):
    server, key, journal, _ = setup
    effects = []
    server.expose('/act')(lambda: effects.append(1) or {})
    ready, release = threading.Barrier(2), threading.Barrier(2)
    msg = message(key)
    def invoke():
        ready.wait(); release.wait()
        return accepted(server, msg)
    with ThreadPoolExecutor() as pool:
        future = pool.submit(invoke)
        ready.wait()
        if operation == 'revoke': server.revoke(key.public_key_bytes())
        elif operation == 'rotate': server.rotate_key(key.public_key_bytes(), Ed25519Keypair.generate().public_key_bytes())
        elif operation == 'narrow': server.trust(key.public_key_bytes(), SENDER, ['other'])
        else: server.request_stop()
        release.wait()
        assert not future.result(5)
    assert effects == [] and journal.inspect() == []


def test_narrow_conflicts_and_atomic_rotation(setup):
    server, key, _, _ = setup
    server.expose('/act')(lambda: {})
    server.expose('/other')(lambda: {})
    public = key.public_key_bytes()
    with pytest.raises(ValueError): server.trust(public, Identifier('participant', 'else'), ['act'])
    for actions in [[], ['bad?'], 'act']:
        with pytest.raises(ValueError): server.trust(public, SENDER, actions)
    server.trust(public, SENDER, ['other'])
    assert not accepted(server, message(key))
    assert accepted(server, message(key, 'other'))
    new = Ed25519Keypair.generate()
    server.trust(new.public_key_bytes(), SENDER, ['act'])
    for old, replacement in [(public, public), (public, new.public_key_bytes()),
                             (b'x', public), (Ed25519Keypair.generate().public_key_bytes(), public)]:
        with pytest.raises(ValueError): server.rotate_key(old, replacement)
    assert accepted(server, message(key, 'other'))
    assert server.revoke(public)
    assert not server.revoke(public)
    assert not accepted(server, message(key, 'other'))
    server.trust(public, SENDER, ['act'])
    assert accepted(server, message(key))


def test_sqlite_rotation_reopen(setup):
    server, key, journal, path = setup
    server.expose('/act')(lambda: {'effect': 'done'})
    server.expose('/forbidden')(lambda: pytest.fail('ungranted handler'))
    msg = message(key)
    assert accepted(server, msg)
    new = Ed25519Keypair.generate()
    server.rotate_key(key.public_key_bytes(), new.public_key_bytes())
    fresh = server._handle_request(message(new))
    assert fresh.msg_type == MessageType.RESPONSE and fresh.payload == {'effect': 'done'}
    assert not accepted(server, message(new, 'forbidden'))
    retry = message(new)
    retry.operation_id = msg.operation_id
    retry.sign(new)
    assert not accepted(server, retry)
    assert server.stop()
    server.resume()
    assert not accepted(server, retry)
    if isinstance(journal, SQLiteJournal):
        journal.close()
        opened = SQLiteJournal.open(path, RECIPIENT, 100)
        try:
            fresh = Ordavyn(participant=RECIPIENT, replay_capacity=100, journal=opened, signer=TEST_SIGNER)
            fresh.expose('/act')(lambda: {})
            fresh.trust(new.public_key_bytes(), SENDER, ['act'])
            assert not accepted(fresh, retry)
            assert accepted(fresh, message(new))
            assert fresh.stop()
        finally: opened.close()


@pytest.mark.parametrize('failure', ['exception', 'interrupt', 'complete'])
def test_failure_releases_activity(setup, failure, monkeypatch):
    server, key, journal, _ = setup
    def act():
        if failure == 'exception': raise ValueError('failed')
        if failure == 'interrupt': raise KeyboardInterrupt()
        return {}
    server.expose('/act')(act)
    if failure == 'complete':
        def fail(_): raise JournalError('failed completion')
        monkeypatch.setattr(journal, 'complete', fail)
    msg = message(key)
    if failure == 'interrupt':
        with pytest.raises(KeyboardInterrupt): server._handle_request(msg)
    else: assert not accepted(server, msg)
    assert server.stop(0)
    server.resume()
    assert not accepted(server, msg)


def test_stop_before_start_bind_failure_and_repeated_start(setup):
    server, _, _, _ = setup
    assert server.stop(0)
    with socket.socket() as occupied:
        occupied.bind(('127.0.0.1', 0)); occupied.listen()
        server.port = occupied.getsockname()[1]
        with pytest.raises(OSError): server.start()
        assert server.stop(0)
    server.port = 0
    server.start()
    with pytest.raises(RuntimeError): server.start()
    assert server.stop()
    assert server.stop(0)
    server.start()
    assert server.stop()


def test_handler_can_request_stop_and_bounded_wait(setup):
    server, key, _, _ = setup
    def act():
        server.request_stop()
        assert not server.stop(0)
        return {}
    server.expose('/act')(act)
    assert accepted(server, message(key))
    assert server.stop(0)
    for timeout in [-1, float('nan'), float('inf'), True, '4', 1e100, 10**1000]:
        with pytest.raises(ValueError): server.stop(timeout)


def test_concurrent_starts(setup):
    server, _, _, _ = setup
    barrier = threading.Barrier(2)
    def start():
        barrier.wait()
        try: server.start(); return True
        except RuntimeError: return False
    with ThreadPoolExecutor() as pool:
        results = list(pool.map(lambda _: start(), range(2)))
    assert sorted(results) == [False, True]
    assert server.stop()


@pytest.mark.parametrize('operation', ['revoke', 'rotate'])
def test_management_first_http_has_no_reservation(setup, operation):
    server, key, journal, _ = setup
    def unexpected(): raise AssertionError('revoked request executed')
    server.expose('/act')(unexpected)
    server.start()
    if operation == 'revoke': server.revoke(key.public_key_bytes())
    else: server.rotate_key(key.public_key_bytes(), Ed25519Keypair.generate().public_key_bytes())
    assert server.client().send('/act', message(key)).msg_type == MessageType.ERROR
    assert journal.inspect() == []


def test_stop_counts_connection_before_admission(setup, monkeypatch):
    server, key, journal, _ = setup
    entered, release = threading.Event(), threading.Event()
    original = server._handle_connection
    def delayed(conn):
        entered.set()
        assert release.wait(5)
        original(conn)
    monkeypatch.setattr(server, '_handle_connection', delayed)
    server.expose('/act')(lambda: {})
    server.start()
    with ThreadPoolExecutor() as pool:
        future = pool.submit(server.client().send, '/act', message(key))
        assert entered.wait(5)
        server.request_stop()
        assert not server.stop(0)
        with pytest.raises(RuntimeError): server.resume()
        release.set()
        assert future.result(5).msg_type == MessageType.ERROR
    assert server.stop()
    assert journal.inspect() == []


@pytest.mark.parametrize('boundary', ['authorize_and_reserve', 'reserve'])
def test_interrupt_at_ownership_return_drains_admission(setup, boundary):
    import sys
    server, key, journal, _ = setup
    effects = []
    server.expose('/act')(lambda: effects.append(1) or {})
    msg = message(key)
    def interrupt(frame, event, arg):
        if frame.f_code.co_name == boundary and event == 'return':
            raise KeyboardInterrupt('ownership handoff')
        return interrupt
    sys.settrace(interrupt)
    try:
        with pytest.raises(KeyboardInterrupt): server._handle_request(msg)
    finally:
        sys.settrace(None)
    assert effects == []
    assert server.stop(0)
    server.resume()
    assert not accepted(server, msg)
    assert journal.inspect()[0]['state'] == 'outcome_unknown'
    journal.close()



def test_interrupt_after_thread_launch_has_one_owner(setup, monkeypatch):
    server, key, _, _ = setup
    server.expose('/act')(lambda: {})
    original = threading.Thread.start
    def start_then_interrupt(thread):
        original(thread)
        raise KeyboardInterrupt('after launch')
    with monkeypatch.context() as patch:
        patch.setattr(threading.Thread, 'start', start_then_interrupt)
        with pytest.raises(KeyboardInterrupt): server.start()
    thread = server._server_thread
    assert thread is not None
    assert not accepted(server, message(key))
    assert server.stop(2)
    assert not thread.is_alive() and server.security._network == 0
    assert server.stop(0)
    server.start()
    assert server.stop(2)


@pytest.mark.parametrize('operation', ['revoke', 'rotate', 'narrow', 'stop'])
def test_reserved_before_handler_management_boundary(setup, operation):
    server, key, journal, _ = setup
    request = message(key)
    token = object()
    try:
        server.security.authorize_and_reserve(request, 'act', token)
        assert journal.inspect()[0]['state'] == 'outcome_unknown'
        if operation == 'revoke': server.revoke(key.public_key_bytes())
        elif operation == 'rotate': server.rotate_key(key.public_key_bytes(), Ed25519Keypair.generate().public_key_bytes())
        elif operation == 'narrow': server.trust(key.public_key_bytes(), SENDER, ['other'])
        else: server.request_stop()
        assert not server.stop(0)
        with pytest.raises(JournalError): journal.close()
        with pytest.raises(RuntimeError): server.resume()
        # Existing reservation ownership can complete after admission closes.
        journal.complete(token)
    finally:
        server.security.finish(token)
    assert server.stop(0)
    assert journal.inspect()[0]['state'] == 'handler_returned'
