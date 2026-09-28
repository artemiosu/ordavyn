"""Protected standalone loopback HTTP/1.1 prototype server."""
import copy
import socket
import threading
import time
from .aim import Identifier
from .journal import JournalError
from .message import Message, MessageBuilder, MessageType
from .security import SecurityPolicy, SecurityError, valid_endpoint, MAX_BODY, MAX_HEADERS, TIMEOUT
from .client import OrdavynClient, PATH_PREFIX, VERSION_HEADER


from .wire import strict_json, validate_envelope


class Ordavyn:
    def __init__(self, app=None, host='127.0.0.1', port=8080, *, participant=None, replay_capacity=10000, journal=None, signer=None, tls=None):
        if app is not None:
            raise ValueError('Framework app integration is not implemented; use standalone Ordavyn')
        if host not in ('127.0.0.1', 'localhost'):
            raise ValueError('local prototype: loopback only')
        self.host, self.port = host, port
        self.security = SecurityPolicy(participant or Identifier('participant', 'service'), replay_capacity, journal=journal)
        from .crypto import Ed25519Keypair
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from .tls import ServerTLS
        if not isinstance(signer, Ed25519Keypair):
            raise ValueError('explicit server Ed25519 signer required')
        seed = signer._private_key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        self.__signer = Ed25519Keypair(Ed25519PrivateKey.from_private_bytes(seed))
        if tls is not None and type(tls) is not ServerTLS:
            raise ValueError('ServerTLS configuration required')
        self.__tls_context = tls.context() if tls is not None else None
        self._handlers = {}
        self._running = False
        self._server_sock = None
        self._server_thread = None

    def trust(self, public_key, participant, actions):
        self.security.trust(public_key, participant, actions)
        return self

    def revoke(self, public_key):
        return self.security.revoke(public_key)

    def rotate_key(self, old_key, new_key):
        self.security.rotate_key(old_key, new_key)
        return self

    def resume(self):
        self.security.resume()
        return self

    def expose(self, path, consequential=False):
        # Every action requires signature and explicit permission, including reads.
        if not valid_endpoint(path):
            raise ValueError('invalid endpoint')
        def register(func):
            full = PATH_PREFIX + path
            if full in self._handlers:
                raise ValueError('duplicate endpoint')
            self._handlers[full] = func
            return func
        return register

    def _handle_request(self, msg, path=None):
        # Take an independent snapshot; never mutate the signed request.
        msg = copy.deepcopy(msg)
        from .wire import request_digest
        validate_envelope(msg.to_dict())
        if msg.msg_type != MessageType.REQUEST or msg.to_id != self.security.recipient:
            raise SecurityError('invalid request recipient or type')
        digest = request_digest(msg)
        response = (MessageBuilder(self.security.recipient, msg.from_id)
                    .operation_id(msg.operation_id).subject(msg.subject).epoch(msg.epoch).build())
        response.reply_to = msg.id
        response.request_digest = digest
        reservation = object()
        try:
            try:
                action = msg.payload.get('action') if isinstance(msg.payload, dict) else None
                if not isinstance(action, str) or not valid_endpoint('/' + action):
                    raise SecurityError('invalid action')
                expected = PATH_PREFIX + '/' + action
                if path is None:
                    path = expected
                handler = self._handlers.get(path)
                if path != expected or handler is None:
                    raise SecurityError('route mismatch')
                self.security.authorize_and_reserve(msg, action, reservation)
                params = dict(msg.payload)
                del params['action']
                result = handler(**params)
                response.msg_type = MessageType.RESPONSE
                response.payload = result if isinstance(result, dict) else {'result': result}
            except Exception as exc:
                response.msg_type = MessageType.ERROR
                response.payload = {'error': str(exc) if isinstance(exc, (SecurityError, JournalError)) else 'handler_or_input_error; outcome may be unknown'}
            try:
                response.sign(self.__signer)
                response.to_json()
                if response.msg_type == MessageType.RESPONSE:
                    self.security.journal.complete(reservation)
            except Exception:
                response.msg_type = MessageType.ERROR
                response.payload = {'error': 'response unavailable or exceeds limits; effect may have occurred'}
                response.sign(self.__signer)
                response.to_json()
            return response
        finally:
            self.security.finish(reservation)

    def _handle_connection(self, conn):
        deadline = time.monotonic() + TIMEOUT
        try:
            if self.__tls_context is not None:
                conn.settimeout(max(0.001, deadline - time.monotonic()))
                conn = self.__tls_context.wrap_socket(conn, server_side=True)
                if conn.selected_alpn_protocol() != 'http/1.1':
                    raise ValueError('TLS ALPN mismatch')
            self._process_connection(conn, deadline)
        except (OSError, ValueError):
            pass
        finally:
            conn.close()

    def _process_connection(self, conn, deadline):
        def receive(size):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError()
            conn.settimeout(remaining)
            data = conn.recv(size)
            if not data:
                raise ValueError('truncated request')
            return data
        status, body = 400, b'{"error":"invalid HTTP request"}'
        try:
            raw = b''
            while b'\r\n\r\n' not in raw:
                raw += receive(1024)
                if len(raw) > MAX_HEADERS + 1024:
                    raise ValueError('headers too large')
            header, data = raw.split(b'\r\n\r\n', 1)
            if len(header) > MAX_HEADERS:
                raise ValueError('headers too large')
            lines = header.decode('ascii').split('\r\n')
            method, path, http_version = lines[0].split(' ')
            headers = {}
            for line in lines[1:]:
                k, v = line.split(':', 1)
                k = k.lower()
                if k in headers:
                    raise ValueError('duplicate header')
                headers[k] = v.strip()
            if (method != 'POST' or http_version != 'HTTP/1.1' or headers.get(VERSION_HEADER) != '3'
                    or headers.get('content-type') != 'application/json' or 'transfer-encoding' in headers):
                raise ValueError('unsupported HTTP metadata')
            length_text = headers.get('content-length', '')
            if not length_text.isascii() or not length_text.isdecimal():
                raise ValueError('invalid length')
            length = int(length_text)
            if length < 1 or length > MAX_BODY or len(data) > length:
                raise ValueError('body limit')
            while len(data) < length:
                data += receive(min(4096, length - len(data)))
            msg = Message.from_dict(strict_json(data))
            response = self._handle_request(msg, path)
            body = response.to_json().encode('utf-8')
            status = 200
        except Exception:
            pass
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('response deadline')
            conn.settimeout(remaining)
            conn.sendall((f'HTTP/1.1 {status} Result\r\nContent-Type: application/json\r\n{VERSION_HEADER}: 3\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n').encode('ascii') + body)
        except OSError:
            pass
        finally:
            conn.close()

    def start(self):
        with self.security._condition:
            if self._running or self.security._network or (self._server_thread is not None and self._server_thread.is_alive()):
                raise RuntimeError('server or handler still running')
            if not self.security._accepting and self.security._active:
                raise RuntimeError('handler still running')
            sock = socket.socket()
            owned = False
            thread = None
            def release_listener():
                nonlocal owned
                with self.security._condition:
                    if owned:
                        owned = False
                        self.security._network -= 1
                    if self._server_sock is sock:
                        self._running = False
                        self._server_sock = None
                    self.security._condition.notify_all()
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(('127.0.0.1', self.port))
                sock.listen(16)
                sock.settimeout(0.1)
                self.port = sock.getsockname()[1]
                self._server_sock = sock
                self._running = True
                self.security._network += 1
                owned = True
                def run():
                    try:
                        while True:
                            with self.security._lock:
                                if not self._running:
                                    break
                            try:
                                conn, _ = sock.accept()
                                self._handle_connection(conn)
                            except socket.timeout:
                                continue
                            except OSError:
                                break
                    finally:
                        sock.close()
                        release_listener()
                thread = threading.Thread(target=run, daemon=True)
                self._server_thread = thread
                self._server_thread.start()
                self.security._accepting = True
            except BaseException:
                sock.close()
                self.security.request_stop()
                self._running = False
                # Thread.start may raise after launching. Its worker still owns
                # cleanup, and stop must retain the handle until it has exited.
                if thread is None or thread.ident is None:
                    release_listener()
                    self._server_thread = None
                raise
        return self

    def request_stop(self):
        with self.security._condition:
            self.security.request_stop()
            self._running = False
            if self._server_sock:
                self._server_sock.close()

    def stop(self, timeout=4.0):
        self.security.validate_timeout(timeout)
        self.request_stop()
        deadline = time.monotonic() + timeout
        if not self.security.wait_stopped(timeout):
            return False
        thread = self._server_thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(max(0.0, deadline - time.monotonic()))
            return not thread.is_alive()
        return thread is None or not thread.is_alive()

    def client(self, keypair=None, *, tls=None):
        if self.__tls_context is not None and tls is None:
            raise ValueError('explicit client TLS trust required')
        client = OrdavynClient(self.host, self.port, response_key=self.__signer.public_key_bytes(), participant=self.security.recipient, tls=tls)
        return client.with_keypair(keypair) if keypair else client
