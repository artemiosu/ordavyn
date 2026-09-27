"""Protected standalone loopback HTTP/1.1 prototype server."""
import copy
import json
import socket
import threading
import time
from .aim import Identifier
from .message import Message, MessageBuilder, MessageType
from .security import SecurityPolicy, SecurityError, valid_endpoint, MAX_BODY, MAX_HEADERS, TIMEOUT
from .client import OrdavynClient, PATH_PREFIX, VERSION_HEADER


def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate JSON key')
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


class Ordavyn:
    def __init__(self, app=None, host='127.0.0.1', port=8080, *, participant=None, replay_capacity=10000):
        if app is not None:
            raise ValueError('Framework app integration is not implemented; use standalone Ordavyn')
        if host not in ('127.0.0.1', 'localhost'):
            raise ValueError('local prototype: loopback only')
        self.host, self.port = host, port
        self.security = SecurityPolicy(participant or Identifier('participant', 'service'), replay_capacity)
        self._handlers = {}
        self._running = False
        self._server_sock = None
        self._server_thread = None

    def trust(self, public_key, participant, actions):
        self.security.trust(public_key, participant, actions)
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
        response = (MessageBuilder(self.security.recipient, msg.from_id)
                    .operation_id(msg.operation_id).subject(msg.subject).epoch(msg.epoch).build())
        try:
            if len(msg.to_json().encode('utf-8')) > MAX_BODY:
                raise SecurityError('message too large')
            action = msg.payload.get('action') if isinstance(msg.payload, dict) else None
            if not isinstance(action, str) or not valid_endpoint('/' + action):
                raise SecurityError('invalid action')
            expected = PATH_PREFIX + '/' + action
            if path is None:
                path = expected
            handler = self._handlers.get(path)
            if path != expected or handler is None:
                raise SecurityError('route mismatch')
            self.security.authorize_and_reserve(msg, action)
            params = dict(msg.payload)
            del params['action']
            result = handler(**params)
            response.msg_type = MessageType.RESPONSE
            response.payload = result if isinstance(result, dict) else {'result': result}
            if len(response.to_json().encode('utf-8')) > MAX_BODY:
                raise SecurityError('response too large')
        except Exception as exc:
            response.msg_type = MessageType.ERROR
            response.payload = {'error': str(exc) if isinstance(exc, SecurityError) else 'handler_or_input_error'}
        return response

    def _handle_connection(self, conn):
        deadline = time.monotonic() + TIMEOUT
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
            if (method != 'POST' or http_version != 'HTTP/1.1' or headers.get(VERSION_HEADER) != '1'
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
            status = 200 if response.msg_type == MessageType.RESPONSE else 403
        except Exception:
            pass
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('response deadline')
            conn.settimeout(remaining)
            conn.sendall((f'HTTP/1.1 {status} Result\r\nContent-Type: application/json\r\n{VERSION_HEADER}: 1\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n').encode('ascii') + body)
        except OSError:
            pass
        finally:
            conn.close()

    def start(self):
        if self._running or (self._server_thread is not None and self._server_thread.is_alive()):
            raise RuntimeError('server or handler still running')
        sock = socket.socket()
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen(16)
        sock.settimeout(0.1)
        self.port = sock.getsockname()[1]
        self._server_sock = sock
        self._running = True
        def run():
            while self._running:
                try:
                    conn, _ = sock.accept()
                    self._handle_connection(conn)
                except socket.timeout:
                    continue
                except OSError:
                    break
        self._server_thread = threading.Thread(target=run, daemon=True)
        self._server_thread.start()
        return self

    def stop(self):
        self._running = False
        if self._server_sock:
            self._server_sock.close()
        if self._server_thread:
            self._server_thread.join(TIMEOUT + 1)

    def client(self, keypair=None):
        client = OrdavynClient(self.host, self.port)
        return client.with_keypair(keypair) if keypair else client
