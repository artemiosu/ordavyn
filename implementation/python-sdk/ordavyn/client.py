"""Bounded local HTTP/1.1 client; responses are pinned, signed and request-bound."""
import copy
import socket
import time
from .message import Message, MessageType
from .security import valid_endpoint, MAX_BODY, MAX_HEADERS, TIMEOUT
PROTOCOL_VERSION = 3
VERSION_HEADER = 'x-ordavyn-version'
PATH_PREFIX = '/ordavyn/v3'
CONTENT_TYPE = 'application/json'


class OrdavynClient:
    def __init__(self, host='127.0.0.1', port=8080, *, response_key=None, participant=None, tls=None):
        if host not in ('127.0.0.1', 'localhost'):
            raise ValueError('local prototype: loopback only')
        self.host, self.port = host, port
        self._keypair = None
        from .tls import ClientTLS
        if tls is not None and type(tls) is not ClientTLS:
            raise ValueError('ClientTLS configuration required')
        self._tls = tls
        self._pin = None
        if response_key is not None or participant is not None:
            self.with_response_key(response_key, participant)

    def with_response_key(self, public_key, participant):
        from .security import SecurityPolicy
        from .aim import Identifier
        if not isinstance(participant, Identifier) or participant.namespace != 'participant' or not participant.is_valid():
            raise ValueError('response participant required')
        self._pin = (SecurityPolicy._key(public_key), copy.deepcopy(participant))
        return self

    def with_keypair(self, keypair):
        self._keypair = keypair
        return self

    def send(self, endpoint, msg, sign=True):
        if not valid_endpoint(endpoint):
            raise ValueError('invalid endpoint')
        pin = copy.deepcopy(self._pin)
        if pin is None:
            raise ValueError('local response key and participant required')
        msg = copy.deepcopy(msg)
        if msg.to_id != pin[1]:
            raise ValueError('response pin participant mismatch')
        if sign and self._keypair is not None and not msg.is_signed():
            msg.sign(self._keypair)
        from .wire import request_digest
        digest = request_digest(msg)
        body = msg.to_json().encode('utf-8')
        if len(body) > MAX_BODY:
            raise ValueError('request too large')
        deadline = time.monotonic() + TIMEOUT
        with socket.create_connection(('127.0.0.1', self.port), timeout=TIMEOUT) as conn:
            if self._tls is not None:
                context = self._tls.context()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('TLS deadline')
                conn.settimeout(remaining)
                conn = context.wrap_socket(conn, server_hostname=self._tls.server_name)
                if conn.selected_alpn_protocol() != 'http/1.1':
                    conn.close()
                    raise ValueError('TLS ALPN mismatch')
            with conn:
                return self._exchange(conn, endpoint, msg, body, deadline, pin, digest)

    def _exchange(self, conn, endpoint, msg, body, deadline, pin, digest):
        def receive(size):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('response deadline')
            conn.settimeout(remaining)
            data = conn.recv(size)
            if not data:
                raise ValueError('truncated response')
            return data
        header = (f'POST {PATH_PREFIX}{endpoint} HTTP/1.1\r\nHost: {self.host}:{self.port}\r\n'
                  f'Content-Type: {CONTENT_TYPE}\r\n{VERSION_HEADER}: 3\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n')
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('request deadline')
        conn.settimeout(remaining)
        conn.sendall(header.encode('ascii') + body)
        raw = b''
        while b'\r\n\r\n' not in raw:
            raw += receive(1024)
            if len(raw) > MAX_HEADERS + 1024:
                raise ValueError('response headers too large')
        head, data = raw.split(b'\r\n\r\n', 1)
        if len(head) > MAX_HEADERS:
            raise ValueError('response headers too large')
        lines = head.decode('ascii').split('\r\n')
        version, status, reason = lines[0].split(' ', 2)
        headers = {}
        for line in lines[1:]:
            key, value = line.split(':', 1)
            key = key.lower()
            if key in headers:
                raise ValueError('duplicate response header')
            headers[key] = value.strip()
        if (version != 'HTTP/1.1' or headers.get(VERSION_HEADER) != '3'
                or headers.get('content-type') != CONTENT_TYPE or 'transfer-encoding' in headers):
            raise ValueError('invalid response metadata')
        length_text = headers.get('content-length', '')
        if not length_text.isascii() or not length_text.isdecimal():
            raise ValueError('invalid response length')
        length = int(length_text)
        if not 0 < length <= MAX_BODY or len(data) > length:
            raise ValueError('response body limit')
        while len(data) < length:
            data += receive(min(4096, length - len(data)))
        from .server import strict_json
        result = Message.from_dict(strict_json(data))
        if (type(result.version) is not int or result.version != 3 or result.encoding != 'ordavyn-cbor-v3'
                or result.msg_type not in (MessageType.RESPONSE, MessageType.ERROR)
                or result.from_id != msg.to_id or result.to_id != msg.from_id
                or result.operation_id != msg.operation_id or result.subject != msg.subject
                or result.epoch != msg.epoch or result.reply_to != msg.id
                or result.request_digest != digest or result.from_id != pin[1]
                or not result.verify_signature(pin[0])):
            raise ValueError('invalid response envelope')
        if status != '200':
            raise ValueError('HTTP error')
        return result
