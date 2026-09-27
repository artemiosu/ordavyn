"""Local explicit grants and bounded, process-local replay protection.

No delegation, expiry negotiation, persistent journal or remote key discovery.
"""
import hashlib
import threading
from collections.abc import Collection, Mapping
from .aim import Identifier
from .message import MessageType

MAX_BODY = 65536
MAX_HEADERS = 8192
TIMEOUT = 3.0


class SecurityError(ValueError):
    pass


def valid_endpoint(path):
    return (isinstance(path, str) and path.startswith('/') and len(path) <= 256
            and all(c.isascii() and (c.isalnum() or c in '/_-') for c in path)
            and '//' not in path and not path.endswith('/'))


class SecurityPolicy:
    def __init__(self, recipient, capacity=10000):
        if not isinstance(recipient, Identifier) or recipient.namespace != 'participant' or type(capacity) is not int or capacity < 1:
            raise ValueError('recipient and positive replay capacity required')
        self.recipient = recipient
        self.capacity = capacity
        self._grants = {}
        self._messages = set()
        self._operations = set()
        self._lock = threading.Lock()

    def trust(self, public_key, participant, actions):
        if len(public_key) != 32 or participant.namespace != 'participant':
            raise ValueError('invalid local key binding')
        if (not isinstance(actions, Collection) or isinstance(actions, (str, bytes, bytearray, Mapping))
                or not actions or any(type(a) is not str or not valid_endpoint('/' + a) for a in actions)):
            raise ValueError('explicit action names required')
        actions = frozenset(actions)
        if not actions:
            raise ValueError('explicit action names required')
        key_id = hashlib.sha256(public_key).digest()[:8].hex()
        with self._lock:
            self._grants[key_id] = (bytes(public_key), participant, actions)

    def authorize_and_reserve(self, msg, action):
        if (type(msg.version) is not int or msg.version != 1 or msg.msg_type != MessageType.REQUEST
                or msg.encoding != 'json' or msg.to_id != self.recipient
                or msg.from_id.namespace != 'participant'
                or msg.id.namespace != 'message' or msg.operation_id.namespace != 'logical-operation'
                or msg.epoch.namespace != 'epoch'
                or not isinstance(msg.payload, dict) or msg.payload.get('action') != action):
            raise SecurityError('invalid envelope or route')
        if (not isinstance(msg.subject.target_type, str) or not msg.subject.target_type
                or len(msg.subject.target_type) > 256 or type(msg.timestamp.nanos) is not int
                or not 0 <= msg.timestamp.nanos < 2**64
                or (msg.subject.closure_version is not None and
                    (type(msg.subject.closure_version) is not int or not 0 <= msg.subject.closure_version < 2**64))):
            raise SecurityError('invalid metadata')
        for ident in (msg.id, msg.operation_id, msg.from_id, msg.to_id, msg.epoch, msg.subject.target_id):
            if (not isinstance(ident.value, str) or not ident.value or len(ident.value) > 256
                    or not ident.is_valid() or len(ident.namespace) > 256
                    or (ident.version is not None and (type(ident.version) is not int or not 0 <= ident.version < 2**64))):
                raise SecurityError('invalid identifier')
        with self._lock:
            grant = self._grants.get(msg.key_id)
            if not grant or grant[1] != msg.from_id or action not in grant[2]:
                raise SecurityError('not authorized')
            if not msg.verify_signature(grant[0]):
                raise SecurityError('invalid signature')
            message_key = (msg.from_id, msg.id)
            operation_key = (msg.from_id, msg.operation_id)
            if message_key in self._messages or operation_key in self._operations:
                raise SecurityError('replay')
            if len(self._messages) >= self.capacity:
                raise SecurityError('replay journal full')
            self._messages.add(message_key)
            self._operations.add(operation_key)
