"""Local explicit grants and bounded replay protection.

No delegation, expiry negotiation or remote key discovery.
"""
import hashlib
import threading
import math
import time
from collections.abc import Collection, Mapping
from .aim import Identifier
from .message import MessageType
from .journal import MemoryJournal

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
    def __init__(self, recipient, capacity=10000, journal=None):
        if not isinstance(recipient, Identifier) or recipient.namespace != 'participant' or type(capacity) is not int or capacity < 1:
            raise ValueError('recipient and positive replay capacity required')
        self.recipient = recipient
        self.capacity = capacity
        self._grants = {}
        self.journal = journal if journal is not None else MemoryJournal(recipient, capacity)
        if self.journal.recipient != recipient or self.journal.capacity != capacity:
            raise ValueError("journal binding mismatch")
        self._lock = threading.RLock()
        self._condition = threading.Condition(self._lock)
        self._accepting = True
        self._active = set()
        self._network = 0

    def trust(self, public_key, participant, actions):
        public_key = self._key(public_key)
        if not isinstance(participant, Identifier) or participant.namespace != 'participant' or not participant.is_valid():
            raise ValueError('invalid local key binding')
        if (not isinstance(actions, Collection) or isinstance(actions, (str, bytes, bytearray, Mapping))
                or not actions or any(type(a) is not str or not valid_endpoint('/' + a) for a in actions)):
            raise ValueError('explicit action names required')
        actions = frozenset(actions)
        if not actions:
            raise ValueError('explicit action names required')
        key_id = hashlib.sha256(public_key).digest()[:8].hex()
        with self._lock:
            old = self._grants.get(key_id)
            if old and (old[0] != public_key or old[1] != participant):
                raise ValueError('conflicting local key binding')
            self._grants[key_id] = (public_key, participant, actions)

    @staticmethod
    def _key(public_key):
        if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != 32:
            raise ValueError('invalid public key')
        return bytes(public_key)

    def revoke(self, public_key):
        public_key = self._key(public_key)
        key_id = hashlib.sha256(public_key).digest()[:8].hex()
        with self._lock:
            old = self._grants.get(key_id)
            if old is None or old[0] != public_key:
                return False
            del self._grants[key_id]
            return True

    def rotate_key(self, old_key, new_key):
        old_key, new_key = self._key(old_key), self._key(new_key)
        old_id = hashlib.sha256(old_key).digest()[:8].hex()
        new_id = hashlib.sha256(new_key).digest()[:8].hex()
        with self._lock:
            old = self._grants.get(old_id)
            if old is None or old[0] != old_key or old_key == new_key or new_id in self._grants:
                raise ValueError('invalid key rotation')
            self._grants[new_id] = (new_key, old[1], old[2])
            del self._grants[old_id]

    def request_stop(self):
        with self._condition:
            self._accepting = False
            self._condition.notify_all()

    @staticmethod
    def validate_timeout(timeout):
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout < 0 or timeout > threading.TIMEOUT_MAX or not math.isfinite(timeout):
            raise ValueError('finite nonnegative timeout required')

    def wait_stopped(self, timeout):
        self.validate_timeout(timeout)
        deadline = time.monotonic() + timeout
        with self._condition:
            while self._active or self._network:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._condition.wait(remaining)
            return True

    def resume(self):
        with self._lock:
            if self._active or self._network:
                raise RuntimeError('server or handler still running')
            self._accepting = True

    def finish(self, reservation):
        with self._condition:
            if reservation in self._active:
                try:
                    self.journal.release(reservation, _missing_ok=True)
                finally:
                    self._active.discard(reservation)
                    self._condition.notify_all()

    def authorize_and_reserve(self, msg, action, reservation):
        from .wire import validate_envelope
        validate_envelope(msg.to_dict())
        if (type(msg.version) is not int or msg.version != 3 or msg.msg_type != MessageType.REQUEST
                or msg.encoding != 'ordavyn-cbor-v3' or msg.to_id != self.recipient
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
            if not self._accepting:
                raise SecurityError('admission stopped')
            grant = self._grants.get(msg.key_id)
            if not grant or grant[1] != msg.from_id or action not in grant[2]:
                raise SecurityError('not authorized')
            if not msg.verify_signature(grant[0]):
                raise SecurityError('invalid signature')
            # The caller owns this token before entering admission. Register its
            # cleanup before any interruptible return/assignment boundary.
            self._active.add(reservation)
            self.journal.reserve(msg.from_id, msg.id, msg.operation_id, _reservation=reservation)
            return reservation
