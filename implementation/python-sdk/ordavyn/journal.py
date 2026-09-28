"""Local replay journals. A reservation is not evidence of an external effect."""
import os
import sqlite3
import stat
import threading
from urllib.parse import quote
import cbor2
from .aim import Identifier
from .wire import canonical_cbor


SCHEMA = {
    'metadata': 'CREATE TABLE metadata(version INTEGER NOT NULL, recipient BLOB NOT NULL, capacity INTEGER NOT NULL)',
    'operations': "CREATE TABLE operations(sender BLOB NOT NULL, message BLOB NOT NULL, operation BLOB NOT NULL, state TEXT NOT NULL CHECK(state IN ('outcome_unknown','handler_returned')), UNIQUE(sender,message), UNIQUE(sender,operation))",
}


class JournalError(ValueError):
    pass


def identifier_blob(identifier):
    if (not isinstance(identifier, Identifier) or not identifier.is_valid()
            or len(identifier.namespace.encode('utf-8')) > 256
            or len(identifier.value.encode('utf-8')) > 256
            or (identifier.version is not None and
                (type(identifier.version) is not int or not 0 <= identifier.version < 2**64))):
        raise JournalError('invalid journal identifier')
    return canonical_cbor([identifier.namespace, identifier.value, identifier.version], canonical=True)


def _decode(blob, namespace):
    if type(blob) is not bytes:
        raise JournalError('journal identifiers must be BLOBs')
    try:
        parts = cbor2.loads(blob)
        if type(parts) is not list or len(parts) != 3:
            raise ValueError()
        ident = Identifier(*parts)
        if ident.namespace != namespace or identifier_blob(ident) != blob:
            raise ValueError()
        return ident
    except Exception as exc:
        raise JournalError('invalid journal identifier data') from exc


class MemoryJournal:
    """Explicitly temporary; all protection is lost when this object is lost."""
    def __init__(self, recipient, capacity=10000):
        identifier_blob(recipient)
        if recipient.namespace != 'participant' or type(capacity) is not int or not 0 < capacity < 2**63:
            raise JournalError('recipient and positive capacity required')
        self._recipient, self._capacity = recipient, capacity
        self._lock = threading.RLock()
        self._active = {}
        self._closed = False
        self._rows = {}
        self._messages = set()
        self._operations = set()

    @property
    def recipient(self):
        return self._recipient

    @property
    def capacity(self):
        return self._capacity

    def _ready(self):
        if self._closed:
            raise JournalError('journal closed')

    def reserve(self, sender, message, operation):
        key = (identifier_blob(sender), identifier_blob(message), identifier_blob(operation))
        for blob, namespace in zip(key, ('participant', 'message', 'logical-operation')):
            _decode(blob, namespace)
        with self._lock:
            self._ready()
            self._reserve(key)
            reservation = object()
            self._active[reservation] = key
        return reservation

    def _reserve(self, key):
        if (key[0], key[1]) in self._messages or (key[0], key[2]) in self._operations:
            raise JournalError('replay')
        if len(self._rows) >= self.capacity:
            raise JournalError('replay journal full')
        self._rows[key] = 'outcome_unknown'
        self._messages.add((key[0], key[1]))
        self._operations.add((key[0], key[2]))

    def complete(self, reservation):
        with self._lock:
            self._ready()
            if reservation not in self._active:
                raise JournalError('not an active reservation')
            self._complete(self._active[reservation])

    def _complete(self, key):
        if self._rows.get(key) != 'outcome_unknown':
            raise JournalError('reservation missing or already completed')
        self._rows[key] = 'handler_returned'

    def release(self, reservation):
        """End local handler ownership; never delete the replay reservation."""
        with self._lock:
            if reservation not in self._active:
                raise JournalError('not an active reservation')
            del self._active[reservation]

    def inspect(self):
        with self._lock:
            self._ready()
            return [dict(sender=_decode(k[0], 'participant'), message=_decode(k[1], 'message'),
                         operation=_decode(k[2], 'logical-operation'), state=v)
                    for k, v in self._rows.items()]

    def close(self):
        with self._lock:
            if self._active:
                raise JournalError('handler still active')
            self._closed = True


class SQLiteJournal(MemoryJournal):
    """SQLite on trusted ordinary local files; create and open are distinct."""
    @classmethod
    def create(cls, path, recipient, capacity=10000):
        return cls(path, recipient, capacity, create=True)

    @classmethod
    def open(cls, path, recipient, capacity=10000):
        return cls(path, recipient, capacity, create=False)

    def __init__(self, path, recipient, capacity=10000, *, create):
        super().__init__(recipient, capacity)
        path = os.path.abspath(os.fspath(path))
        if create:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(fd)
        if not stat.S_ISREG(os.lstat(path).st_mode):
            raise JournalError('ordinary local file required')
        self._db = None
        try:
            self._db = sqlite3.connect('file:' + quote(path, safe='/') + '?mode=rw', uri=True,
                                       timeout=3, isolation_level=None, check_same_thread=False)
            self._db.execute('PRAGMA busy_timeout=3000')
            if self._db.execute('PRAGMA journal_mode=DELETE').fetchone()[0] != 'delete':
                raise JournalError('DELETE journal required')
            self._db.execute('PRAGMA synchronous=EXTRA')
            if self._db.execute('PRAGMA synchronous').fetchone()[0] != 3:
                raise JournalError('EXTRA synchronization required')
            if self._db.execute('PRAGMA busy_timeout').fetchone()[0] != 3000:
                raise JournalError('invalid lock timeout')
            if create:
                self._db.execute('BEGIN IMMEDIATE')
                self._db.execute(SCHEMA['metadata'])
                self._db.execute(SCHEMA['operations'])
                self._db.execute('INSERT INTO metadata VALUES (1,?,?)', (identifier_blob(recipient), capacity))
                self._db.execute('COMMIT')
            self._validate()
        except BaseException:
            if self._db is not None:
                self._db.close()
            raise

    def _validate(self):
        try:
            self._db.execute('BEGIN IMMEDIATE')
            if self._db.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
                raise JournalError('corrupt journal')
            objects = self._db.execute("SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name").fetchall()
            if objects != [('table', 'metadata'), ('table', 'operations')]:
                raise JournalError('unknown journal schema')
            for table, sql in self._db.execute("SELECT name,sql FROM sqlite_master WHERE type='table'"):
                if sql != SCHEMA.get(table):
                    raise JournalError('unknown journal table definition')
            for table, expected in [('metadata', [('version','INTEGER'),('recipient','BLOB'),('capacity','INTEGER')]),
                                    ('operations', [('sender','BLOB'),('message','BLOB'),('operation','BLOB'),('state','TEXT')])]:
                columns = self._db.execute('PRAGMA table_info(' + table + ')').fetchall()
                if [(r[1], r[2]) for r in columns] != expected or any(r[3] != 1 or r[4] is not None or r[5] != 0 for r in columns):
                    raise JournalError('unknown journal columns')
            indexes = self._db.execute('PRAGMA index_list(operations)').fetchall()
            if len(indexes) != 2 or any(r[2] != 1 or r[3] != 'u' or r[4] != 0 for r in indexes):
                raise JournalError('journal uniqueness missing')
            if sorted(tuple(r[2] for r in self._db.execute('SELECT seqno,cid,name FROM pragma_index_info(?) ORDER BY seqno', (row[1],))) for row in indexes) != [('sender','message'), ('sender','operation')]:
                raise JournalError('invalid journal indexes')
            if self._db.execute('SELECT version,recipient,capacity FROM metadata').fetchall() != [(1, identifier_blob(self.recipient), self.capacity)]:
                raise JournalError('journal metadata mismatch')
            rows = self._db.execute('SELECT sender,message,operation,state FROM operations').fetchall()
            if len(rows) > self.capacity:
                raise JournalError('journal over capacity')
            for sender, message, operation, state in rows:
                _decode(sender, 'participant'); _decode(message, 'message'); _decode(operation, 'logical-operation')
                if state not in ('outcome_unknown', 'handler_returned'):
                    raise JournalError('unknown journal state')
            self._db.execute('COMMIT')
        except BaseException:
            if self._db.in_transaction:
                self._db.execute('ROLLBACK')
            raise

    def _reserve(self, key):
        try:
            self._db.execute('BEGIN IMMEDIATE')
            if self._db.execute('SELECT 1 FROM operations WHERE sender=? AND (message=? OR operation=?)', key).fetchone():
                raise JournalError('replay')
            if self._db.execute('SELECT count(*) FROM operations').fetchone()[0] >= self.capacity:
                raise JournalError('replay journal full')
            self._db.execute("INSERT INTO operations VALUES (?,?,?,'outcome_unknown')", key)
            self._db.execute('COMMIT')
        except BaseException:
            if self._db.in_transaction:
                self._db.execute('ROLLBACK')
            raise

    def _complete(self, key):
        try:
            self._db.execute('BEGIN IMMEDIATE')
            result = self._db.execute("UPDATE operations SET state='handler_returned' WHERE sender=? AND message=? AND operation=? AND state='outcome_unknown'", key)
            if result.rowcount != 1:
                raise JournalError('reservation missing or already completed')
            self._db.execute('COMMIT')
        except BaseException:
            if self._db.in_transaction:
                self._db.execute('ROLLBACK')
            raise

    def inspect(self):
        with self._lock:
            self._ready()
            entries = []
            for a,b,c,d in self._db.execute('SELECT sender,message,operation,state FROM operations'):
                if d not in ('outcome_unknown', 'handler_returned'):
                    raise JournalError('unknown journal state')
                entries.append(dict(sender=_decode(a, 'participant'), message=_decode(b, 'message'),
                                    operation=_decode(c, 'logical-operation'), state=d))
            return entries

    def close(self):
        with self._lock:
            if self._active:
                raise JournalError('handler still active')
            if not self._closed:
                self._db.close()
                self._closed = True
