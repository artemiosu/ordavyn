
from ordavyn import Ed25519Keypair, Identifier
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
TEST_SIGNER = Ed25519Keypair(Ed25519PrivateKey.from_private_bytes(bytes([99])*32))
import sqlite3
import threading
import pytest
from ordavyn.journal import identifier_blob
from ordavyn import Identifier, MemoryJournal, SQLiteJournal, JournalError, Ordavyn, Ed25519Keypair, MessageBuilder, MessageType

RECIPIENT = Identifier('participant', 'service', 2**64-1)
SENDER = Identifier('participant', 'caller')
MESSAGE = Identifier('message', 'm', 2**64-1)
OPERATION = Identifier('logical-operation', 'op')

@pytest.fixture(params=['memory','sqlite'])
def journal(request, tmp_path):
    return MemoryJournal(RECIPIENT, 2) if request.param == 'memory' else SQLiteJournal.create(tmp_path/'journal.sqlite', RECIPIENT, 2)


def test_reservation_states_capacity_close(journal):
    token = journal.reserve(SENDER, MESSAGE, OPERATION)
    assert journal.inspect()[0]['state'] == 'outcome_unknown'
    with pytest.raises(JournalError): journal.close()
    journal.complete(token)
    journal.release(token)
    assert journal.inspect()[0]['state'] == 'handler_returned'
    for m, op in [(MESSAGE, Identifier('logical-operation','other')), (Identifier('message','other'), OPERATION)]:
        with pytest.raises(JournalError): journal.reserve(SENDER,m,op)
    token = journal.reserve(SENDER,Identifier('message','two'),Identifier('logical-operation','two'))
    journal.release(token)
    with pytest.raises(JournalError): journal.reserve(SENDER,Identifier('message','three'),Identifier('logical-operation','three'))
    journal.close()
    with pytest.raises(JournalError): journal.inspect()


def test_open_validation(tmp_path):
    path = tmp_path/'journal.sqlite'
    with pytest.raises((OSError, sqlite3.Error)): SQLiteJournal.open(path,RECIPIENT,2)
    assert not path.exists()
    j = SQLiteJournal.create(path,RECIPIENT,2)
    token = j.reserve(SENDER,MESSAGE,OPERATION); j.release(token); j.close()
    with pytest.raises(FileExistsError): SQLiteJournal.create(path,RECIPIENT,2)
    for recipient, capacity in [(Identifier('participant','wrong'),2),(RECIPIENT,3)]:
        with pytest.raises(JournalError): SQLiteJournal.open(path,recipient,capacity)
    j = SQLiteJournal.open(path,RECIPIENT,2)
    assert j.inspect()[0]['message'] == MESSAGE
    assert j.inspect()[0]['state'] == 'outcome_unknown'
    with pytest.raises(JournalError): j.reserve(SENDER,MESSAGE,OPERATION)
    j.close()


@pytest.mark.parametrize('mutation', ['version','state','identifier','schema','corrupt','overfull'])
def test_reject_damaged_journal(tmp_path, mutation):
    path = tmp_path/'journal.sqlite'
    j = SQLiteJournal.create(path,RECIPIENT,2)
    t = j.reserve(SENDER,MESSAGE,OPERATION); j.release(t); j.close()
    if mutation == 'corrupt': path.write_bytes(b'not sqlite')
    else:
        with sqlite3.connect(path) as db:
            if mutation == 'version': db.execute('UPDATE metadata SET version=3')
            elif mutation == 'state':
                db.execute('PRAGMA ignore_check_constraints=ON'); db.execute("UPDATE operations SET state='success'")
            elif mutation == 'identifier': db.execute("UPDATE operations SET message=x'01'")
            elif mutation == 'schema': db.execute('CREATE TABLE extra(a)')
            elif mutation == 'overfull':
                for n in ('two', 'three'):
                    db.execute("INSERT INTO operations VALUES (?,?,?,'outcome_unknown')", (identifier_blob(SENDER),identifier_blob(Identifier('message',n)),identifier_blob(Identifier('logical-operation',n))))
    with pytest.raises((JournalError,sqlite3.Error)): SQLiteJournal.open(path,RECIPIENT,2)


def server(journal, handler):
    key = Ed25519Keypair.generate()
    app = Ordavyn(participant=RECIPIENT,replay_capacity=2,journal=journal, signer=TEST_SIGNER)
    app.trust(key.public_key_bytes(),SENDER,['act']); app.expose('/act')(handler)
    msg = MessageBuilder(SENDER,RECIPIENT).payload({'action':'act'}).build(); msg.sign(key)
    return app,msg


def test_unauthorized_and_bad_route_do_not_reserve(journal):
    app,msg = server(journal,lambda: {})
    assert app._handle_request(msg,'/ordavyn/v3/wrong').msg_type == MessageType.ERROR
    msg.signature = '00'*64
    assert app._handle_request(msg).msg_type == MessageType.ERROR
    assert journal.inspect() == []


@pytest.mark.parametrize('failure', ['exception','response','complete'])
def test_handler_failure_unknown(journal,failure,monkeypatch):
    effects=[]
    def handle():
        effects.append(1)
        if failure=='exception': raise RuntimeError()
        if failure=='response': return object()
        return {}
    if failure=='complete': monkeypatch.setattr(journal,'_complete',lambda _: (_ for _ in ()).throw(sqlite3.OperationalError('commit failed')))
    app,msg = server(journal,handle)
    assert app._handle_request(msg).msg_type == MessageType.ERROR
    assert journal.inspect()[0]['state']=='outcome_unknown'
    assert app._handle_request(msg).msg_type == MessageType.ERROR and effects==[1]
    journal.close()


def test_sqlite_real_commit_failure(tmp_path):
    path=tmp_path/'journal.sqlite'; j=SQLiteJournal.create(path,RECIPIENT,2)
    reader=sqlite3.connect(path,isolation_level=None)
    effects=[]
    def handle():
        effects.append(1)
        reader.execute('BEGIN'); reader.execute('SELECT * FROM operations').fetchall()
        return {}
    app,msg=server(j,handle)
    assert app._handle_request(msg).msg_type == MessageType.ERROR
    reader.execute('ROLLBACK'); reader.close()
    assert j.inspect()[0]['state']=='outcome_unknown'
    assert app._handle_request(msg).msg_type == MessageType.ERROR and effects==[1]
    j.close()


def test_write_and_lock_failure_before_handler(tmp_path):
    path=tmp_path/'journal.sqlite'; j=SQLiteJournal.create(path,RECIPIENT,2)
    effects=[]; app,msg=server(j,lambda: effects.append(1))
    j._db.execute('PRAGMA query_only=ON')
    assert app._handle_request(msg).msg_type == MessageType.ERROR and not effects
    j._db.execute('PRAGMA query_only=OFF')
    with sqlite3.connect(path,isolation_level=None) as other:
        other.execute('BEGIN IMMEDIATE')
        assert app._handle_request(msg).msg_type == MessageType.ERROR and not effects
        other.execute('ROLLBACK')
        # A held reader allows the insert but forces reservation COMMIT to fail.
        other.execute('BEGIN'); other.execute('SELECT * FROM operations').fetchall()
        assert app._handle_request(msg).msg_type == MessageType.ERROR and not effects
        other.execute('ROLLBACK')
    assert not j.inspect()
    assert app._handle_request(msg).msg_type == MessageType.RESPONSE
    j.close()


def test_close_and_stop_during_handler(journal):
    entered=threading.Event(); resume=threading.Event()
    def handle(): entered.set(); assert resume.wait(5); return {}
    app,msg=server(journal,handle)
    worker=threading.Thread(target=lambda: app._handle_request(msg)); worker.start()
    assert entered.wait(5)
    try:
        with pytest.raises(JournalError): journal.close()
        app.stop()
        assert journal.inspect()[0]['state']=='outcome_unknown'
    finally: resume.set(); worker.join(5)
    assert journal.inspect()[0]['state']=='handler_returned'; journal.close()


def test_configuration_is_read_only(journal):
    for name, value in [('recipient', Identifier('participant','other')), ('capacity', 100)]:
        with pytest.raises(AttributeError): setattr(journal, name, value)
    assert journal.recipient == RECIPIENT and journal.capacity == 2
    journal.close()


@pytest.mark.parametrize('kind', ['memory', 'sqlite'])
def test_reservation_handles_belong_to_one_instance(tmp_path, kind):
    journals = ([MemoryJournal(RECIPIENT,2), MemoryJournal(RECIPIENT,2)] if kind=='memory'
                else [SQLiteJournal.create(tmp_path/f'{n}.sqlite',RECIPIENT,2) for n in range(2)])
    a,b=journals
    ta=a.reserve(SENDER,MESSAGE,OPERATION); tb=b.reserve(SENDER,MESSAGE,OPERATION)
    for receiver,foreign in [(a,tb),(b,ta)]:
        with pytest.raises(JournalError): receiver.complete(foreign)
        with pytest.raises(JournalError): receiver.release(foreign)
        with pytest.raises(JournalError): receiver.close()
        assert receiver.inspect()[0]['state']=='outcome_unknown'
    a.complete(ta);a.release(ta);b.release(tb)
    for j in journals:j.close()


def test_completion_is_scoped_to_sender(journal):
    other=Identifier('participant','other')
    a=journal.reserve(SENDER,MESSAGE,OPERATION); b=journal.reserve(other,MESSAGE,OPERATION)
    journal.complete(a);journal.release(a);journal.release(b)
    expected={SENDER:'handler_returned',other:'outcome_unknown'}
    assert {r['sender']:r['state'] for r in journal.inspect()}==expected
    if isinstance(journal,SQLiteJournal):
        path=journal._db.execute('PRAGMA database_list').fetchone()[2]
        journal.close();journal=SQLiteJournal.open(path,RECIPIENT,2)
        assert {r['sender']:r['state'] for r in journal.inspect()}==expected
    journal.close()


def test_inspection_rejects_unknown_state_after_open(tmp_path):
    path=tmp_path/'state.sqlite';j=SQLiteJournal.create(path,RECIPIENT,2)
    t=j.reserve(SENDER,MESSAGE,OPERATION);j.release(t)
    with sqlite3.connect(path) as db:
        db.execute('PRAGMA ignore_check_constraints=ON')
        db.execute("UPDATE operations SET state='unexpected'")
    with pytest.raises(JournalError):j.inspect()
    j.close()


class InterruptConnection:
    def __init__(self, db, exception):self.db=db;self.exception=exception;self.armed=True
    def __getattr__(self,name):return getattr(self.db,name)
    def execute(self,sql,*args):
        if sql=='COMMIT' and self.armed:
            self.armed=False
            raise self.exception()
        return self.db.execute(sql,*args)


@pytest.mark.parametrize('exception',[KeyboardInterrupt,SystemExit])
@pytest.mark.parametrize('operation',['reserve','complete','validate'])
def test_interruption_rolls_back_and_connection_reusable(tmp_path,exception,operation):
    path=tmp_path/'interrupt.sqlite';j=SQLiteJournal.create(path,RECIPIENT,2)
    token=j.reserve(SENDER,MESSAGE,OPERATION) if operation=='complete' else None
    j._db=InterruptConnection(j._db,exception)
    with pytest.raises(exception):
        if operation=='reserve':j.reserve(SENDER,MESSAGE,OPERATION)
        elif operation=='complete':j.complete(token)
        else:j._validate()
    assert not j._db.in_transaction
    with sqlite3.connect(path,isolation_level=None) as other:
        other.execute('BEGIN IMMEDIATE');other.execute('ROLLBACK')
    if token is None:
        assert j.inspect()==[];token=j.reserve(SENDER,MESSAGE,OPERATION)
    else:assert j.inspect()[0]['state']=='outcome_unknown'
    j.complete(token);j.release(token);j.close()


@pytest.mark.parametrize('exception',[KeyboardInterrupt,SystemExit])
@pytest.mark.parametrize('opening',[False,True])
def test_interrupted_initialization_closes_connection(tmp_path,monkeypatch,exception,opening):
    path=tmp_path/'initialization.sqlite'
    if opening:SQLiteJournal.create(path,RECIPIENT,2).close()
    original=sqlite3.connect;connections=[]
    def connect(*args,**kwargs):
        db=original(*args,**kwargs);connections.append(db)
        return InterruptConnection(db,exception)
    monkeypatch.setattr(sqlite3,'connect',connect)
    with pytest.raises(exception):
        (SQLiteJournal.open if opening else SQLiteJournal.create)(path,RECIPIENT,2)
    with pytest.raises(sqlite3.ProgrammingError):connections[0].execute('SELECT 1')
    with original(path,isolation_level=None) as db:
        db.execute('BEGIN IMMEDIATE');db.execute('ROLLBACK')
