"""Shared SQLite format, killed subprocesses and cross-SDK admission races.

The independent fsynced effect file is deliberately outside the replay journal.
Checkpoints exercise admission before invocation, after effect before completion,
and after durable completion. No subprocess recovers or retries an admitted action.
"""
import os
from pathlib import Path
import select
import sqlite3
import subprocess
import sys
import time
import pytest
from ordavyn import Identifier, SQLiteJournal
from ordavyn.journal import identifier_blob

ROOT=Path(__file__).resolve().parents[1]
RUST=ROOT/'target/debug/examples/journal_peer'
RECIPIENT=Identifier('participant','service',2**64-1)
PYTHON_PEER=r'''
import os,sys
from ordavyn import Identifier,SQLiteJournal
mode,path=sys.argv[1:3]
r=Identifier('participant','service',2**64-1)
if mode=='create':
    try: SQLiteJournal.create(path,r,2).close();print('created',flush=True)
    except Exception: print('rejected',flush=True)
    raise SystemExit()
try: j=SQLiteJournal.open(path,r,2)
except Exception: print('rejected',flush=True);raise SystemExit()
if mode=='inspect':
    for row in j.inspect():print(row['state'],flush=True)
    j.close();raise SystemExit()
def checkpoint(label):
    print(label,flush=True)
    assert sys.stdin.buffer.read(1)
checkpoint('ready')
try:t=j.reserve(Identifier('participant','caller'),Identifier('message',sys.argv[4],2**64-1),Identifier('logical-operation',sys.argv[5]))
except Exception:print('rejected',flush=True);raise SystemExit()
checkpoint('reserved')
with open(sys.argv[3],'ab',buffering=0) as f:f.write(b'effect\n');os.fsync(f.fileno())
checkpoint('effect')
try:j.complete(t)
except Exception:print('rejected',flush=True);raise SystemExit()
checkpoint('completed');j.release(t);j.close();print('done',flush=True)
'''

@pytest.fixture(scope='module',autouse=True)
def build_peer():
    subprocess.run([os.environ.get('CARGO','cargo'),'build','--locked','--example','journal_peer'],cwd=ROOT,check=True)

def command(language,*args):
    return ([sys.executable,'-u','-c',PYTHON_PEER] if language=='python' else [str(RUST)])+list(map(str,args))

def run(language,*args):
    return subprocess.run(command(language,*args),capture_output=True,text=True,check=True,timeout=15).stdout.strip()

def line(process, timeout=12):
    deadline=time.monotonic()+timeout
    value=bytearray()
    while len(value)<4096:
        remaining=deadline-time.monotonic()
        if remaining<=0 or not select.select([process.stdout],[],[],remaining)[0]:
            raise TimeoutError('subprocess checkpoint timeout')
        chunk=os.read(process.stdout.fileno(),1)
        if not chunk:
            raise RuntimeError('subprocess closed its output')
        if chunk==b'\n':return value.decode().strip()
        value.extend(chunk)
    raise RuntimeError('subprocess checkpoint too long')

def go(process):process.stdin.write(b'g');process.stdin.flush()

def start(language,path,effect,message='m',operation='op'):
    p=subprocess.Popen(command(language,'run',path,effect,message,operation),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
    try:
        assert line(p)=='ready'
        return p
    except BaseException:
        stop(p)
        raise

def stop(p):
    if p.poll() is None:p.kill()
    p.wait(timeout=10)
    for f in (p.stdin,p.stdout,p.stderr):f.close()

def reject(language,path,effect,message='m',operation='op'):
    p=start(language,path,effect,message,operation)
    try:go(p);assert line(p)=='rejected';assert p.wait(timeout=10)==0
    finally:stop(p)

@pytest.mark.parametrize('creator',['python','rust'])
@pytest.mark.parametrize('actor',['python','rust'])
@pytest.mark.parametrize('checkpoint',['reserved','effect','completed'])
def test_killed_process_never_replays(tmp_path,creator,actor,checkpoint):
    path=tmp_path/'journal.sqlite';effect=tmp_path/'effects'
    assert run(creator,'create',path)=='created'
    p=start(actor,path,effect)
    try:
        for phase in ['reserved','effect','completed']:
            go(p);assert line(p)==phase
            if phase==checkpoint:break
    finally:stop(p)
    other='rust' if actor=='python' else 'python'
    state=run(other,'inspect',path)
    assert state in (['handler_returned','HandlerReturned'] if checkpoint=='completed' else ['outcome_unknown','OutcomeUnknown'])
    for language in ['python','rust']:
        reject(language,path,effect)
        reject(language,path,effect,'m','other')
        reject(language,path,effect,'other','op')
    assert (effect.read_bytes() if effect.exists() else b'') == (b'' if checkpoint=='reserved' else b'effect\n')

@pytest.mark.parametrize('pair',[('python','python'),('rust','rust'),('python','rust')])
@pytest.mark.parametrize('last_slot',[False,True])
def test_two_processes_only_one_admission(tmp_path,pair,last_slot):
    path=tmp_path/'journal.sqlite';effect=tmp_path/'effects';assert run('python','create',path)=='created'
    if last_slot:
        j=SQLiteJournal.open(path,RECIPIENT,2)
        token=j.reserve(Identifier('participant','caller'),Identifier('message','prior'),Identifier('logical-operation','prior'));j.release(token);j.close()
    processes=[]
    try:
        for n,language in enumerate(pair):
            processes.append(start(language,path,effect,f'm{n}' if last_slot else 'm',f'op{n}' if last_slot else 'op'))
        for p in processes:go(p)
        states=[line(p) for p in processes];assert sorted(states)==['rejected','reserved']
        winner=processes[states.index('reserved')]
        for phase in ['effect','completed','done']:go(winner);assert line(winner)==phase
        for p in processes:assert p.wait(timeout=10)==0
    finally:
        for p in processes:stop(p)
    assert effect.read_bytes()==b'effect\n'

@pytest.mark.parametrize('language',['python','rust'])
@pytest.mark.parametrize('damage',['version','state','blob','unique','missing','overfull'])
def test_both_sdks_fail_closed_on_damage(tmp_path,language,damage):
    path=tmp_path/'journal.sqlite';effect=tmp_path/'effects'
    if damage=='missing':
        assert run(language,'inspect',path)=='rejected';assert not path.exists();return
    j=SQLiteJournal.create(path,RECIPIENT,2)
    token=j.reserve(Identifier('participant','caller'),Identifier('message','m'),Identifier('logical-operation','op'));j.release(token);j.close()
    with sqlite3.connect(path) as db:
        if damage=='version':db.execute('UPDATE metadata SET version=2')
        elif damage=='state':db.execute('PRAGMA ignore_check_constraints=ON');db.execute("UPDATE operations SET state='success'")
        elif damage=='blob':db.execute("UPDATE operations SET message=x'01'")
        elif damage=='overfull':
            for n in ('two','three'):
                db.execute("INSERT INTO operations VALUES (?,?,?,'outcome_unknown')",(identifier_blob(Identifier('participant','caller')),identifier_blob(Identifier('message',n)),identifier_blob(Identifier('logical-operation',n))))
        elif damage=='unique':db.execute('ALTER TABLE operations RENAME TO old');db.execute('CREATE TABLE operations(sender BLOB NOT NULL,message BLOB NOT NULL,operation BLOB NOT NULL,state TEXT NOT NULL)');db.execute('INSERT INTO operations SELECT * FROM old');db.execute('DROP TABLE old')
    assert run(language,'inspect',path)=='rejected'




HOT_WRITER = r"""
import sqlite3,sys
from ordavyn import Identifier
from ordavyn.journal import identifier_blob
connection=sqlite3.connect(sys.argv[1],isolation_level=None)
connection.execute('PRAGMA journal_mode=DELETE')
connection.execute('PRAGMA synchronous=EXTRA')
connection.execute('PRAGMA cache_size=1')
connection.execute('PRAGMA cache_spill=ON')
connection.execute('BEGIN IMMEDIATE')
connection.execute("UPDATE operations SET state='handler_returned'")
# Exceed the page cache to force uncommitted pages into the main file and a hot rollback journal.
for n in range(500):
    connection.execute("INSERT INTO operations VALUES (?,?,?,'outcome_unknown')",
        (identifier_blob(Identifier('participant','caller')),
         identifier_blob(Identifier('message','uncommitted-'+str(n))),
         identifier_blob(Identifier('logical-operation','uncommitted-'+str(n)))))
print('dirty',flush=True)
assert sys.stdin.buffer.read(1)
"""

@pytest.mark.parametrize('language',['python','rust'])
def test_hot_rollback_journal_recovered_by_each_sdk(tmp_path,language):
    path=tmp_path/'hot.sqlite';effect=tmp_path/'effects'
    j=SQLiteJournal.create(path,RECIPIENT,2)
    token=j.reserve(Identifier('participant','caller'),Identifier('message','m',2**64-1),Identifier('logical-operation','op'))
    j.release(token);j.close()
    p=subprocess.Popen([sys.executable,'-u','-c',HOT_WRITER,str(path)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
    try:
        assert line(p)=='dirty'
        rollback=Path(str(path)+'-journal')
        assert rollback.stat().st_size>512
        assert rollback.read_bytes()[:8]==bytes.fromhex('d9d505f920a163d7')
    finally:stop(p)
    assert run(language,'inspect',path) in ('outcome_unknown','OutcomeUnknown')
    reject(language,path,effect)
    reopened=SQLiteJournal.open(path,RECIPIENT,2)
    assert len(reopened.inspect())==1
    token=reopened.reserve(Identifier('participant','caller'),Identifier('message','uncommitted-0'),Identifier('logical-operation','uncommitted-0'))
    reopened.release(token);reopened.close()
    assert not effect.exists()


@pytest.mark.parametrize('script',[
    "import sys,time;sys.stdout.write('partial');sys.stdout.flush();time.sleep(10)",
    "import os,time;os.close(1);time.sleep(10)",
])
def test_line_read_is_bounded_even_with_open_stderr(script):
    p=subprocess.Popen([sys.executable,'-u','-c',script],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
    started=time.monotonic()
    try:
        with pytest.raises((TimeoutError,RuntimeError)):line(p,timeout=0.2)
        assert time.monotonic()-started<2
    finally:stop(p)


def test_failed_start_cleans_up_child(monkeypatch,tmp_path):
    original=subprocess.Popen;children=[]
    def track(*args,**kwargs):
        p=original(*args,**kwargs);children.append(p);return p
    monkeypatch.setattr(subprocess,'Popen',track)
    monkeypatch.setattr(sys.modules[__name__],'command',lambda *args:[sys.executable,'-u','-c',"import time;print('wrong',flush=True);time.sleep(10)"])
    with pytest.raises(AssertionError):start('python',tmp_path/'unused',tmp_path/'effect')
    assert len(children)==1 and children[0].poll() is not None
    assert all(stream.closed for stream in (children[0].stdin,children[0].stdout,children[0].stderr))

if __name__=='__main__':raise SystemExit(pytest.main([__file__,'-q']))
