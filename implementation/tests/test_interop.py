"""Run real SDKs across loopback in both directions; bounded child processes, no external service.

Run this file directly. ORDAVYN_INTEROP_PEER may point at a prebuilt Rust peer.
"""
import copy
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import tempfile
import time
from cbor2._encoder import dumps as canonical_cbor
from contextlib import contextmanager
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ordavyn import Identifier, MessageBuilder, Ed25519Keypair, Ordavyn
from ordavyn.message import Message, MessageType
from ordavyn.client import OrdavynClient

ROOT=Path(__file__).resolve().parents[1]
FIXTURE=Path(os.environ.get('ORDAVYN_WIRE_FIXTURE',ROOT/'tests/fixtures/wire-v2.json'))
DATA=json.loads(FIXTURE.read_text())
KEY=Ed25519Keypair(Ed25519PrivateKey.from_private_bytes(bytes.fromhex(DATA['seed_hex'])))
PEER=Path(os.environ.get('ORDAVYN_INTEROP_PEER',ROOT/'target/debug/examples/interop_peer'))


def call(*args):
    return subprocess.run([str(PEER),*map(str,args)],capture_output=True,text=True,timeout=10,check=True).stdout.strip()


def readline(proc, timeout=5):
    # Read one byte at a time from an unbuffered, nonblocking pipe. Readiness
    # for a partial line must never turn into an unbounded readline().
    deadline = time.monotonic() + timeout
    line = bytearray()
    while len(line) < 4096:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([proc.stdout], [], [], remaining)[0]:
            raise TimeoutError('Rust peer did not reply within deadline')
        chunk = os.read(proc.stdout.fileno(), 1)
        if not chunk:
            raise RuntimeError('Rust peer exited')
        if chunk == b'\n':
            return line.decode('utf-8').strip()
        line.extend(chunk)
    raise ValueError('Rust peer line exceeds limit')


@contextmanager
def rust_server(capacity=1000):
    proc=subprocess.Popen([str(PEER),'server',str(capacity)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
    os.set_blocking(proc.stdout.fileno(), False)
    try:
        port=int(readline(proc))
        def count():
            proc.stdin.write(b'count\n');proc.stdin.flush()
            return int(readline(proc))
        yield port,count
    finally:
        try:
            if proc.poll() is None:
                try:
                    proc.stdin.write(b'stop\n'); proc.stdin.flush()
                except (BrokenPipeError, OSError):
                    pass
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill(); proc.wait(timeout=5)
        finally:
            proc.stdin.close(); proc.stdout.close(); proc.stderr.close()


def raw(port,body,path='/ordavyn/v2/act',version='2',content_type='application/json'):
    if isinstance(body,str):body=body.encode('utf-8')
    deadline=time.monotonic()+4
    with socket.create_connection(('127.0.0.1',port),timeout=4) as sock:
        header=(f'POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: {content_type}\r\nx-ordavyn-version: {version}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n').encode()
        sock.sendall(header+body)
        response=b''
        while True:
            remaining=deadline-time.monotonic()
            if remaining<=0: raise TimeoutError('response deadline')
            sock.settimeout(remaining)
            try:chunk=sock.recv(4096)
            except ConnectionResetError:break
            if not chunk:break
            response+=chunk
            if len(response)>65536+8192: raise ValueError('response byte limit')
    assert response, 'server must answer bounded input'
    return int(response.split(b' ',2)[1])


def exercise(port,count,origin,tmp):
    seq=0
    def fresh(action='act'):
        nonlocal seq
        seq+=1
        msg=MessageBuilder(Identifier('participant','caller'),Identifier('participant','service')).payload({'action':action,'value':'雪'}).build()
        if origin=='rust':
            f=tmp/f'message-{seq}.json';f.write_text(msg.to_json())
            return Message.from_dict(json.loads(call('sign',f)))
        msg.sign(KEY);return msg
    msg=fresh()
    if origin=='python': result=OrdavynClient(port=port).send('/act',msg,sign=False)
    else:
        f=tmp/'send.json';f.write_text(msg.to_json());result=Message.from_dict(json.loads(call('client',port,f)))
    assert result.msg_type==MessageType.RESPONSE and result.operation_id==msg.operation_id
    assert result.payload['effects']==1 and count()==1
    cases=[]
    replay=fresh();replay.id=msg.id;replay.sign(KEY)
    cases.append(('message-replay',replay.to_json(),{}))
    retry=fresh();retry.operation_id=msg.operation_id;retry.sign(KEY)
    cases.append(('operation-replay',retry.to_json(),{}))
    for field in ['payload','signature','key','permission','unsigned','version','encoding','unknown','alias','missing','aim-missing','aim-unknown','wrong-type','integer','utf8','depth']:
        m=fresh('denied' if field=='permission' else 'act');d=m.to_dict()
        if field=='payload':d['payload']['value']='tampered'
        elif field=='signature':d['signature']='00'*64
        elif field=='key':m.sign(Ed25519Keypair.generate());d=m.to_dict()
        elif field=='unsigned':d.update(signature=None,key_id=None,signature_alg=None)
        elif field=='version':d['version']=1
        elif field=='encoding':d['encoding']='cbor'
        elif field=='unknown':d['extra']=0
        elif field=='alias':d['msg_type']=d.pop('type')
        elif field=='missing':del d['signature']
        elif field=='aim-missing':del d['subject']['closure_version']
        elif field=='aim-unknown':d['id']['extra']=0
        elif field=='wrong-type':d['timestamp']['nanos']=1.0
        elif field=='integer':d['payload']['value']=2**64
        elif field=='utf8':d['id']['value']='я'*129
        elif field=='depth':
            v=0
            for _ in range(32):v=[v]
            d['payload']['value']=v
        if field in {'version','encoding','unknown','alias','aim-missing','aim-unknown','wrong-type','integer','utf8','depth'}:
            raw_sign(d)
        cases.append((field,json.dumps(d),{'path':'/ordavyn/v2/denied'} if field=='permission' else {}))
    over_model=fresh().to_dict();over_model['payload']['value']=[0.1]*8000;raw_sign(over_model)
    cases.append(('model-budget',json.dumps(over_model,separators=(',',':')),{}))
    for case in DATA['invalid_json']:cases.append((case['name'],case['json'],{}))
    cases.extend([('old-route',fresh().to_json(),{'path':'/ordavyn/v1/act'}),('old-header',fresh().to_json(),{'version':'1'}),('cbor-network',b'\xa0',{'content_type':'application/cbor'}),('oversized',b' '*65537,{})])
    for name,body,opts in cases:
        assert raw(port,body,**opts)!=200,(origin,name)
        assert count()==1,(origin,name,'handler ran')
    # A signed but structurally invalid request must not reserve either ID.
    last=fresh()
    invalid=last.to_dict();invalid['timestamp']['nanos']=1.0;raw_sign(invalid)
    assert raw(port,json.dumps(invalid))!=200 and count()==1
    assert raw(port,last.to_json())==200 and count()==2
    effects=2
    for refusal in ('wrong-key','no-permission','route-mismatch'):
        retry=fresh('denied' if refusal=='no-permission' else 'act')
        if refusal=='wrong-key': retry.sign(Ed25519Keypair.generate())
        path='/ordavyn/v2/denied' if refusal in ('no-permission','route-mismatch') else '/ordavyn/v2/act'
        assert raw(port,retry.to_json(),path=path)!=200 and count()==effects
        retry.payload['action']='act';retry.sign(KEY)
        assert raw(port,retry.to_json())==200
        effects+=1
        assert count()==effects
    for vector in DATA['vectors']:
        item=fresh()
        item.payload={'action':'act','value':vector['message']['payload']}
        item.subject=Message.from_dict(vector['message']).subject
        item.timestamp=Message.from_dict(vector['message']).timestamp
        item.id=Identifier(item.id.namespace,item.id.value,vector['message']['id']['version'])
        item.sign(KEY)
        if origin=='rust':
            f=tmp/'numeric.json';f.write_text(item.to_json())
            item=Message.from_dict(json.loads(call('sign',f)))
            f.write_text(item.to_json());result=Message.from_dict(json.loads(call('client',port,f)))
        else:
            result=OrdavynClient(port=port).send('/act',item,sign=False)
        effects+=1
        assert canonical_cbor(result.payload['echo'],canonical=True)==canonical_cbor(item.payload['value'],canonical=True)
        assert result.subject==item.subject and count()==effects
    # Rust spelling fits exactly; Python's equivalent JSON exceeds the network cap.
    edge=fresh();edge.payload={'action':'act','value':[1e-7]*100,'padding':'\n'*1000};edge.sign(KEY)
    data=edge.to_dict()
    compact=json.dumps(data,separators=(',',':'),ensure_ascii=False).replace('1e-07','1e-7')
    data['payload']['padding']+='x'*(65536-len(compact.encode()))
    raw_sign(data)
    body=json.dumps(data,separators=(',',':'),ensure_ascii=False).replace('1e-07','1e-7')
    assert len(body.encode())==65536
    if origin=='rust':
        f=tmp/'boundary.json';f.write_text(body)
        body=call('sign',f)
        assert len(body.encode())==65536
    assert raw(port,body)==200
    effects+=1
    assert count()==effects
    assert raw(port,body+' ')!=200 and count()==effects
    print(f'{origin} -> other SDK: {effects} effects; {len(cases)} refusals, same-ID recovery, numeric/optional vectors, 64KiB boundary',flush=True)


def raw_sign(data):
    # Independent test signer deliberately bypasses production shape validation.
    data['signature_alg']=1;data['key_id']=KEY.key_id()
    value={key:value for key,value in data.items() if key!='signature'}
    data['signature']=KEY.sign(b'ordavyn:v2:message\0'+canonical_cbor(value,canonical=True)).hex()


def capacity_exercise(port,count,origin,tmp):
    for n in range(3):
        msg=MessageBuilder(Identifier('participant','caller'),Identifier('participant','service')).payload({'action':'act','value':n}).build()
        msg.sign(KEY)
        if origin=='rust':
            f=tmp/'capacity.json';f.write_text(msg.to_json())
            msg=Message.from_dict(json.loads(call('sign',f)))
        assert (raw(port,msg.to_json())==200)==(n<2)
        assert count()==min(n+1,2)


def python_server(capacity=1000):
    effects=[]
    server=Ordavyn(port=0,participant=Identifier('participant','service'),replay_capacity=capacity).trust(KEY.public_key_bytes(),Identifier('participant','caller'),['act'])
    @server.expose('/denied')
    @server.expose('/act')
    def act(value, padding=None):
        effects.append(value);return {'effects':len(effects),'echo':value}
    return server,effects


def main():
    if 'ORDAVYN_INTEROP_PEER' not in os.environ:
        subprocess.run(['cargo','build','--manifest-path',str(ROOT/'Cargo.toml'),'--locked','--example','interop_peer'],check=True,timeout=120)
    for args in [('sign',),('client',),('client','1234')]:
        invalid=subprocess.run([str(PEER),*args],capture_output=True,text=True,timeout=5)
        assert invalid.returncode!=0 and 'usage:' in invalid.stderr and 'panicked' not in invalid.stderr
    with tempfile.TemporaryDirectory(prefix='ordavyn-interop-') as directory:
        tmp=Path(directory)
        with rust_server() as (port,count):exercise(port,count,'python',tmp)
        server,effects=python_server()
        server.start()
        try:exercise(server.port,lambda:len(effects),'rust',tmp)
        finally:server.stop()
        with rust_server(2) as (port,count):capacity_exercise(port,count,'python',tmp)
        server,effects=python_server(2);server.start()
        try:capacity_exercise(server.port,lambda:len(effects),'rust',tmp)
        finally:server.stop()
    return 0

if __name__=='__main__':raise SystemExit(main())
