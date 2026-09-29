"""Live v3/TLS matrix. Certificates are generated only in temporary directories."""
import copy
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import importlib.util
import ipaddress
import ssl
import json
import os
from pathlib import Path
import socket
import subprocess
import threading
import time

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from ordavyn import SQLiteJournal, ClientTLS, ServerTLS, Ordavyn, OrdavynClient, Message, MessageBuilder, Identifier, MessageType
from ordavyn.wire import request_digest

spec = importlib.util.spec_from_file_location('exchange_peer', Path(__file__).with_name('test_interop.py'))
peer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(peer)
SERVICE = Identifier('participant', 'service')
CALLER = Identifier('participant', 'caller')

@pytest.fixture
def certificates(tmp_path):
    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'temporary test CA')])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now-timedelta(days=2)).not_valid_after(now+timedelta(days=2))
          .add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True)
          .add_extension(x509.KeyUsage(False,False,False,False,False,True,True,False,False),critical=True)
          .sign(ca_key,hashes.SHA256()))
    ca_path = tmp_path/'ca.pem'; ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    def leaf(kind='valid'):
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        cert=(x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'test.local')]))
              .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
              .not_valid_before(now+timedelta(days=1) if kind=='future' else now-timedelta(days=2))
              .not_valid_after(now-timedelta(days=1) if kind=='expired' else now+timedelta(days=2))
              .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True)
              .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),critical=False))
        if kind!='cn-only':
            san=[x509.IPAddress(ipaddress.ip_address('127.0.0.1'))] if kind=='ip' else [x509.DNSName('test.local')]
            cert=cert.add_extension(x509.SubjectAlternativeName(san),critical=False)
        cert=cert.sign(ca_key,hashes.SHA256())
        certfile=tmp_path/f'cert-{kind}.pem';keyfile=tmp_path/f'key-{kind}.pem'
        certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        keyfile.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        return certfile,keyfile
    return ca_path,leaf(),leaf('expired'),leaf



def request():
    msg=MessageBuilder(CALLER,SERVICE).payload({'action':'act','value':'local only'}).build()
    msg.sign(peer.KEY)
    return msg


@contextmanager
def server(language, certificates, monkeypatch, expired=False, certificate='valid', journal_path=None, reopen=False):
    ca,good,bad=certificates[:3]
    cert,key=certificates[3](certificate) if certificate!='valid' else bad if expired else good
    if language=='rust':
        monkeypatch.setenv('ORDAVYN_TLS_CERT',str(cert));monkeypatch.setenv('ORDAVYN_TLS_KEY',str(key))
        if journal_path is not None:
            monkeypatch.setenv('ORDAVYN_TEST_JOURNAL',str(journal_path))
            monkeypatch.setenv('ORDAVYN_TEST_JOURNAL_MODE','open' if reopen else 'create')
        with peer.rust_server() as (port,count):yield port,count,None
    else:
        journal=(SQLiteJournal.open if reopen else SQLiteJournal.create)(journal_path,SERVICE,1000) if journal_path is not None else None
        app=Ordavyn(port=0,participant=SERVICE,signer=peer.TEST_SIGNER,tls=ServerTLS(str(cert),str(key)),journal=journal,replay_capacity=1000)
        app.trust(peer.KEY.public_key_bytes(),CALLER,['act']); effects=[]
        @app.expose('/act')
        def act(value):
            effects.append(value)
            if value=='fail-after-effect':raise RuntimeError('simulated failure after effect')
            return {'echo':'\n'*40000 if value=='oversize' else value}
        app.start()
        try:yield app.port,lambda:len(effects),app
        finally:
            assert app.stop(4)
            if journal is not None:journal.close()


def send(language, port, msg, ca, name, tmp_path, monkeypatch):
    if language=='python':
        return OrdavynClient(port=port,response_key=peer.TEST_SIGNER.public_key_bytes(),participant=SERVICE,tls=ClientTLS(ca.read_text(),name)).send('/act',msg)
    monkeypatch.setenv('ORDAVYN_TLS_CA',str(ca));monkeypatch.setenv('ORDAVYN_TLS_NAME',name)
    path=tmp_path/'request.json';path.write_text(msg.to_json())
    return Message.from_dict(json.loads(peer.call('client',port,path)))


@pytest.mark.parametrize('server_language',['python','rust'])
@pytest.mark.parametrize('client_language',['python','rust'])
def test_tls_all_pairs_success_and_signed_admission_error(server_language,client_language,certificates,tmp_path,monkeypatch):
    with server(server_language,certificates,monkeypatch) as (port,count,app):
        msg=request()
        for expected in [MessageType.RESPONSE,MessageType.ERROR]:
            response=send(client_language,port,msg,certificates[0],'test.local',tmp_path,monkeypatch)
            assert response.msg_type==expected and response.verify_signature(peer.TEST_SIGNER.public_key_bytes())
            assert response.reply_to==msg.id and response.request_digest==request_digest(msg)
        assert count()==1
        if app:assert len(app.security.journal.inspect())==1


@pytest.mark.parametrize('server_language',['python','rust'])
@pytest.mark.parametrize('client_language',['python','rust'])
@pytest.mark.parametrize('failure',['name','ca','expired','cn-only','future'])
def test_tls_rejection_has_no_effect_or_reservation(server_language,client_language,failure,certificates,tmp_path,monkeypatch):
    with server(server_language,certificates,monkeypatch,expired=failure=='expired',certificate=failure if failure in ('cn-only','future') else 'valid') as (port,count,app):
        ca=certificates[0];name='wrong.local' if failure=='name' else 'test.local'
        if failure=='ca':
            # A valid unrelated CA, never system trust.
            other_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
            now=datetime.now(timezone.utc);n=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'unrelated')])
            other=(x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(other_key.public_key()).serial_number(8)
                   .not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=1))
                   .add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True).sign(other_key,hashes.SHA256()))
            ca=tmp_path/'other.pem';ca.write_bytes(other.public_bytes(serialization.Encoding.PEM))
        msg=request()
        with pytest.raises((OSError,ValueError,subprocess.CalledProcessError)):
            send(client_language,port,msg,ca,name,tmp_path,monkeypatch)
        assert count()==0
        if app:assert app.security.journal.inspect()==[]
        else:assert count.reservations()==0
        if failure in ('name','ca'):
            assert send(client_language,port,msg,certificates[0],'test.local',tmp_path,monkeypatch).msg_type==MessageType.RESPONSE
            assert count()==1


@pytest.mark.parametrize('language',['python','rust'])
def test_plain_mismatch_and_stalled_handshake_recover(language,certificates,tmp_path,monkeypatch):
    with server(language,certificates,monkeypatch) as (port,count,app):
        with socket.create_connection(('127.0.0.1',port),timeout=4) as conn:
            conn.sendall(b'POST /ordavyn/v3/act HTTP/1.1\r\n\r\n')
            try:assert not conn.recv(256).startswith(b'HTTP/')
            except ConnectionResetError:pass
        with socket.create_connection(('127.0.0.1',port),timeout=4) as conn:
            started=time.monotonic()
            assert conn.recv(256)==b''
            assert time.monotonic()-started<3.8
        assert count()==0
        assert send('python',port,request(),certificates[0],'test.local',tmp_path,monkeypatch).msg_type==MessageType.RESPONSE


def test_python_stop_owns_pending_handshake(certificates,monkeypatch):
    with server('python',certificates,monkeypatch) as (port,count,app):
        entered=threading.Event()
        original=app._handle_connection
        def handling(conn):entered.set();return original(conn)
        monkeypatch.setattr(app,'_handle_connection',handling)
        with socket.create_connection(('127.0.0.1',port),timeout=4):
            assert entered.wait(2)
            assert not app.stop(.01)
            with pytest.raises(RuntimeError):app.resume()
            assert app.stop(4)
        assert count()==0 and app.security.journal.inspect()==[]
        app.resume()


@pytest.mark.parametrize('client_language',['python','rust'])
@pytest.mark.parametrize('change',['unsigned','wrong-key','reply','digest','same-id-new-payload','participant','operation','subject','epoch','payload','type','timestamp','id','version','encoding','signature-alg','key-id','signature','signed-reply','signed-participant','signed-operation','signed-subject','signed-epoch','signed-digest','signed-request','signed-event'])
def test_clients_reject_untrusted_response(client_language,change,tmp_path,monkeypatch):
    msg=request()
    response=(MessageBuilder(SERVICE,CALLER).msg_type(MessageType.RESPONSE).operation_id(msg.operation_id)
              .subject(msg.subject).epoch(msg.epoch).payload({'ok':True}).build())
    response.reply_to=msg.id;response.request_digest=request_digest(msg);response.sign(peer.TEST_SIGNER)
    d=response.to_dict()
    if change=='unsigned':d.update(signature=None,key_id=None,signature_alg=None)
    elif change=='wrong-key':response.sign(peer.KEY);d=response.to_dict()
    elif change=='same-id-new-payload':msg.payload['value']='different';msg.sign(peer.KEY)
    elif change=='reply':d['reply_to']['value']='other'
    elif change=='digest':d['request_digest']='00'*32
    elif change in ['participant','operation','epoch','id']:
        field={'participant':'from','operation':'operation_id'}.get(change,change);d[field]['value']='other'
    elif change=='subject':d['subject']['target_id']['value']='other'
    elif change=='payload':d['payload']={'ok':False}
    elif change=='type':d['type']='error'
    elif change=='timestamp':d['timestamp']['nanos']+=1
    elif change=='version':d['version']=2
    elif change=='encoding':d['encoding']='ordavyn-cbor-v2'
    elif change=='signature-alg':d['signature_alg']=2
    elif change=='key-id':d['key_id']='00'*8
    elif change=='signature':d['signature']='00'*64
    elif change=='signed-digest':
        d['request_digest']='00'*32
        response=Message.from_dict(d);response.sign(peer.TEST_SIGNER);d=response.to_dict()
    elif change in ('signed-request','signed-event'):
        # These are valid signed envelopes, but invalid types for a response.
        d.update(type=change.removeprefix('signed-'),reply_to=None,request_digest=None)
        response=Message.from_dict(d);response.sign(peer.TEST_SIGNER);d=response.to_dict()
    elif change.startswith('signed-'):
        field={'signed-reply':'reply_to','signed-participant':'from','signed-operation':'operation_id','signed-subject':'subject','signed-epoch':'epoch'}[change]
        if field=='subject':d[field]['target_id']['value']='other'
        else:d[field]['value']='other'
        response=Message.from_dict(d);response.sign(peer.TEST_SIGNER);d=response.to_dict()
    body=json.dumps(d).encode()
    listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen();listener.settimeout(5)
    port=listener.getsockname()[1]
    def serve():
        with listener:
            conn,_=listener.accept()
            with conn:
                conn.recv(65536)
                conn.sendall(f'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nx-ordavyn-version: 3\r\nContent-Length: {len(body)}\r\n\r\n'.encode()+body)
    worker=threading.Thread(target=serve);worker.start()
    try:
        with pytest.raises((ValueError,subprocess.CalledProcessError)):
            if client_language=='python':
                OrdavynClient(port=port,response_key=peer.TEST_SIGNER.public_key_bytes(),participant=SERVICE).send('/act',msg)
            else:
                path=tmp_path/'message.json';path.write_text(msg.to_json());peer.call('client',port,path)
    finally:worker.join(6);assert not worker.is_alive()


def test_missing_pin_before_connect(monkeypatch):
    monkeypatch.setattr(socket,'create_connection',lambda *a,**k:pytest.fail('network attempted without pin'))
    with pytest.raises(ValueError):OrdavynClient().send('/act',request())
    with pytest.raises(ValueError):Ordavyn(signer=None)


def test_rust_tls_stop_and_cancel_keep_handler_owned(certificates,monkeypatch):
    ca,(cert,key),_=certificates[:3]
    for name,value in [('CERT',cert),('KEY',key),('CA',ca)]:monkeypatch.setenv('ORDAVYN_TLS_'+name,str(value))
    assert peer.call('tls-lifecycle')=='tls lifecycle passed'


@pytest.mark.parametrize('damaged', ['empty-cert','malformed-cert','empty-key','malformed-key','mismatched-key'])
def test_rust_pem_parser_rejects_invalid_inputs(damaged,certificates,tmp_path,monkeypatch):
    ca,(cert,key),_=certificates[:3]
    bad_cert=tmp_path/'bad-cert.pem';bad_key=tmp_path/'bad-key.pem'
    bad_cert.write_bytes(b'' if damaged=='empty-cert' else b'-----BEGIN CERTIFICATE-----\nnot-base64\n-----END CERTIFICATE-----\n')
    if damaged=='mismatched-key':
        _,other_key=certificates[3]('ip')
        bad_key.write_bytes(other_key.read_bytes())
    else:
        bad_key.write_bytes(b'' if damaged=='empty-key' else b'-----BEGIN PRIVATE KEY-----\nnot-base64\n-----END PRIVATE KEY-----\n')
    monkeypatch.setenv('ORDAVYN_TLS_CA',str(ca))
    monkeypatch.setenv('ORDAVYN_TLS_CERT',str(bad_cert if 'cert' in damaged else cert))
    monkeypatch.setenv('ORDAVYN_TLS_KEY',str(bad_key if 'key' in damaged else key))
    with pytest.raises(subprocess.CalledProcessError):
        peer.call('tls-lifecycle')


def test_python_tls_stop_waits_for_admitted_handler(certificates,monkeypatch,tmp_path):
    with server('python',certificates,monkeypatch) as (port,count,app):
        entered=threading.Event();release=threading.Event()
        app._handlers.clear()
        @app.expose('/act')
        def act(value):entered.set();assert release.wait(4);return {'ok':True}
        result=[]
        worker=threading.Thread(target=lambda:result.append(send('python',port,request(),certificates[0],'test.local',tmp_path,monkeypatch)))
        worker.start();assert entered.wait(2)
        try:
            assert not app.stop(0)
            with pytest.raises(RuntimeError):app.resume()
        finally:release.set();worker.join(4)
        assert not worker.is_alive() and result[0].msg_type==MessageType.RESPONSE
        assert app.stop(4)


@pytest.mark.parametrize('server_language',['python','rust'])
@pytest.mark.parametrize('client_language',['python','rust'])
def test_valid_tls_does_not_replace_protocol_pin(server_language,client_language,certificates,tmp_path,monkeypatch):
    with server(server_language,certificates,monkeypatch) as (port,count,app):
        msg=request()
        with pytest.raises((ValueError,subprocess.CalledProcessError)):
            if client_language=='python':
                OrdavynClient(port=port,response_key=peer.KEY.public_key_bytes(),participant=SERVICE,tls=ClientTLS(certificates[0].read_text(),'test.local')).send('/act',msg)
            else:
                monkeypatch.setenv('ORDAVYN_WRONG_PIN','1')
                send('rust',port,msg,certificates[0],'test.local',tmp_path,monkeypatch)
        assert count()==1  # A response rejection cannot undo an admitted effect.


@pytest.mark.parametrize('language',['python','rust'])
def test_tls12_rejected_before_reservation(language,certificates,tmp_path,monkeypatch):
    import ssl
    with server(language,certificates,monkeypatch) as (port,count,app):
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cadata=certificates[0].read_text())
        context.minimum_version=context.maximum_version=ssl.TLSVersion.TLSv1_2
        context.set_alpn_protocols(['http/1.1'])
        with socket.create_connection(('127.0.0.1',port),timeout=4) as conn:
            with pytest.raises(ssl.SSLError):context.wrap_socket(conn,server_hostname='test.local')
        assert count()==0
        if app:assert app.security.journal.inspect()==[]
        else:assert count.reservations()==0
        assert send('python',port,request(),certificates[0],'test.local',tmp_path,monkeypatch).msg_type==MessageType.RESPONSE


def test_insecure_context_injection_rejected(certificates):
    import ssl
    with pytest.raises(ValueError):OrdavynClient(tls=ssl._create_unverified_context())
    with pytest.raises(ValueError):Ordavyn(signer=peer.TEST_SIGNER,tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER))
    context=ClientTLS(certificates[0].read_text(),'test.local').context()
    assert context.verify_mode==ssl.CERT_REQUIRED and context.check_hostname
    assert not context.hostname_checks_common_name and len(context.get_ca_certs())==1


@pytest.mark.parametrize('server_language',['python','rust'])
@pytest.mark.parametrize('client_language',['python','rust'])
@pytest.mark.parametrize('failure',['fail-after-effect','oversize'])
def test_tls_signed_errors_after_effect_retain_barrier(server_language,client_language,failure,certificates,tmp_path,monkeypatch):
    with server(server_language,certificates,monkeypatch) as (port,count,app):
        msg=request();msg.payload['value']=failure;msg.sign(peer.KEY)
        for _ in range(2):
            response=send(client_language,port,msg,certificates[0],'test.local',tmp_path,monkeypatch)
            assert response.msg_type==MessageType.ERROR
            assert response.verify_signature(peer.TEST_SIGNER.public_key_bytes())
            assert response.request_digest==request_digest(msg)
        assert count()==1
        if app:assert app.security.journal.inspect()[0]['state']=='outcome_unknown'
        else:assert count.states()==['outcome_unknown']


@pytest.mark.parametrize('server_language',['python','rust'])
@pytest.mark.parametrize('client_language',['python','rust'])
def test_ip_san_is_verified(server_language,client_language,certificates,tmp_path,monkeypatch):
    with server(server_language,certificates,monkeypatch,certificate='ip') as (port,count,app):
        msg=request()
        with pytest.raises((OSError,ValueError,subprocess.CalledProcessError)):
            send(client_language,port,msg,certificates[0],'127.0.0.2',tmp_path,monkeypatch)
        assert count()==0
        if app:assert app.security.journal.inspect()==[]
        else:assert count.states()==[]
        response=send(client_language,port,msg,certificates[0],'127.0.0.1',tmp_path,monkeypatch)
        assert response.msg_type==MessageType.RESPONSE and response.request_digest==request_digest(msg)
        assert count()==1


def raw_tls_context(certificates, *, server_side, alpn):
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server_side else ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version=context.maximum_version=ssl.TLSVersion.TLSv1_3
    if server_side:
        cert,key=certificates[1];context.load_cert_chain(str(cert),str(key))
        context.num_tickets=0  # Avoid post-handshake ticket writes racing the rejecting client close.
    else:
        context.load_verify_locations(cadata=certificates[0].read_text())
        context.hostname_checks_common_name=False
    if alpn:context.set_alpn_protocols(alpn)
    return context


@pytest.mark.parametrize('client_language',['python','rust'])
@pytest.mark.parametrize('alpn',[[],['h2']],ids=['omitted','incompatible'])
def test_clients_reject_post_handshake_alpn_without_http(client_language,alpn,certificates,tmp_path,monkeypatch):
    context=raw_tls_context(certificates,server_side=True,alpn=alpn)
    listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen();listener.settimeout(5)
    port=listener.getsockname()[1]
    observed={};errors=[]
    def serve_raw():
        try:
            with listener:
                conn,_=listener.accept()
                with conn:
                    conn.settimeout(5)
                    with context.wrap_socket(conn,server_side=True) as stream:
                        observed['version']=stream.version()
                        observed['alpn']=stream.selected_alpn_protocol()
                        try:observed['http']=stream.recv(65536)
                        except (ssl.SSLEOFError,ConnectionResetError,BrokenPipeError):observed['http']=b''
        except Exception as error:errors.append(error)
    worker=threading.Thread(target=serve_raw);worker.start()
    try:
        with pytest.raises((OSError,ValueError,subprocess.CalledProcessError)):
            send(client_language,port,request(),certificates[0],'test.local',tmp_path,monkeypatch)
    finally:worker.join(6)
    assert not worker.is_alive() and not errors
    assert observed=={'version':'TLSv1.3','alpn':None,'http':b''}


@pytest.mark.parametrize('server_language',['python','rust'])
@pytest.mark.parametrize('alpn',[[],['h2']],ids=['omitted','incompatible'])
def test_servers_reject_alpn_without_admission_and_recover(server_language,alpn,certificates,tmp_path,monkeypatch):
    with server(server_language,certificates,monkeypatch) as (port,count,app):
        context=raw_tls_context(certificates,server_side=False,alpn=alpn)
        msg=request();body=msg.to_json().encode()
        http=(f'POST /ordavyn/v3/act HTTP/1.1\r\nHost: test.local\r\nContent-Type: application/json\r\nx-ordavyn-version: 3\r\nContent-Length: {len(body)}\r\n\r\n').encode()+body
        handshake=False
        with socket.create_connection(('127.0.0.1',port),timeout=4) as conn:
            try:
                with context.wrap_socket(conn,server_hostname='test.local') as stream:
                    handshake=True
                    assert stream.version()=='TLSv1.3' and stream.selected_alpn_protocol() is None
                    try:
                        stream.sendall(http)
                        assert stream.recv(65536)==b''
                    except (ssl.SSLError,ConnectionResetError,BrokenPipeError):pass
            except ssl.SSLError:
                # Rustls may reject an explicitly incompatible ALPN during handshake.
                assert alpn==['h2']
        if not alpn:assert handshake  # Exercise the SDK's post-handshake ALPN guard.
        assert count()==0
        if app:assert app.security.journal.inspect()==[]
        else:assert count.states()==[]
        response=send('python',port,msg,certificates[0],'test.local',tmp_path,monkeypatch)
        assert response.msg_type==MessageType.RESPONSE and count()==1


@pytest.mark.parametrize('client_language',['python','rust'])
def test_client_handshake_uses_total_three_second_budget(client_language,certificates,tmp_path,monkeypatch):
    listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen();listener.settimeout(5)
    port=listener.getsockname()[1];release=threading.Event();observed=[];errors=[]
    def stall():
        try:
            with listener:
                conn,_=listener.accept()
                with conn:
                    conn.settimeout(5)
                    observed.append(conn.recv(65536))
                    release.wait(6)  # Never answer ClientHello, even with a TLS alert.
        except Exception as error:errors.append(error)
    worker=threading.Thread(target=stall);worker.start()
    started=time.monotonic()
    try:
        with pytest.raises((OSError,ValueError,subprocess.CalledProcessError)):
            send(client_language,port,request(),certificates[0],'test.local',tmp_path,monkeypatch)
        elapsed=time.monotonic()-started
    finally:release.set();worker.join(6)
    assert not worker.is_alive() and not errors
    assert observed and observed[0].startswith(b'\x16\x03')
    assert 2.6<=elapsed<4.8, f'handshake consumed {elapsed:.3f}s instead of the shared 3s budget'


@pytest.mark.parametrize('server_language',['python','rust'])
@pytest.mark.parametrize('client_language',['python','rust'])
@pytest.mark.parametrize('failure',['fail-after-effect','oversize'])
def test_tls_error_barrier_survives_sqlite_reopen(server_language,client_language,failure,certificates,tmp_path,monkeypatch):
    path=tmp_path/'durable.sqlite';msg=request();msg.payload['value']=failure;msg.sign(peer.KEY)
    def states(app,count):
        return [entry['state'] for entry in app.security.journal.inspect()] if app else count.states()
    with server(server_language,certificates,monkeypatch,journal_path=path) as (port,count,app):
        response=send(client_language,port,msg,certificates[0],'test.local',tmp_path,monkeypatch)
        assert response.msg_type==MessageType.ERROR
        assert response.verify_signature(peer.TEST_SIGNER.public_key_bytes())
        assert response.request_digest==request_digest(msg) and response.reply_to==msg.id
        assert count()==1 and states(app,count)==['outcome_unknown']
    # A new server process/object opens the same file without clearing its records.
    with server(server_language,certificates,monkeypatch,journal_path=path,reopen=True) as (port,count,app):
        assert states(app,count)==['outcome_unknown']
        response=send(client_language,port,msg,certificates[0],'test.local',tmp_path,monkeypatch)
        assert response.msg_type==MessageType.ERROR and 'replay' in response.payload['error']
        assert response.verify_signature(peer.TEST_SIGNER.public_key_bytes())
        assert response.request_digest==request_digest(msg) and response.reply_to==msg.id
        assert count()==0 and states(app,count)==['outcome_unknown']
