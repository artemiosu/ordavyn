"""Frozen cross-language v2 vectors and strict codec rejection matrix."""

from ordavyn import Ed25519Keypair, Identifier
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
TEST_SIGNER = Ed25519Keypair(Ed25519PrivateKey.from_private_bytes(bytes([99])*32))
import copy
import json
import os
from pathlib import Path
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ordavyn.aim import Identifier
from ordavyn.crypto import Ed25519Keypair
from ordavyn.message import Message
from ordavyn.wire import strict_json

FIXTURE = Path(os.environ.get('ORDAVYN_WIRE_FIXTURE', Path(__file__).resolve().parents[2] / 'tests/fixtures/wire-v3.json'))
DATA = json.loads(FIXTURE.read_text())
KEY = Ed25519Keypair(Ed25519PrivateKey.from_private_bytes(bytes.fromhex(DATA['seed_hex'])))

@pytest.mark.parametrize('vector', DATA['vectors'], ids=lambda v:v['name'])
def test_frozen_vectors(vector):
    msg = Message.from_dict(vector['message'])
    assert msg._signable_bytes().hex() == vector['signable_hex']
    assert msg.verify_signature(bytes.fromhex(DATA['public_key_hex']))
    msg.sign(KEY)
    assert msg.signature == vector['signature_hex']
    decoded = Message.from_dict(strict_json(msg.to_json()))
    assert decoded._signable_bytes() == msg._signable_bytes()

@pytest.mark.parametrize('case', DATA['invalid_json'], ids=lambda c:c['name'])
def test_invalid_json(case):
    with pytest.raises((ValueError, UnicodeError)):
        Message.from_dict(strict_json(case['json']))

@pytest.mark.parametrize('field', list(DATA['vectors'][0]['message']))
def test_all_fields_required(field):
    data = copy.deepcopy(DATA['vectors'][0]['message']); del data[field]
    with pytest.raises(ValueError): Message.from_dict(data)

@pytest.mark.parametrize('mutation', ['alias','unknown','missing-version','missing-closure','aim-unknown','bool-version','float-time','old-version','old-encoding','uppercase','partial-null','utf8-limit'])
def test_invalid_envelope(mutation):
    d = copy.deepcopy(DATA['vectors'][0]['message'])
    if mutation=='alias': d['msg_type']=d.pop('type')
    elif mutation=='unknown': d['extra']=None
    elif mutation=='missing-version': del d['id']['version']
    elif mutation=='missing-closure': del d['subject']['closure_version']
    elif mutation=='aim-unknown': d['subject']['target_id']['extra']=0
    elif mutation=='bool-version': d['id']['version']=True
    elif mutation=='float-time': d['timestamp']['nanos']=1.0
    elif mutation=='old-version': d['version']=1
    elif mutation=='old-encoding': d['encoding']='json'
    elif mutation=='uppercase': d['signature']=d['signature'].upper()
    elif mutation=='partial-null': d['signature']=None
    elif mutation=='utf8-limit': d['id']['value']='я'*129
    with pytest.raises(ValueError): Message.from_dict(d)

def test_depth_and_direct_api():
    for depth in (31,32):
        d=copy.deepcopy(DATA['vectors'][0]['message']); v=0
        for _ in range(depth-2): v=[v]
        d['payload']=v
        Message.from_dict(d)
    d['payload']=[v]
    with pytest.raises(ValueError): Message.from_dict(d)
    msg=Message.from_dict(DATA['vectors'][0]['message'])
    for payload in ({'bad':2**64}, {'bad':{1:'x'}}, {'bad':float('inf')}, {'bad':(1,2)}):
        msg.payload=payload
        with pytest.raises(ValueError): msg.sign(KEY)
        assert not msg.verify_signature(KEY.public_key_bytes())
    msg.payload={};msg.id=Identifier('message','я'*129)
    with pytest.raises(ValueError): msg.sign(KEY)


def test_model_budget_independent_of_json_and_exact_boundary():
    from cbor2._encoder import dumps
    from ordavyn import Ordavyn
    d=copy.deepcopy(DATA['vectors'][0]['message'])
    d['payload']={'action':'act','value':'\n'*40000}
    msg=Message.from_dict(d);msg.sign(KEY)
    assert msg.verify_signature(KEY.public_key_bytes())
    with pytest.raises(ValueError): msg.to_json()
    server=Ordavyn(participant=msg.to_id, signer=TEST_SIGNER).trust(KEY.public_key_bytes(),msg.from_id,['act'])
    effects=[]
    @server.expose('/act')
    def act(value): effects.append(value);return {'ok':True}
    assert server._handle_request(msg).msg_type=='response'
    assert len(effects)==1
    d['payload']['value']='x'*64000
    d['payload']['value']+='x'*(65536-len(dumps(d,canonical=True)))
    assert len(dumps(d,canonical=True))==65536
    msg=Message.from_dict(d);msg.sign(KEY)
    assert msg.verify_signature(KEY.public_key_bytes())
    msg.payload['value']+='x'
    with pytest.raises(ValueError): msg.to_dict()
    with pytest.raises(ValueError): msg.sign(KEY)
    assert not msg.verify_signature(KEY.public_key_bytes())
    with pytest.raises(ValueError): server._handle_request(msg)
    assert len(effects)==1


def test_sign_budget_failure_preserves_unsigned_original():
    from cbor2._encoder import dumps
    d=copy.deepcopy(DATA['vectors'][0]['message'])
    d.update(signature=None,signature_alg=None,key_id=None)
    d['payload']={'value':'x'*64000}
    d['payload']['value']+='x'*(65480-len(dumps(d,canonical=True)))
    msg=Message.from_dict(d)
    before=copy.deepcopy(msg)
    candidate=copy.deepcopy(msg)
    candidate.signature_alg=1;candidate.key_id=KEY.key_id()
    candidate._signable_bytes()  # Metadata fits; adding the signature crosses the budget.
    with pytest.raises(ValueError,match='model exceeds'): msg.sign(KEY)
    assert msg==before


def test_fixed_request_digest_and_signed_response_vectors():
    from ordavyn.wire import request_digest
    request=Message.from_dict(DATA['binding_request'])
    assert request_digest(request)==DATA['request_digest']
    for vector in DATA['vectors'][-2:]:
        response=Message.from_dict(vector['message'])
        assert response.reply_to==request.id
        assert response.request_digest==DATA['request_digest']
