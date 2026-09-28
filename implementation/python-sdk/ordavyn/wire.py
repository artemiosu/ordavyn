"""Experimental v2 JSON transport and deterministic CBOR signing codec."""
import json
import math
import re
# cbor2 5.x C accelerator emits a non-shortest float for 65504.0.
# Its Python canonical encoder preserves the RFC8949 shortest-float rule.
from cbor2._encoder import dumps as canonical_cbor

ENCODING = 'ordavyn-cbor-v2'
DOMAIN = b'ordavyn:v2:message\0'
MAX_BODY = 65536


def validate_tree(value, depth=1):
    if depth > 32:
        raise ValueError('tree depth exceeds 32')
    if value is None or type(value) is bool:
        return
    if type(value) is str:
        value.encode('utf-8', errors='strict')
    elif type(value) is int:
        if not -(2**63) <= value < 2**64:
            raise ValueError('integer out of range')
    elif type(value) is float:
        if not math.isfinite(value):
            raise ValueError('nonfinite number')
    elif type(value) is list:
        for item in value:
            validate_tree(item, depth + 1)
    elif type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                raise ValueError('object key must be a string')
            key.encode('utf-8', errors='strict')
            validate_tree(item, depth + 1)
    else:
        raise ValueError('unsupported JSON type')


def json_bytes(value):
    validate_tree(value)
    result = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(',', ':'), sort_keys=True).encode('utf-8')
    if len(result) > MAX_BODY:
        raise ValueError('body exceeds 64KiB')
    return result


def strict_json(data):
    if isinstance(data, bytes):
        data = data.decode('utf-8', errors='strict')
    if len(data.encode('utf-8')) > MAX_BODY:
        raise ValueError('body exceeds 64KiB')
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate JSON key')
            result[key] = value
        return result
    def integer(token):
        if token == '-0':
            raise ValueError('negative integer zero')
        value = int(token)
        if not -(2**63) <= value < 2**64:
            raise ValueError('integer out of range')
        return value
    def constant(_):
        raise ValueError('nonfinite number')
    value = json.loads(data, object_pairs_hook=pairs, parse_int=integer, parse_constant=constant)
    validate_tree(value)
    return value


def validate_envelope(d, signing=False):
    fields = {'version', 'type', 'id', 'operation_id', 'subject', 'from', 'to', 'epoch', 'payload', 'timestamp', 'encoding', 'signature_alg', 'key_id', 'signature'}
    if type(d) is not dict or set(d) != fields:
        raise ValueError('invalid envelope fields')
    validate_tree(d)
    if len(canonical_cbor(d, canonical=True)) > MAX_BODY:
        raise ValueError("model exceeds 64KiB")
    if type(d['version']) is not int or d['version'] != 2 or d['encoding'] != ENCODING or d['type'] not in ('request', 'response', 'event', 'error'):
        raise ValueError('invalid envelope metadata')
    from .aim import Identifier, Reference, Instant
    for name, ns in [('id', 'message'), ('operation_id', 'logical-operation'), ('from', 'participant'), ('to', 'participant'), ('epoch', 'epoch')]:
        if Identifier.from_dict(d[name]).namespace != ns:
            raise ValueError('invalid envelope namespace')
    Reference.from_dict(d['subject'])
    Instant.from_dict(d['timestamp'])
    alg, kid, sig = d['signature_alg'], d['key_id'], d['signature']
    if alg is None and kid is None and sig is None:
        return
    if type(alg) is not int or alg != 1 or type(kid) is not str or re.fullmatch('[0-9a-f]{16}', kid) is None:
        raise ValueError('invalid signing metadata')
    if signing and sig is None:
        return
    if type(sig) is not str or re.fullmatch('[0-9a-f]{128}', sig) is None:
        raise ValueError('invalid signature')


def signable_bytes(envelope):
    validate_envelope(envelope, signing=True)
    value = dict(envelope)
    del value['signature']
    return DOMAIN + canonical_cbor(value, canonical=True)
