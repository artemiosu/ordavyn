"""Role-neutral local wire-v3 exchange between two services; no real operations."""

from ordavyn import Ordavyn, Identifier, MessageBuilder, MessageType, Ed25519Keypair


def main():
    left, right = Identifier('participant', 'left'), Identifier('participant', 'right')
    left_key, right_key = Ed25519Keypair.generate(), Ed25519Keypair.generate()
    first, second = Ordavyn(port=0, participant=left, signer=Ed25519Keypair.generate()), Ordavyn(port=0, participant=right, signer=Ed25519Keypair.generate())
    first.trust(right_key.public_key_bytes(), right, ['status'])
    second.trust(left_key.public_key_bytes(), left, ['status'])
    @first.expose('/status')
    def left_status(): return {'service': 'left'}
    @second.expose('/status')
    def right_status(): return {'service': 'right'}
    first.start(); second.start()
    try:
        a = second.client(left_key).send('/status', MessageBuilder(left,right).payload({'action':'status'}).build())
        b = first.client(right_key).send('/status', MessageBuilder(right,left).payload({'action':'status'}).build())
        assert a.msg_type == b.msg_type == MessageType.RESPONSE
        assert a.payload == {'service':'right'} and b.payload == {'service':'left'}
        print('Ordavyn two-way service exchange: both authorized requests succeeded')
    finally:
        first.stop(); second.stop()

if __name__ == '__main__': main()
