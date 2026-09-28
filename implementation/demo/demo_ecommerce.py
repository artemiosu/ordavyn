"""Local wire-v2 simulated order; no real purchases. Run after installing the SDK."""
from ordavyn import Ordavyn, Identifier, MessageBuilder, MessageType, Ed25519Keypair


def main():
    caller, shop = Identifier('participant', 'caller'), Identifier('participant', 'shop')
    key = Ed25519Keypair.generate()
    bridge = Ordavyn(port=0, participant=shop)
    bridge.trust(key.public_key_bytes(), caller, ['buy'])
    orders = []
    @bridge.expose('/buy', consequential=True)
    def buy(product_id):
        orders.append(product_id)
        return {'simulated_order': len(orders)}
    request = MessageBuilder(caller, shop).payload({'action': 'buy', 'product_id': 'sample'}).build()
    request.sign(key)
    bridge.start()
    try:
        client = bridge.client(key)
        result = client.send('/buy', request)
        replay = client.send('/buy', request)
        assert result.msg_type == MessageType.RESPONSE
        assert replay.msg_type == MessageType.ERROR and len(orders) == 1
        print('Ordavyn simulated order: one effect; replay rejected')
    finally:
        bridge.stop()

if __name__ == '__main__': main()
