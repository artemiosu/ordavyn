"""Behavioral prototype checks, not certification of a complete protocol."""
import pathlib
import subprocess
import sys

UNSUPPORTED = ('delegation', 'negotiation', 'post-quantum cryptography', 'exactly-once external effects', 'streaming transport', 'HTTP/2 streams and concurrent-stream limits', 'CBOR transport decoding', 'CBOR decoder resource-limit enforcement')

def main():
    root = pathlib.Path(__file__).resolve().parents[1]
    print('Ordavyn local prototype behavioral suite', flush=True)
    for capability in UNSUPPORTED:
        print(f'UNSUPPORTED: {capability}', flush=True)
    result = subprocess.call([sys.executable, '-m', 'pytest', str(root/'python-sdk/tests'), '-q'])
    if result:
        return result
    result = subprocess.call([sys.executable, '-m', 'pytest', str(root/'tests/test_journal_recovery.py'), str(root/'tests/test_authenticated_exchange.py'), '-q'])
    if result:
        return result
    return subprocess.call([sys.executable, str(root/'tests/test_interop.py')])

if __name__ == '__main__':
    raise SystemExit(main())
