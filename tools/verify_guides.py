#!/usr/bin/env python3
"""Execute documented snippets with disposable journals and TLS test certificates."""
import argparse
import importlib.util
import os
from pathlib import Path
import re
import subprocess
import tempfile


def guides(root):
    root=Path(root)
    with tempfile.TemporaryDirectory(prefix='ordavyn-guide-') as temp:
        temp=Path(temp)
        for name in ['docs/LOCAL-JOURNAL.md','docs/LOCAL-LIFECYCLE.md','implementation/TUTORIAL.md']:
            text=(root/name).read_text().replace('/trusted/local/service.sqlite',str(temp/'python.sqlite'))
            for snippet in re.findall(r'```python\n(.*?)```',text,re.S):
                ns={};exec(snippet,ns)
                if 'journal' in ns:ns['journal'].close()
            print(name,'Python passed')
        journal=re.search(r'```rust\n(.*?)```',(root/'docs/LOCAL-JOURNAL.md').read_text(),re.S)[1].replace('/trusted/local/service.sqlite',str(temp/'rust.sqlite'))
        journal='\n'.join(x[2:] if x.startswith('# ') else x for x in journal.splitlines())
        lifecycle=re.search(r'```rust\n(.*?)```',(root/'docs/LOCAL-LIFECYCLE.md').read_text(),re.S)[1]
        setup='let old_key=Ed25519Keypair::generate();let new_key=Ed25519Keypair::generate();let server=OrdavynServer::new().with_signer(Ed25519Keypair::generate());server.trust(old_key.public_key(), Identifier::new("participant","caller"), &["status"])?;'
        code=journal+'\n#[tokio::main(flavor="current_thread")] async fn main()->ordavyn_core::Result<()>{example()?;'+setup+lifecycle+'\nOk(())}'
        def rust(code):
            path=root/'implementation/ordavyn-core/examples/release_documentation.rs'
            with path.open('x') as f:f.write(code)
            try:subprocess.run(['cargo','+1.98.1','run','--locked','--offline','--example','release_documentation'],cwd=root/'implementation',check=True)
            finally:path.unlink()
        rust(code)
        spec=importlib.util.spec_from_file_location('exchange',root/'implementation/tests/test_authenticated_exchange.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        ca,(cert,key),_=module.certificates.__wrapped__(temp)[:3]
        doc=(root/'docs/LOCAL-WIRE-V3.md').read_text()
        for old,new in [('/tmp/test-chain.pem',str(cert)),('/tmp/test-key.pem',str(key)),('/tmp/test-ca.pem',str(ca))]:doc=doc.replace(old,new)
        exec(re.search(r'```python\n(.*?)```',doc,re.S)[1],{})
        snippet=re.search(r'```rust\n(.*?)```',doc,re.S)[1]
        snippet='\n'.join(x[2:] if x.startswith('# ') else x for x in snippet.splitlines())
        rust(snippet+'\nfn main(){configured().unwrap();}\n')
        print('Journal, lifecycle and TLS Rust guide fragments passed')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',required=True);a=p.parse_args();guides(a.root)
