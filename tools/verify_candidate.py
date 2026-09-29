#!/usr/bin/env python3
"""Run local verification from an unpacked, hash-checked source candidate."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
sys.dont_write_bytecode = True
import tempfile
from release_candidate import sha
from verify_packages import verify


def run_verification(root,manifest_path,output,wheelhouse):
    root=Path(root).resolve(); output=Path(output).resolve();wheelhouse=Path(wheelhouse).resolve()
    output.mkdir(parents=True,exist_ok=False)
    manifest=json.loads(Path(manifest_path).read_text())
    actual={str(p.relative_to(root)) for p in root.rglob('*') if p.is_file() or p.is_symlink()}
    if actual!={e['path'] for e in manifest['files']}:raise ValueError('unpacked source member list differs from manifest')
    for entry in manifest['files']:
        p=root/entry['path']
        if not p.is_file() or p.is_symlink() or sha(p.read_bytes())!=entry['sha256'] or p.stat().st_mode & 0o777 != int(entry['mode'],8):raise ValueError('source differs from manifest')
    if platform.system()!='Linux' or platform.machine()!='x86_64' or sys.version_info[:3]!=(3,13,15):raise ValueError('verification requires CPython 3.13.15, Linux x86_64')
    env={k:v for k,v in os.environ.items() if k not in ('PYTHONPATH','CARGO_TARGET_DIR')}
    env.update({'RUSTUP_TOOLCHAIN':'1.98.1','CARGO_NET_OFFLINE':'true','PIP_NO_INDEX':'1','PIP_FIND_LINKS':str(wheelhouse),'PIP_DISABLE_PIP_VERSION_CHECK':'1','PYTHONDONTWRITEBYTECODE':'1'})
    commands=[]
    def run(args,cwd=output):
        with (output/'verification.log').open('a') as log:
            log.write('\nCOMMAND '+json.dumps([str(x) for x in args])+'\n');log.flush()
            subprocess.run([str(x) for x in args],cwd=cwd,env=env,stdout=log,stderr=subprocess.STDOUT,check=True,timeout=900)
        commands.append([str(x) for x in args])
    run(['cargo','+1.98.1','test','--locked','--offline'],root/'implementation')
    run(['cargo','+1.98.1','build','--release','--locked','--offline'],root/'implementation')
    run(['cargo','+1.98.1','build','--examples','--locked','--offline'],root/'implementation')
    run([sys.executable,'-m','unittest','discover','-s',root/'tools/tests','-v'])
    # Build a disposable copy selected only from manifest paths, without stale egg-info.
    build_source=output/'sdk-build';build_source.mkdir()
    prefix='implementation/python-sdk/'
    for entry in manifest['files']:
        if entry['path'].startswith(prefix):
            dst=build_source/entry['path'][len(prefix):];dst.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(root/entry['path'],dst)
    packages=output/'packages'
    run([sys.executable,'-m','build','--no-isolation','--outdir',packages,build_source])
    wheel=packages/'ordavyn-0.1.0-py3-none-any.whl';sdist=packages/'ordavyn-0.1.0.tar.gz'
    inventories=verify(root,wheel,sdist)
    (output/'package-inventory.json').write_text(json.dumps(inventories,indent=2)+'\n')
    readme=(root/'implementation/python-sdk/README.md').read_text()
    example=output/'readme_example.py';example.write_text(readme.split('```python\n',1)[1].split('```',1)[0])
    for kind,artifact in (('wheel',wheel),('sdist',sdist)):
        venv=output/kind
        run([sys.executable,'-m','venv',venv])
        python=venv/'bin/python'
        run([python,'-m','pip','install','--require-hashes','-r',root/'release/verification-requirements.txt'])
        run([python,'-m','pip','install','--no-deps','--no-build-isolation',artifact])
        run([python,'-m','pip','check'])
        run([python,'-c',"import ordavyn; assert 'site-packages' in ordavyn.__file__; print(ordavyn.__file__)"])
        run([python,root/'implementation/tests/test_conformance.py'])
        for path in ('implementation/demo/demo_ecommerce.py','implementation/demo/demo_multi.py'):
            run([python,root/path])
        run([python,example])
        run([python,root/'tools/verify_guides.py','--root',root])
    for entry in manifest['files']:
        if sha((root/entry['path']).read_bytes())!=entry['sha256']:raise ValueError('verification mutated source')
    result={'status':'TESTS_PASS','publication':'BLOCKED','source_commit':manifest['commit'],'source_sha256':manifest['source_sha256'],'python':sys.version,'platform':platform.platform(),'commands':commands,'artifacts':inventories,'wheel_bit_reproducibility':'NOT_CLAIMED'}
    (output/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',required=True);p.add_argument('--manifest',required=True);p.add_argument('--output',required=True);p.add_argument('--wheelhouse',required=True);a=p.parse_args();run_verification(a.root,a.manifest,a.output,a.wheelhouse)
