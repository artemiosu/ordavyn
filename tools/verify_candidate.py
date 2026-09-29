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
from release_candidate import sha, git, verify_source, archive_entries, Rejected
from verify_packages import verify
from audit_dependencies import locked_wheels


def bind_source(root, manifest, archive, repo, commit):
    if not archive or not repo or not commit:
        raise Rejected('trusted repository, expected commit and source archive required')
    resolved=git(repo,'rev-parse','--verify',commit+'^{commit}').decode().strip()
    if manifest.get('commit')!=resolved: raise Rejected('unexpected source commit')
    verify_source(archive,manifest)
    policy=json.loads(git(repo,'show',resolved+':release/files.json'))['files']
    tree={}
    for row in git(repo,'ls-tree','-rz','--full-tree',resolved).split(b'\0'):
        if not row: continue
        metadata,name=row.split(b'\t',1);mode,kind,oid=metadata.decode().split()
        tree[name.decode()]=(mode,kind,oid)
    if set(tree)!=set(policy): raise Rejected('snapshot classification mismatch')
    selected={n for n,r in policy.items() if r['action']=='include'}
    if selected!={e['path'] for e in manifest['files']}: raise Rejected('snapshot member mismatch')
    for entry in manifest['files']:
        mode,kind,oid=tree[entry['path']]
        data=git(repo,'cat-file','blob',oid)
        if kind!='blob' or mode not in ('100644','100755') or sha(data)!=entry['sha256'] or len(data)!=entry['size'] or int(mode,8)&0o777!=int(entry['mode'],8):
            raise Rejected('source is not the selected Git blob')
    return resolved,sha(Path(archive).read_bytes())


def controlled_environment(output,wheelhouse):
    # Cache data is reused, but no host Cargo configuration or user HOME is read.
    host=Path.home();home=output/'home';home.mkdir()
    cargo=output/'cargo-home';cargo.mkdir()
    for name in ('registry','git'):
        source=host/'.cargo'/name
        if source.exists(): (cargo/name).symlink_to(source,target_is_directory=True)
    env={'PATH':str(host/'.cargo/bin')+':/usr/local/bin:/usr/bin:/bin','HOME':str(home),
         'CARGO_HOME':str(cargo),'RUSTUP_HOME':str(host/'.rustup'),'RUSTUP_TOOLCHAIN':'1.98.1',
         'CARGO_NET_OFFLINE':'true','PIP_CONFIG_FILE':os.devnull,'PIP_NO_INDEX':'1',
         'PIP_FIND_LINKS':str(wheelhouse),'PIP_DISABLE_PIP_VERSION_CHECK':'1',
         'PYTHONDONTWRITEBYTECODE':'1','PYTHONNOUSERSITE':'1','PYTEST_DISABLE_PLUGIN_AUTOLOAD':'1',
         'LANG':'C.UTF-8','LC_ALL':'C.UTF-8'}
    return env


def environment_inventory(env):
    import ssl,sqlite3,_ssl,_sqlite3
    result={'hermetic':False,'settings':env,'python':sys.version,'ssl':ssl.OPENSSL_VERSION,
            'sqlite':sqlite3.sqlite_version,'platform':platform.platform(),'binaries':{}}
    result['runtime_extensions']={module.__name__:{'path':module.__file__,'sha256':sha(Path(module.__file__).read_bytes())} for module in (_ssl,_sqlite3)}
    for name in ('python','rustc','cargo','rustup','cc','ld','ar'):
        path=sys.executable if name=='python' else shutil.which(name,path=env['PATH'])
        try:
            actual=Path(path).resolve()
            version=subprocess.check_output([str(actual),'--version'],env=env,stderr=subprocess.STDOUT,timeout=30).decode().strip()
            result['binaries'][name]={'path':str(actual),'sha256':sha(actual.read_bytes()),'version':version}
        except Exception as error: result['binaries'][name]={'status':'UNKNOWN','error':type(error).__name__}
    for name in ('rustc','cargo'):
        try:
            path=subprocess.check_output(['rustup','which','--toolchain','1.98.1',name],env=env,timeout=30).decode().strip()
            result['binaries']['toolchain_'+name]={'path':path,'sha256':sha(Path(path).read_bytes()),'version':subprocess.check_output([path,'--version'],env=env).decode().strip()}
        except Exception as error: result['binaries']['toolchain_'+name]={'status':'UNKNOWN','error':type(error).__name__}
    return result


def installed_inputs(python, wheels, env):
    import zipfile
    site=Path(subprocess.check_output([str(python),'-c','import sysconfig; print(sysconfig.get_path("purelib"))'],env=env).decode().strip())
    report={}
    for name,entry in wheels.items():
        matched={}
        with zipfile.ZipFile(entry['wheel']) as archive:
            for member in archive.namelist():
                if member.endswith('/') or member.endswith('.dist-info/RECORD'): continue
                # This verification profile has no spread .data wheels.
                if '.data/' in member or '..' in Path(member).parts or Path(member).is_absolute(): raise Rejected('unsupported wheel layout')
                path=site/member;want=sha(archive.read(member))
                if not path.is_file() or path.is_symlink() or sha(path.read_bytes())!=want: raise Rejected('installed wheel bytes mismatch: '+name)
                matched[member]=want
        report[name]={'wheel_sha256':entry['wheel_sha256'],'installed_files':matched}
    return report


def suite_summary(args,text):
    command=' '.join(map(str,args))
    if re.search(r'\b[1-9][0-9]* (?:skipped|deselected|xfailed|filtered out|ignored)\b',text): raise Rejected('incomplete test suite')
    if 'test_conformance.py' in command:
        counts=[int(x) for x in re.findall(r'(\d+) passed',text)]
        if counts!=[249,154]: raise Rejected('unexpected conformance test counts')
        return {'suite':'python-conformance','passed':counts,'skipped':0,'deselected':0}
    if 'cargo' in command and 'test' in args:
        counts=[int(x) for x in re.findall(r'test result: ok\. (\d+) passed',text)]
        if sum(counts)!=96: raise Rejected('unexpected Rust test counts')
        return {'suite':'rust','passed':sum(counts),'ignored':0,'filtered':0}
    if 'unittest' in args:
        counts=re.findall(r'Ran (\d+) tests',text)
        if len(counts)!=1 or int(counts[0])<34 or not re.search(r'\nOK\s*$',text): raise Rejected('tool tests not complete')
        return {'suite':'tools','passed':int(counts[0])}
    return None


def run_verification(root,manifest_path,output,wheelhouse,archive=None,repo=None,commit=None):
    root=Path(root).resolve(); output=Path(output).resolve();wheelhouse=Path(wheelhouse).resolve()
    if output==root or root in output.parents: raise Rejected('verification output must be outside unpacked source')
    output.mkdir(parents=True,exist_ok=False)
    manifest=json.loads(Path(manifest_path).read_text())
    verified_commit,verified_sha=bind_source(root,manifest,archive,repo,commit)
    actual={str(p.relative_to(root)) for p in root.rglob('*') if p.is_file() or p.is_symlink()}
    if actual!={e['path'] for e in manifest['files']}:raise ValueError('unpacked source member list differs from manifest')
    for entry in manifest['files']:
        p=root/entry['path']
        if not p.is_file() or p.is_symlink() or sha(p.read_bytes())!=entry['sha256'] or p.stat().st_mode & 0o777 != int(entry['mode'],8):raise ValueError('source differs from manifest')
    if platform.system()!='Linux' or platform.machine()!='x86_64' or sys.version_info[:3]!=(3,13,15):raise ValueError('verification requires CPython 3.13.15, Linux x86_64')
    # Cargo reads ancestor .cargo/config files independently of CARGO_HOME.
    for directory in (root,*root.parents,output,*output.parents):
        if any((directory/'.cargo'/name).exists() for name in ('config','config.toml')): raise Rejected('unexpected ancestor Cargo override')
    lock,wheels=locked_wheels(root/'release/verification-requirements.txt',wheelhouse)
    if set(lock)!=set(wheels): raise Rejected('missing hash-verified wheel inputs')
    selected_wheels=output/'verified-wheels';selected_wheels.mkdir()
    for entry in wheels.values():
        destination=selected_wheels/Path(entry['wheel']).name;shutil.copyfile(entry['wheel'],destination)
        if sha(destination.read_bytes())!=entry['wheel_sha256']: raise Rejected('wheel changed during copy')
        entry['wheel']=str(destination)
    env=controlled_environment(output,selected_wheels)
    inventory=environment_inventory(env)
    inventory_path=output/'environment.json';inventory_path.write_text(json.dumps(inventory,indent=2)+'\n')
    commands=[]
    suite_results=[]
    def run(args,cwd=output):
        args=[str(x) for x in args]
        command_log=output/('command-%03d.log'%len(commands))
        with command_log.open('x') as log:
            subprocess.run(args,cwd=cwd,env=env,stdout=log,stderr=subprocess.STDOUT,check=True,timeout=900,umask=0o022)
        text=command_log.read_text()
        with (output/'verification.log').open('a') as log: log.write('\nCOMMAND '+json.dumps(args)+'\n'+text)
        summary=suite_summary(args,text)
        if summary: suite_results.append(summary)
        commands.append({'args':args,'log':command_log.name,'sha256':sha(command_log.read_bytes())})
    run(['cargo','+1.98.1','test','--locked','--offline'],root/'implementation')
    run(['cargo','+1.98.1','build','--release','--locked','--offline'],root/'implementation')
    run(['cargo','+1.98.1','build','--examples','--locked','--offline'],root/'implementation')
    run([sys.executable,'-m','unittest','discover','-s',root/'tools/tests','-v'])
    # Build a disposable copy selected only from manifest paths, without stale egg-info.
    build_source=output/'sdk-build';build_source.mkdir()
    prefix='implementation/python-sdk/'
    for entry in manifest['files']:
        if entry['path'].startswith(prefix):
            dst=build_source/entry['path'][len(prefix):];dst.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(root/entry['path'],dst);dst.chmod(0o644)
    build_venv=output/'build-venv'
    run([sys.executable,'-m','venv',build_venv])
    build_python=build_venv/'bin/python'
    run([build_python,'-m','pip','install','--require-hashes','--only-binary=:all:','-r',root/'release/verification-requirements.txt'])
    run([build_python,'-m','pip','check'])
    inputs=installed_inputs(build_python,wheels,env)
    inputs_path=output/'build-inputs.json';inputs_path.write_text(json.dumps(inputs,indent=2)+'\n')
    packages=output/'packages'
    run([build_python,'-m','build','--no-isolation','--outdir',packages,build_source])
    wheel=packages/'ordavyn-0.1.0-py3-none-any.whl';sdist=packages/'ordavyn-0.1.0.tar.gz'
    inventories=verify(root,wheel,sdist)
    (output/'package-inventory.json').write_text(json.dumps(inventories,indent=2)+'\n')
    readme=(root/'implementation/python-sdk/README.md').read_text()
    example=output/'readme_example.py';example.write_text(readme.split('```python\n',1)[1].split('```',1)[0])
    for kind,artifact in (('wheel',wheel),('sdist',sdist)):
        venv=output/kind
        run([sys.executable,'-m','venv',venv])
        python=venv/'bin/python'
        run([python,'-m','pip','install','--require-hashes','--only-binary=:all:','-r',root/'release/verification-requirements.txt'])
        run([python,'-m','pip','install','--no-deps','--no-build-isolation',artifact])
        run([python,'-m','pip','check'])
        installed_inputs(python,wheels,env)
        run([python,'-c',"import ordavyn; assert 'site-packages' in ordavyn.__file__; print(ordavyn.__file__)"])
        run([python,root/'implementation/tests/test_conformance.py'])
        for path in ('implementation/demo/demo_ecommerce.py','implementation/demo/demo_multi.py'):
            run([python,root/path])
        run([python,example])
        run([python,root/'tools/verify_guides.py','--root',root])
    for entry in manifest['files']:
        if sha((root/entry['path']).read_bytes())!=entry['sha256']:raise ValueError('verification mutated source')
    result={'status':'TESTS_PASS','publication':'BLOCKED','source_commit':verified_commit,'source_sha256':verified_sha,'environment_sha256':sha(inventory_path.read_bytes()),'build_inputs_sha256':sha(inputs_path.read_bytes()),'verification_lock_sha256':sha((root/'release/verification-requirements.txt').read_bytes()),'suite_results':suite_results,'python':sys.version,'platform':platform.platform(),'commands':commands,'artifacts':inventories,'wheel_bit_reproducibility':'NOT_CLAIMED'}
    (output/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',required=True);p.add_argument('--manifest',required=True);p.add_argument('--output',required=True);p.add_argument('--wheelhouse',required=True);p.add_argument('--archive',required=True);p.add_argument('--repo',required=True);p.add_argument('--commit',required=True);a=p.parse_args();run_verification(a.root,a.manifest,a.output,a.wheelhouse,a.archive,a.repo,a.commit)
