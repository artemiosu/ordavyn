#!/usr/bin/env python3
"""Record dependency evidence locally; missing evidence remains UNKNOWN."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
from pathlib import Path
import platform
import re
import os
import shutil
import subprocess
import sys
import tomllib
import urllib.request

# Reviewed public verification inputs; never discover names for outbound queries.
PUBLIC_PYTHON = {'build':'1.6.1','cbor2':'5.9.0','cffi':'2.1.1','cryptography':'50.0.1','iniconfig':'2.3.0','packaging':'26.3','pip':'26.2.1','pluggy':'1.6.0','pycparser':'3.0','Pygments':'2.21.0','pyproject_hooks':'1.3.3','pytest':'9.1.1','setuptools':'84.0.0','wheel':'0.48.0'}


def digest(data): return hashlib.sha256(data).hexdigest()


def fetch(url):
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={'User-Agent':'Ordavyn-local-audit'}),timeout=30) as response:
            data=response.read()
            return {'status':'FETCHED','url':url,'sha256':digest(data),'data':json.loads(data)}
    except Exception as error:
        return {'status':'UNKNOWN','url':url,'error':type(error).__name__,'http_status':getattr(error,'code',None)}


def notices(root):
    result=[]
    for path in sorted(root.rglob('*')):
        if path.is_file() and re.search(r'(?i)(?:^|[._-])(licen[cs]e|copying|notice|copyright)(?:$|[._-])',path.name):
            result.append({'path':str(path.relative_to(root)),'sha256':digest(path.read_bytes())})
    return result


def semver_matches(helper, queries):
    if helper is None:
        return [None] * len(queries)
    try:
        raw=subprocess.check_output([str(helper)],input=json.dumps(queries).encode(),stderr=subprocess.DEVNULL,timeout=30)
        answers=json.loads(raw)
        if not isinstance(answers,list) or len(answers)!=len(queries): raise ValueError('invalid helper response')
        result=[]
        for query,answer in zip(queries,answers):
            matches=answer.get('matches') if isinstance(answer,dict) else None
            if not isinstance(matches,list) or len(matches)!=len(query['requirements']) or any(type(value) is not bool for value in matches):
                result.append(None)
            else: result.append(matches)
        return result
    except (OSError,subprocess.CalledProcessError,subprocess.TimeoutExpired,ValueError,TypeError,json.JSONDecodeError):
        return [None] * len(queries)


def prepare_semver_helper(root, output, lock=None):
    lock=lock or tomllib.loads((root/'implementation/Cargo.lock').read_text())
    target=output/'semver-build'
    home=output/'semver-home';cargo_home=output/'semver-cargo-home'
    home.mkdir();(cargo_home/'registry/cache').mkdir(parents=True)
    cargo_executable=shutil.which('cargo')
    if cargo_executable is None: raise OSError('cargo unavailable')
    source_cargo_home=Path(os.environ.get('CARGO_HOME',Path(cargo_executable).resolve().parent.parent))
    rustup_home=Path(os.environ.get('RUSTUP_HOME',source_cargo_home.parent/'.rustup'))
    host_cache=source_cargo_home/'registry/cache';archives={}
    for package in lock['package']:
        if package.get('source')!='registry+https://github.com/rust-lang/crates.io-index': continue
        key=package['name']+'-'+package['version'];matches=[]
        for path in list(host_cache.glob('*/'+key+'.crate'))+list(output.glob(key+'.crate')):
            if digest(path.read_bytes())==package['checksum']: matches.append(path)
        if not matches: continue
        source=matches[0];destination=cargo_home/'registry/cache'/source.parent.name/source.name
        destination.parent.mkdir(parents=True,exist_ok=True);destination.write_bytes(source.read_bytes())
        archives[key]={'sha256':package['checksum'],'source':package['source']}
    index=source_cargo_home/'registry/index'
    if index.exists(): (cargo_home/'registry/index').symlink_to(index,target_is_directory=True)
    cargo_cwd=root/'implementation'
    for directory in (cargo_cwd,*cargo_cwd.parents):
        if any((directory/'.cargo'/name).exists() for name in ('config','config.toml')): raise ValueError('unexpected ancestor Cargo override')
    blocked={'HOME','CARGO_HOME','RUSTUP_HOME','RUSTFLAGS','RUSTC_WRAPPER','CARGO_ENCODED_RUSTFLAGS','CARGO_TARGET_DIR','CC','CXX','AR','LD'}
    env={key:value for key,value in os.environ.items() if key not in blocked and not key.startswith('CARGO_TARGET_')}
    remap=f'--remap-path-prefix={root.resolve()}=/ordavyn-source --remap-path-prefix={cargo_home.resolve()}=/cargo-home'
    path=str(Path(cargo_executable).parent)+':'+env.get('PATH','/usr/local/bin:/usr/bin:/bin')
    env.update({'PATH':path,'HOME':str(home),'CARGO_HOME':str(cargo_home),'RUSTUP_HOME':str(rustup_home),'RUSTUP_TOOLCHAIN':'1.98.1','CARGO_TARGET_DIR':str(target),'CARGO_NET_OFFLINE':'true','RUSTFLAGS':remap})
    subprocess.run(['cargo','+1.98.1','build','--locked','--offline','--example','audit_semver'],cwd=cargo_cwd,env=env,check=True,timeout=300,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    helper=target/'debug/examples/audit_semver'
    if not helper.is_file() or helper.is_symlink(): raise ValueError('semver helper missing')
    canary=semver_matches(helper,[{'version':'1.2.3','requirements':['>=1.2.3','<1.2.3']}])
    if canary!=[[True,False]]: raise ValueError('semver helper canary failed')
    extracted={}
    for source in sorted((cargo_home/'registry/src').glob('*/*')):
        if not source.is_dir(): continue
        rows=[]
        for path in sorted(source.rglob('*')):
            if path.is_file() and not path.is_symlink(): rows.append((str(path.relative_to(source)),digest(path.read_bytes())))
        extracted[source.name]=digest(json.dumps(rows,separators=(',',':')).encode())
    return helper,{'archives':archives,'extracted_source_sha256':extracted,'sha256':digest(helper.read_bytes()),'environment':{'fresh_home':True,'fresh_cargo_home':True,'offline':True,'locked':True}}


def rustsec_matches(lock, archive_path, semver_helper=None):
    import tarfile
    packages={}
    for item in lock['package']:
        packages.setdefault(item['name'],[]).append(item['version'])
    result=[]
    with tarfile.open(archive_path) as archive:
        for item in archive:
            if not item.isfile() or '/crates/' not in item.name or not item.name.endswith('.md'): continue
            raw_bytes=archive.extractfile(item).read()
            try:
                raw=raw_bytes.decode()
                if not raw.startswith('```toml\n'): raise ValueError('missing advisory TOML')
                data=tomllib.loads(raw.split('```toml\n',1)[1].split('```',1)[0]);advisory=data['advisory']
                name=advisory['package'];identifier=advisory['id']
                conditions=data.get('versions',{})
                patched=conditions.get('patched',[]);unaffected=conditions.get('unaffected',[])
                if not isinstance(patched,list) or not isinstance(unaffected,list): raise ValueError('invalid ranges')
                versions=packages.get(name,[])
                requirements=patched+unaffected
                queries=[{'version':version,'requirements':requirements} for version in versions]
                answers=semver_matches(semver_helper,queries)
                for version,tests in zip(versions,answers):
                    status='WITHDRAWN' if advisory.get('withdrawn') else 'UNKNOWN' if tests is None else 'NOT_AFFECTED' if True in tests else 'BLOCKER'
                    result.append({'package':name,'version':version,'id':identifier,'status':status,'advisory':data,'sha256':digest(raw_bytes)})
            except (ValueError,KeyError,TypeError,AttributeError) as error:
                result.append({'path':item.name,'status':'UNKNOWN','reason':type(error).__name__,'sha256':digest(raw_bytes)})
    return result


def rustsec_evidence(archive_path, provenance_path, current_commit=None, online=False):
    try:
        provenance=json.loads(Path(provenance_path).read_text())
        commit=provenance['commit']
        if not re.fullmatch(r'[0-9a-f]{40}',commit): raise ValueError('invalid commit')
        if provenance['url']!='https://api.github.com/repos/RustSec/advisory-db/tarball/'+commit: raise ValueError('not immutable official URL')
        if digest(Path(archive_path).read_bytes())!=provenance['sha256']: raise ValueError('archive hash mismatch')
        if not online:
            return {'status':'LOCAL_DECLARATION','commit':commit,'sha256':provenance['sha256'],'url':provenance['url'],'freshness':'UNKNOWN'}
        with urllib.request.urlopen(provenance['url'],timeout=30) as response: remote=response.read()
        if digest(remote)!=provenance['sha256']: raise ValueError('official archive differs')
        return {'status':'MATCHED_IMMUTABLE_SNAPSHOT','commit':commit,'sha256':provenance['sha256'],'url':provenance['url'],'freshness':'CURRENT_HEAD' if current_commit==commit else 'UNKNOWN'}
    except (OSError,KeyError,ValueError,TypeError,AttributeError) as error:
        return {'status':'UNKNOWN','reason':type(error).__name__,'freshness':'UNKNOWN'}


def locked_wheels(lock_path,wheelhouse):
    import zipfile
    from email.parser import BytesParser
    normalize=lambda name: re.sub(r'[-_.]+','-',name).lower()
    locked={}
    for line in Path(lock_path).read_text().replace('\\\n',' ').splitlines():
        match=re.match(r'([A-Za-z0-9_.-]+)==([^ ]+)\s+(.*)',line)
        if not match: raise ValueError('invalid hash lock')
        name,version,hashes=match.groups()
        locked[normalize(name)]={'name':name,'version':version,'hashes':re.findall(r'--hash=sha256:([a-f0-9]{64})',hashes)}
    found={};unusable=set();seen=set()
    for path in sorted(Path(wheelhouse).glob('*.whl')) if wheelhouse else []:
        candidates=[]
        try:
            checksum=digest(path.read_bytes())
            # Do not parse untrusted wheel metadata until a lock digest matches.
            candidates=[n for n,v in locked.items() if checksum in v['hashes']]
            if len(candidates)!=1:
                unusable.update(candidates);continue
            if candidates[0] in seen or candidates[0] in unusable:
                unusable.add(candidates[0]);found.pop(candidates[0],None);continue
            seen.add(candidates[0])
            with zipfile.ZipFile(path) as archive:
                names=archive.namelist()
                if len(names)!=len(set(names)): continue
                metadata=[n for n in names if n.endswith('.dist-info/METADATA') and n.count('/')==1]
                if len(metadata)!=1: continue
                meta=BytesParser().parsebytes(archive.read(metadata[0]))
                name=normalize(meta['Name']);version=meta['Version']
                if name!=candidates[0] or version!=locked[name]['version']: continue
                entry={'name':meta['Name'],'version':version,'wheel':str(path.resolve()),'wheel_sha256':checksum,
                       'status':'HASH_VERIFIED_WHEEL','requires_dist':meta.get_all('Requires-Dist',[]),
                       'license_expression':meta.get('License-Expression'),'legacy_license':meta.get('License'),'notices':[]}
                for member in names:
                    if re.search(r'(?i)(licen[cs]e|copying|notice|copyright)',member):
                        entry['notices'].append({'path':member,'sha256':digest(archive.read(member))})
                found[name]=entry
        except (OSError,ValueError,KeyError,TypeError,zipfile.BadZipFile,RuntimeError,EOFError):
            unusable.update(candidates)
    return locked,{name:entry for name,entry in found.items() if name not in unusable}


def python_wheel_evidence(lock_path,wheelhouse,name,version):
    entry={'name':name,'version':version,'status':'UNKNOWN','notices':[]}
    try:
        _,found=locked_wheels(lock_path,wheelhouse)
        evidence=found.get(re.sub(r'[-_.]+','-',name).lower())
        if evidence is None: entry['reason']='missing or hash-mismatched wheel'
        elif evidence['version']!=version: entry['reason']='lock differs from reviewed version'
        else: entry=evidence
    except Exception as error: entry['reason']=type(error).__name__
    return entry


def audit(root, output, online=False, download_cargo=False, wheelhouse=None):
    root, output=Path(root).resolve(),Path(output).resolve()
    wheelhouse=Path(wheelhouse).resolve() if wheelhouse is not None else None
    output.mkdir(parents=True,exist_ok=False)
    report={'date_utc':datetime.now(timezone.utc).isoformat(),'environment':{'python':sys.version,'platform':platform.platform(),'machine':platform.machine(),'rust':'UNKNOWN'},'package_release':'BLOCKED','cargo':[],'python':[]}
    try: report['environment']['rust']=subprocess.check_output(['rustc','+1.98.1','-Vv']).decode()
    except (OSError,subprocess.CalledProcessError): pass
    producer_names=('tools/audit_dependencies.py','implementation/ordavyn-core/Cargo.toml','implementation/ordavyn-core/examples/audit_semver.rs')
    report['binding']={'locks':{name:digest((root/name).read_bytes()) for name in ('implementation/Cargo.lock','release/verification-requirements.txt')},'producer':{name:(digest((root/name).read_bytes()) if (root/name).is_file() else 'UNKNOWN') for name in producer_names}}
    helper=None
    try: report['binding']['source_commit']=subprocess.check_output(['git','-C',str(root),'rev-parse','HEAD'],stderr=subprocess.DEVNULL).decode().strip()
    except (OSError,subprocess.CalledProcessError): report['binding']['source_commit']='UNKNOWN'
    cargo_home=Path.home()/'.cargo/registry'
    lock=tomllib.loads((root/'implementation/Cargo.lock').read_text())
    for package in lock['package']:
        if 'source' not in package: continue
        entry={k:package[k] for k in ('name','version','source','checksum')}
        entry['lock_dependencies']=package.get('dependencies',[])
        try:
            candidates=list((cargo_home/'src').glob('*/'+package['name']+'-'+package['version']))
            archives=list((cargo_home/'cache').glob('*/'+package['name']+'-'+package['version']+'.crate'))
            entry['archive_status']='UNKNOWN'
            if not archives and online and download_cargo:
                if package['source'] != 'registry+https://github.com/rust-lang/crates.io-index' or not re.fullmatch(r'[A-Za-z0-9_-]+',package['name']) or not re.fullmatch(r'[A-Za-z0-9.+-]+',package['version']):
                    raise ValueError('unreviewed Cargo source')
                url=f"https://static.crates.io/crates/{package['name']}/{package['name']}-{package['version']}.crate"
                entry['official_url']=url
                try:
                    with urllib.request.urlopen(url,timeout=30) as response: data=response.read()
                    if digest(data)!=entry['checksum']: raise ValueError('official crate checksum mismatch')
                    dest=output/(package['name']+'-'+package['version']+'.crate')
                    with dest.open('xb') as f:f.write(data)
                    archives=[dest]
                except Exception as error:
                    entry['download_status']='UNKNOWN';entry['download_error']=type(error).__name__
    
            if archives:
                entry['archive_sha256']=digest(archives[0].read_bytes())
                entry['archive_status']='MATCH' if entry['archive_sha256']==entry['checksum'] else 'MISMATCH'
            entry['license_status']='UNKNOWN'
            if archives and entry['archive_status']=='MATCH':
                try:
                    import tarfile
                    with tarfile.open(archives[0]) as archive:
                        members={item.name:item for item in archive if item.isfile()}
                        prefix=package['name']+'-'+package['version']+'/'
                        metadata=tomllib.loads(archive.extractfile(members[prefix+'Cargo.toml']).read().decode())
                        entry['license_expression']=metadata['package'].get('license')
                        entry['license_file']=metadata['package'].get('license-file')
                        entry['notices']=[]
                        entry['source_files']={}
                        for name,item in members.items():
                            data=archive.extractfile(item).read()
                            entry['source_files'][name]={'sha256':digest(data),'size':len(data)}
                            if re.search(r'(?i)(?:^|[._-])(licen[cs]e|copying|notice|copyright)(?:$|[._-])',Path(name).name):
                                entry['notices'].append({'path':name,'sha256':digest(data)})
                        entry['license_status']='ARCHIVE_EVIDENCE' if entry['notices'] else 'UNKNOWN'
                        entry['dependency_conditions']={k:v for k,v in metadata.items() if k in ('dependencies','dev-dependencies','build-dependencies','target','features')}
                    entry['source_file_checks']='UNKNOWN'
                    if candidates:
                        source=candidates[0]
                        expected={n[len(prefix):]:v['sha256'] for n,v in entry['source_files'].items()}
                        actual={str(p.relative_to(source)) for p in source.rglob('*') if p.is_file() or p.is_symlink()}
                        actual-= {'.cargo-checksum.json','.cargo-ok'}
                        bad=sorted(actual ^ set(expected))
                        for name,want in expected.items():
                            path=source/name
                            if not path.is_file() or path.is_symlink() or digest(path.read_bytes())!=want: bad.append(name)
                        entry['source_file_checks']='MISMATCH' if bad else 'MATCH'
                        entry['source_file_mismatches']=sorted(set(bad))
                except Exception as error:
                    entry['source_file_checks']='UNKNOWN';entry['component_error']=type(error).__name__
        except Exception as error:
            entry['archive_status']='UNKNOWN';entry['component_error']=type(error).__name__
        report['cargo'].append(entry)
    normalized=lambda n: re.sub(r'[-_.]+','-',n).lower()
    reviewed={normalized(n):v for n,v in PUBLIC_PYTHON.items()}
    locked,_=locked_wheels(root/'release/verification-requirements.txt',wheelhouse)
    actual={n:e['version'] for n,e in locked.items()}
    report['python_allowlist_status']='MATCH' if reviewed==actual else 'BLOCKED'
    for key in sorted(set(actual)|set(reviewed)):
        name=locked.get(key,{}).get('name',key);version=actual.get(key,reviewed.get(key))
        if actual.get(key)!=reviewed.get(key):
            report['python'].append({'name':name,'version':version,'status':'UNKNOWN','reason':'reviewed public allowlist differs from lock'});continue
        entry=python_wheel_evidence(root/'release/verification-requirements.txt',wheelhouse,name,version)
        entry['role']=('runtime' if name.lower() in ('cbor2','cffi','cryptography','pycparser') else 'build' if name.lower() in ('build','setuptools','wheel','pyproject_hooks') else 'development')
        entry['official_metadata']=fetch(f'https://pypi.org/pypi/{name}/{version}/json') if online else {'status':'UNKNOWN','reason':'network check not requested'}
        entry['advisory_status']='OBSERVED' if entry['official_metadata']['status']=='FETCHED' else 'UNKNOWN'
        entry['advisories']=entry['official_metadata'].get('data',{}).get('vulnerabilities')
        report['python'].append(entry)
    if online:
        report['name_availability']={name:fetch(url) for name,url in {'pypi_ordavyn':'https://pypi.org/pypi/ordavyn/json','crates_ordavyn_core':'https://crates.io/api/v1/crates/ordavyn-core'}.items()}
        report['rustsec_index']=fetch('https://api.github.com/repos/RustSec/advisory-db/commits/HEAD')
    rustsec_archive=root/'.ordavyn-private/release-candidate/rustsec.tar.gz'
    report['rustsec_archive']=rustsec_evidence(rustsec_archive,root/'.ordavyn-private/release-candidate/rustsec.tar.json',report.get('rustsec_index',{}).get('data',{}).get('sha'),online)
    if report['rustsec_archive']['status']=='MATCHED_IMMUTABLE_SNAPSHOT':
        try:
            helper,helper_evidence=prepare_semver_helper(root,output,lock)
            report['binding']['semver_helper']=helper_evidence
        except (OSError,ValueError,subprocess.CalledProcessError,subprocess.TimeoutExpired) as error:
            report['binding']['semver_helper']={'status':'UNKNOWN','reason':type(error).__name__}
        report['rustsec_matches']=rustsec_matches(lock,rustsec_archive,helper)
    report['limitations']=['No legal or trademark clearance; registry response is only a dated observation.','Advisory data does not establish absence of vulnerabilities.','License metadata and notice hashes are evidence, not interpretation of obligations.','Cargo entries unavailable locally remain UNKNOWN, including untested targets.','Transitive bundled components require separate review.']
    (output/'dependencies.json').write_text(json.dumps(report,indent=2,default=str)+'\n')
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',default='.');p.add_argument('--output',required=True);p.add_argument('--online',action='store_true');p.add_argument('--download-cargo',action='store_true');p.add_argument('--wheelhouse');a=p.parse_args();audit(a.root,a.output,a.online,a.download_cargo,a.wheelhouse)
