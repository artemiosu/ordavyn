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


def rustsec_matches(lock, archive_path):
    import tarfile
    from packaging.version import Version
    packages={}
    for item in lock['package']:
        packages.setdefault(item['name'],[]).append(item['version'])
    def matches(version, expression):
        # Deliberately limited parser: unsupported Rust syntax stays UNKNOWN.
        tests=[]
        for part in expression.split(','):
            match=re.fullmatch(r'\s*(>=|<=|>|<|=|\^)?\s*(\d+(?:\.\d+){0,2}(?:-[a-zA-Z0-9.]+)?)\s*',part)
            if not match: return None
            op,raw=match.groups();bound=Version(raw);current=Version(version)
            if current.is_prerelease: return None
            if op in (None,'^'):
                nums=list(bound.release)+[0,0];major,minor,patch=nums[:3]
                upper=Version(f'{major+1}.0.0' if major else f'0.{minor+1}.0' if minor else f'0.0.{patch+1}')
                tests.append(bound<=current<upper)
            else:
                tests.append({'=':current==bound,'>':current>bound,'>=':current>=bound,'<':current<bound,'<=':current<=bound}[op])
        return all(tests)
    result=[]
    with tarfile.open(archive_path) as archive:
        for item in archive:
            if not item.isfile() or '/crates/' not in item.name or not item.name.endswith('.md'): continue
            raw=archive.extractfile(item).read().decode()
            if not raw.startswith('```toml\n'): continue
            data=tomllib.loads(raw.split('```toml\n',1)[1].split('```',1)[0]);advisory=data['advisory']
            for version in packages.get(advisory['package'],[]):
                conditions=data.get('versions',{});tests=[matches(version,v) for v in conditions.get('patched',[])+conditions.get('unaffected',[])]
                status='WITHDRAWN' if advisory.get('withdrawn') else 'NOT_AFFECTED' if True in tests else 'UNKNOWN' if None in tests else 'BLOCKER'
                result.append({'package':advisory['package'],'version':version,'id':advisory['id'],'status':status,'advisory':data,'sha256':digest(raw.encode())})
    return result


def audit(root, output, online=False, download_cargo=False):
    root, output=Path(root),Path(output)
    output.mkdir(parents=True,exist_ok=False)
    report={'date_utc':datetime.now(timezone.utc).isoformat(),'environment':{'python':sys.version,'platform':platform.platform(),'machine':platform.machine(),'rust':subprocess.check_output(['rustc','+1.98.1','-Vv']).decode()},'publication':'BLOCKED','cargo':[],'python':[]}
    cargo_home=Path.home()/'.cargo/registry'
    lock=tomllib.loads((root/'implementation/Cargo.lock').read_text())
    for package in lock['package']:
        if 'source' not in package: continue
        entry={k:package[k] for k in ('name','version','source','checksum')}
        entry['lock_dependencies']=package.get('dependencies',[])
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
        if candidates:
            source=candidates[0]
            metadata=tomllib.loads((source/'Cargo.toml').read_text())
            entry['license_expression']=metadata['package'].get('license')
            entry['license_file']=metadata['package'].get('license-file')
            entry['notices']=notices(source)
            entry['license_status']='LOCAL_EVIDENCE' if entry['notices'] else 'UNKNOWN'
            entry['dependency_conditions']={k:v for k,v in metadata.items() if k in ('dependencies','dev-dependencies','build-dependencies','target','features')}
            checksum_file=source/'.cargo-checksum.json'
            if checksum_file.exists():
                checks=json.loads(checksum_file.read_text())
                bad=[name for name,want in checks['files'].items() if not (source/name).is_file() or digest((source/name).read_bytes())!=want]
                entry['source_file_checks']='MATCH' if not bad else 'MISMATCH'
                entry['source_file_mismatches']=bad
        if archives and entry['archive_status']=='MATCH':
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
        report['cargo'].append(entry)
    for name,version in PUBLIC_PYTHON.items():
        dist=importlib.metadata.distribution(name)
        if dist.version!=version: raise ValueError('installed verification version differs from public allowlist')
        entry={'name':name,'version':version,'requires_dist':dist.requires or [],'license_expression':dist.metadata.get('License-Expression'),'legacy_license':dist.metadata.get('License'),'notices':[]}
        for item in dist.files or []:
            if re.search(r'(?i)(licen[cs]e|copying|notice|copyright)',str(item)):
                path=dist.locate_file(item)
                if path.is_file(): entry['notices'].append({'path':str(item),'sha256':digest(path.read_bytes())})
        entry['role']=('runtime' if name.lower() in ('cbor2','cffi','cryptography','pycparser') else 'build' if name.lower() in ('build','setuptools','wheel','pyproject_hooks') else 'development')
        entry['official_metadata']=fetch(f'https://pypi.org/pypi/{name}/{version}/json') if online else {'status':'UNKNOWN','reason':'network check not requested'}
        entry['advisory_status']='OBSERVED' if entry['official_metadata']['status']=='FETCHED' else 'UNKNOWN'
        entry['advisories']=entry['official_metadata'].get('data',{}).get('vulnerabilities')
        report['python'].append(entry)
    if online:
        report['name_availability']={name:fetch(url) for name,url in {'pypi_ordavyn':'https://pypi.org/pypi/ordavyn/json','crates_ordavyn_core':'https://crates.io/api/v1/crates/ordavyn-core'}.items()}
        report['rustsec_index']=fetch('https://api.github.com/repos/RustSec/advisory-db/commits/HEAD')
    rustsec_archive=root/'.ordavyn-private/release-candidate/rustsec.tar.gz'
    if rustsec_archive.exists(): report['rustsec_matches']=rustsec_matches(lock,rustsec_archive)
    report['limitations']=['No legal or trademark clearance; registry response is only a dated observation.','Advisory data does not establish absence of vulnerabilities.','License metadata and notice hashes are evidence, not interpretation of obligations.','Cargo entries unavailable locally remain UNKNOWN, including untested targets.','Transitive bundled components require separate review.']
    (output/'dependencies.json').write_text(json.dumps(report,indent=2,default=str)+'\n')
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',default='.');p.add_argument('--output',required=True);p.add_argument('--online',action='store_true');p.add_argument('--download-cargo',action='store_true');a=p.parse_args();audit(a.root,a.output,a.online,a.download_cargo)
