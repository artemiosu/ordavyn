#!/usr/bin/env python3
"""Validate all package bytes against snapshot sources and fixed builder metadata."""
import argparse
import base64
import csv
import io
import json
from pathlib import Path
import tomllib
from release_candidate import Rejected, archive_entries, sha


def expected_metadata(sdk):
    project=tomllib.loads((sdk/'pyproject.toml').read_text())['project']
    pairs=[('Metadata-Version','2.4'),('Name',project['name']),('Version',project['version']),('Summary',project['description']),('License-Expression',project['license']),('Keywords',','.join(project['keywords']))]
    pairs += [('Classifier',v) for v in project['classifiers']]
    pairs += [('Requires-Python',project['requires-python']),('Description-Content-Type','text/markdown'),('License-File','LICENSE')]
    pairs += [('Requires-Dist',v) for v in project['dependencies']]
    pairs += [('Dynamic','license-file')]
    return ('\n'.join(k+': '+v for k,v in pairs)+'\n\n'+(sdk/'README.md').read_text()).encode()


def verify(root, wheel, sdist):
    root=Path(root);sdk=root/'implementation/python-sdk'
    policy=json.loads((root/'release/files.json').read_text())['files']
    modules={name.removeprefix('implementation/python-sdk/'): (root/name).read_bytes() for name,rule in policy.items() if name.startswith('implementation/python-sdk/ordavyn/') and rule['action']=='include'}
    meta=expected_metadata(sdk)
    wheel_data,wheel_modes=archive_entries(wheel,with_modes=True)
    prefix='ordavyn-0.1.0.dist-info/'
    expected_wheel={**modules,prefix+'licenses/LICENSE':(sdk/'LICENSE').read_bytes(),prefix+'METADATA':meta,prefix+'WHEEL':b'Wheel-Version: 1.0\nGenerator: setuptools (84.0.0)\nRoot-Is-Purelib: true\nTag: py3-none-any\n\n',prefix+'top_level.txt':b'ordavyn\n'}
    if set(wheel_data)!=set(expected_wheel)|{prefix+'RECORD'}:raise Rejected('wheel member list mismatch')
    for name,data in expected_wheel.items():
        if wheel_data[name]!=data:raise Rejected('wheel content mismatch: '+name)
    records=list(csv.reader(io.StringIO(wheel_data[prefix+'RECORD'].decode())))
    if len(records)!=len(wheel_data) or {r[0] for r in records}!=set(wheel_data):raise Rejected('RECORD paths mismatch')
    for name,hashvalue,size in records:
        if name==prefix+'RECORD':
            if hashvalue or size:raise Rejected('invalid RECORD self entry')
        elif hashvalue!='sha256='+base64.urlsafe_b64encode(bytes.fromhex(sha(wheel_data[name]))).rstrip(b'=').decode() or size!=str(len(wheel_data[name])):
            raise Rejected('RECORD content mismatch')
    originals={name:(sdk/name).read_bytes() for name in ('LICENSE','MANIFEST.in','README.md','pyproject.toml','requirements.txt')}
    originals.update(modules)
    sources='\n'.join(sorted(originals,key=lambda x: ('/' in x,x)))
    expected_sdist={**originals,'PKG-INFO':meta,'setup.cfg':b'[egg_info]\ntag_build = \ntag_date = 0\n\n','ordavyn.egg-info/SOURCES.txt':sources.encode()}
    expected_sdist={'ordavyn-0.1.0/'+n:d for n,d in expected_sdist.items()}
    sdist_data,sdist_modes=archive_entries(sdist,with_modes=True)
    if set(sdist_data)!=set(expected_sdist):raise Rejected('sdist member list mismatch')
    for name,data in expected_sdist.items():
        if sdist_data[name]!=data:raise Rejected('sdist content mismatch: '+name)
    for modes,contents in ((wheel_modes,wheel_data),(sdist_modes,sdist_data)):
        if any(modes[n]!=0o644 for n in contents): raise Rejected('unexpected package file permissions')
        if any(mode!=0o755 for n,mode in modes.items() if n not in contents): raise Rejected('unexpected package directory permissions')
    return {str(p):{'sha256':sha(Path(p).read_bytes()),'files':{n:{'sha256':sha(d),'size':len(d),'mode':format(modes[n],'04o')} for n,d in sorted(contents.items())}} for p,contents,modes in ((wheel,wheel_data,wheel_modes),(sdist,sdist_data,sdist_modes))}


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',required=True);p.add_argument('--wheel',required=True);p.add_argument('--sdist',required=True);p.add_argument('--output',required=True);a=p.parse_args()
    result=verify(a.root,a.wheel,a.sdist)
    with open(a.output,'x') as f:json.dump(result,f,indent=2);f.write('\n')
