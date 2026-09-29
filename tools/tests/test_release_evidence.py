"""Adversarial checks for missing evidence and package/runner failures."""
import base64
import csv
import io
import os
import json
from pathlib import Path
import shutil
import sys
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import URLError
import zipfile

sys.path.insert(0,str(Path(__file__).parents[1]))
import audit_dependencies as audit
import release_candidate as rc
import verify_candidate as runner
import verify_packages as packages


class EvidenceTests(unittest.TestCase):
    def test_unavailable_official_source_is_unknown(self):
        with patch.object(audit.urllib.request,'urlopen',side_effect=URLError('unavailable')):
            result=audit.fetch('https://pypi.org/pypi/cbor2/5.9.0/json')
        self.assertEqual(result['status'],'UNKNOWN')
        self.assertNotIn('data',result)

    def test_rustsec_archive_requires_provenance_and_freshness(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'archive';meta=Path(temp)/'provenance.json';path.write_bytes(b'archive')
            self.assertEqual(audit.rustsec_evidence(path,meta)['status'],'UNKNOWN')
            commit='a'*40
            meta.write_text(json.dumps({'commit':commit,'url':'https://api.github.com/repos/RustSec/advisory-db/tarball/'+commit,'sha256':rc.sha(b'archive')}))
            self.assertEqual(audit.rustsec_evidence(path,meta,commit)['status'],'LOCAL_DECLARATION')
            self.assertEqual(audit.rustsec_evidence(path,meta,commit)['freshness'],'UNKNOWN')
            with patch.object(audit.urllib.request,'urlopen',return_value=io.BytesIO(b'archive')):
                self.assertEqual(audit.rustsec_evidence(path,meta,commit,online=True)['freshness'],'CURRENT_HEAD')
            with patch.object(audit.urllib.request,'urlopen',return_value=io.BytesIO(b'forged')):
                self.assertEqual(audit.rustsec_evidence(path,meta,commit,online=True)['status'],'UNKNOWN')
            self.assertEqual(audit.rustsec_evidence(path,meta,'b'*40)['freshness'],'UNKNOWN')
            path.write_bytes(b'tampered')
            self.assertEqual(audit.rustsec_evidence(path,meta,commit)['status'],'UNKNOWN')

    def test_failed_runner_never_writes_success(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)/'source';root.mkdir();(root/'x').write_bytes(b'changed')
            manifest=Path(temp)/'manifest.json';manifest.write_text(json.dumps({'files':[{'path':'x','sha256':rc.sha(b'expected'),'mode':'0644'}]}))
            output=Path(temp)/'output'
            with self.assertRaises(ValueError):runner.run_verification(root,manifest,output,Path(temp))
            self.assertFalse((output/'result.json').exists())

    def test_failed_command_never_writes_success(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)/'source';root.mkdir()
            manifest=Path(temp)/'manifest.json';manifest.write_text(json.dumps({'files':[]}))
            output=Path(temp)/'output'
            with patch.object(runner,'bind_source',return_value=('a'*40,'b'*64)), patch.object(runner,'locked_wheels',return_value=({},{})), patch.object(runner,'environment_inventory',return_value={}), patch.object(runner.sys,'version_info',(3,13,15)), patch.object(runner.platform,'system',return_value='Linux'), patch.object(runner.platform,'machine',return_value='x86_64'), patch.object(runner.subprocess,'run',side_effect=subprocess.CalledProcessError(1,['cargo'])):
                with self.assertRaises(subprocess.CalledProcessError):runner.run_verification(root,manifest,output,Path(temp))
            self.assertFalse((output/'result.json').exists())

    def test_environment_removes_hostile_overrides(self):
        with tempfile.TemporaryDirectory() as temp:
            bad={'PYTEST_ADDOPTS':'-k absent','PYTHONPATH':'/bad','PYTEST_PLUGINS':'bad','RUSTFLAGS':'--cfg bad','RUSTC_WRAPPER':'/bad','CC':'/bad','PIP_CONFIG_FILE':'/bad','CARGO_HOME':'/bad','CARGO_ENCODED_RUSTFLAGS':'bad','ORDAVYN_INTEROP_PEER':'/bad'}
            with patch.dict(os.environ,bad): env=runner.controlled_environment(Path(temp),Path(temp))
            for key in bad:
                if key in ('CARGO_HOME','PIP_CONFIG_FILE'): self.assertNotEqual(env[key],bad[key])
                else: self.assertNotIn(key,env)
            self.assertEqual(env['PYTEST_DISABLE_PLUGIN_AUTOLOAD'],'1')

    def test_suite_counts_fail_closed(self):
        self.assertEqual(runner.suite_summary(['python','test_conformance.py'],'249 passed\n154 passed')['passed'],[249,154])
        for text in ('1 passed','249 passed\n154 passed, 1 deselected','249 passed\n153 passed, 1 skipped'):
            with self.assertRaises(rc.Rejected):runner.suite_summary(['python','test_conformance.py'],text)
        with self.assertRaises(rc.Rejected):runner.suite_summary(['python','-m','unittest'],'Ran 0 tests\n\nOK\n')
        with self.assertRaises(rc.Rejected):runner.suite_summary(['cargo','test'],'test result: ok. 95 passed; 0 failed; 1 ignored')

    def test_rustsec_real_toml_multiple_versions_and_unknown(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'advisories.tar.gz'
            cases={'fixed':('>=1.2.3',False),'partial':('>1.2',False),'prerelease':('>=1.0.0-preview.foo',False),'build':('>=1.2.3+build',False),'withdrawn':('>=9.0.0',True),'partial_equal':('=1.2',False),'caret_zero':('^0',False)}
            with tarfile.open(path,'w:gz') as archive:
                for ident,(expr,withdrawn) in cases.items():
                    text='```toml\n[advisory]\nid="'+ident+'"\npackage="demo"\n'+('withdrawn="2026-01-01"\n' if withdrawn else '')+'[versions]\npatched=["'+expr+'"]\n```\n'
                    data=text.encode();item=tarfile.TarInfo('db/crates/demo/'+ident+'.md');item.size=len(data);archive.addfile(item,io.BytesIO(data))
                data=b'```toml\ninvalid = [\n```';item=tarfile.TarInfo('db/crates/demo/broken.md');item.size=len(data);archive.addfile(item,io.BytesIO(data))
            result=audit.rustsec_matches({'package':[{'name':'demo','version':'1.2.2'},{'name':'demo','version':'1.2.3'}]},path)
            statuses={(e.get('id'),e.get('version')):e['status'] for e in result}
            self.assertEqual(statuses['fixed','1.2.2'],'BLOCKER');self.assertEqual(statuses['fixed','1.2.3'],'NOT_AFFECTED')
            for ident in ('partial','prerelease','build','partial_equal','caret_zero'):
                self.assertEqual(statuses[ident,'1.2.3'],'UNKNOWN')
            self.assertEqual(statuses['withdrawn','1.2.2'],'WITHDRAWN')
            self.assertTrue(any(e.get('path','').endswith('broken.md') and e['status']=='UNKNOWN' for e in result))

    def test_missing_and_tampered_wheel_keeps_other_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);wheel=root/'demo-1.0.0-py3-none-any.whl'
            with zipfile.ZipFile(wheel,'w') as archive:
                archive.writestr('demo-1.0.0.dist-info/METADATA','Name: demo\nVersion: 1.0.0\nLicense-Expression: MIT OR Apache-2.0\n')
                archive.writestr('demo-1.0.0.dist-info/licenses/LICENSE','license bytes')
            lock=root/'lock';lock.write_text('demo==1.0.0 --hash=sha256:'+rc.sha(wheel.read_bytes())+'\nmissing==1.0.0 --hash=sha256:'+'0'*64+'\n')
            self.assertEqual(audit.python_wheel_evidence(lock,root,'missing','1.0.0')['status'],'UNKNOWN')
            evidence=audit.python_wheel_evidence(lock,root,'demo','1.0.0')
            self.assertEqual(evidence['status'],'HASH_VERIFIED_WHEEL');self.assertEqual(evidence['license_expression'],'MIT OR Apache-2.0')
            self.assertEqual(evidence['notices'][0]['sha256'],rc.sha(b'license bytes'))
            self.assertEqual(audit.python_wheel_evidence(lock,root,'demo','2.0.0')['status'],'UNKNOWN')
            wheel.write_bytes(wheel.read_bytes()+b'tampered')
            self.assertEqual(audit.python_wheel_evidence(lock,root,'demo','1.0.0')['status'],'UNKNOWN')

    def test_environment_inventory_handles_builtin_extensions(self):
        with tempfile.TemporaryDirectory() as temp:
            env=runner.controlled_environment(Path(temp),Path(temp))
            with patch.object(runner.subprocess,'check_output',side_effect=FileNotFoundError):
                result=runner.environment_inventory(env)
            self.assertIn('_ssl',result['runtime_extensions'])
            self.assertEqual(result['binaries']['toolchain_rustc']['status'],'UNKNOWN')

    def test_installed_build_input_tampering(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);site=root/'site';site.mkdir();wheel=root/'demo.whl'
            with zipfile.ZipFile(wheel,'w') as archive:archive.writestr('demo.py',b'original')
            (site/'demo.py').write_bytes(b'original')
            wheels={'demo':{'wheel':str(wheel),'wheel_sha256':rc.sha(wheel.read_bytes())}}
            with patch.object(runner.subprocess,'check_output',return_value=str(site).encode()):
                self.assertIn('demo',runner.installed_inputs('python',wheels,{}))
                (site/'demo.py').write_bytes(b'tampered')
                with self.assertRaises(rc.Rejected):runner.installed_inputs('python',wheels,{})

    def test_audit_writes_partial_registry_without_installed_packages(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/'implementation').mkdir();(root/'release').mkdir()
            (root/'implementation/Cargo.lock').write_text('package=[]')
            (root/'release/verification-requirements.txt').write_text('missing==1.0.0 --hash=sha256:'+'0'*64+'\n')
            with patch.object(audit,'PUBLIC_PYTHON',{'missing':'1.0.0'}),patch.object(audit.subprocess,'check_output',side_effect=FileNotFoundError):
                report=audit.audit(root,root/'out',wheelhouse=root)
            self.assertEqual(report['python'][0]['status'],'UNKNOWN')
            self.assertTrue((root/'out/dependencies.json').is_file())



class PackageMutationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);sdk=self.root/'implementation/python-sdk'
        project=Path(__file__).resolve().parents[2]
        shutil.copytree(project/'implementation/python-sdk',sdk,ignore=shutil.ignore_patterns('__pycache__','build','dist','*.egg-info','tests'))
        (self.root/'release').mkdir();shutil.copyfile(project/'release/files.json',self.root/'release/files.json')
        self.modules={str(p.relative_to(sdk)):p.read_bytes() for p in (sdk/'ordavyn').glob('*.py')}
        meta=packages.expected_metadata(sdk);prefix='ordavyn-0.1.0.dist-info/'
        self.wheel_data={**self.modules,prefix+'licenses/LICENSE':(sdk/'LICENSE').read_bytes(),prefix+'METADATA':meta,prefix+'WHEEL':b'Wheel-Version: 1.0\nGenerator: setuptools (84.0.0)\nRoot-Is-Purelib: true\nTag: py3-none-any\n\n',prefix+'top_level.txt':b'ordavyn\n'}
        rows=[[n,'sha256='+base64.urlsafe_b64encode(bytes.fromhex(rc.sha(d))).rstrip(b'=').decode(),str(len(d))] for n,d in self.wheel_data.items()]
        rows.append([prefix+'RECORD','','']);record=io.StringIO();csv.writer(record).writerows(rows);self.wheel_data[prefix+'RECORD']=record.getvalue().encode()
        originals={n:(sdk/n).read_bytes() for n in ['LICENSE','MANIFEST.in','README.md','pyproject.toml','requirements.txt']};originals.update(self.modules)
        sources='\n'.join(sorted(originals,key=lambda x:('/' in x,x)))
        self.sdist_data={'ordavyn-0.1.0/'+n:d for n,d in {**originals,'PKG-INFO':meta,'setup.cfg':b'[egg_info]\ntag_build = \ntag_date = 0\n\n','ordavyn.egg-info/SOURCES.txt':sources.encode()}.items()}
        self.wheel=self.root/'candidate.whl';self.sdist=self.root/'candidate.tar.gz';self.write()

    def write(self):
        with zipfile.ZipFile(self.wheel,'w') as z:
            for name,data in self.wheel_data.items():
                item=zipfile.ZipInfo(name);item.external_attr=((0o100664 if name.endswith('.dist-info/RECORD') else 0o100644)<<16);z.writestr(item,data)
        with tarfile.open(self.sdist,'w:gz') as t:
            for name,data in self.sdist_data.items():
                item=tarfile.TarInfo(name);item.size=len(data);t.addfile(item,io.BytesIO(data))

    def verify(self):return packages.verify(self.root,self.wheel,self.sdist)

    def test_control_package_and_injected_wheel_file(self):
        self.verify()
        self.wheel_data['unexpected.py']=b'print("injected")';self.write()
        with self.assertRaises(rc.Rejected):self.verify()

    def test_changed_wheel_source(self):
        self.wheel_data['ordavyn/client.py']+=b'\n# changed';self.write()
        with self.assertRaises(rc.Rejected):self.verify()

    def test_changed_generated_metadata(self):
        self.sdist_data['ordavyn-0.1.0/PKG-INFO']+=b'\nchanged';self.write()
        with self.assertRaises(rc.Rejected):self.verify()

    def test_injected_sdist_file(self):
        self.sdist_data['ordavyn-0.1.0/secret.txt']=b'undisclosed';self.write()
        with self.assertRaises(rc.Rejected):self.verify()

    def test_changed_record(self):
        self.wheel_data['ordavyn-0.1.0.dist-info/RECORD']=b'';self.write()
        with self.assertRaises(rc.Rejected):self.verify()

    def test_wheel_permissions_mutation(self):
        with zipfile.ZipFile(self.wheel,'w') as archive:
            for name,data in self.wheel_data.items():
                item=zipfile.ZipInfo(name);item.external_attr=0o100666<<16;archive.writestr(item,data)
        with self.assertRaises(rc.Rejected):self.verify()

    def test_record_permission_is_exact(self):
        with zipfile.ZipFile(self.wheel,'w') as archive:
            for name,data in self.wheel_data.items():
                item=zipfile.ZipInfo(name);item.external_attr=0o100644<<16;archive.writestr(item,data)
        with self.assertRaises(rc.Rejected):self.verify()

    def test_sdist_permissions_and_directory_mutation(self):
        for directory in (False,True):
            with tarfile.open(self.sdist,'w:gz') as archive:
                if directory:
                    item=tarfile.TarInfo('ordavyn-0.1.0');item.type=tarfile.DIRTYPE;item.mode=0o777;archive.addfile(item)
                for name,data in self.sdist_data.items():
                    item=tarfile.TarInfo(name);item.size=len(data);item.mode=0o644 if directory else 0o666;archive.addfile(item,io.BytesIO(data))
            with self.assertRaises(rc.Rejected):self.verify()


if __name__=='__main__':unittest.main()
