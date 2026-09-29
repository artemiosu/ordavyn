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
        from test_release_candidate import CandidateTests
        fixture=CandidateTests();fixture.setUp()
        try:
            fixture.export()
            base=Path(fixture.tmp.name);archive=base/'result/source.tar.gz';manifest=base/'result/manifest.json'
            for mutation in ('mutate','add','remove','symlink','chmod'):
                root=base/mutation;root.mkdir()
                with tarfile.open(archive) as source: source.extractall(root,filter='data')
                target=root/'file.txt'
                if mutation=='mutate': target.write_text('different')
                elif mutation=='add': (root/'extra').write_text('extra')
                elif mutation=='remove': target.unlink()
                elif mutation=='symlink': target.unlink();target.symlink_to(root/'release/files.json')
                else: target.chmod(0o755)
                output=base/('out-'+mutation)
                with patch.object(runner,'producer_binding') as producer:
                    with self.assertRaisesRegex(ValueError,'source.*manifest'):
                        runner.run_verification(root,manifest,output,base,archive,fixture.root,fixture.head)
                    producer.assert_not_called()
                self.assertFalse((output/'result.json').exists())
        finally: fixture.doCleanups()

    def test_failed_command_never_writes_success(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)/'source';root.mkdir()
            manifest=Path(temp)/'manifest.json';manifest.write_text(json.dumps({'files':[]}))
            output=Path(temp)/'output'
            with patch.object(runner,'producer_binding',return_value={}),patch.object(runner,'dependency_binding',return_value={}),patch.object(runner,'prepare_rust_inputs',return_value={}),patch.object(runner,'bind_source',return_value=('a'*40,'b'*64)), patch.object(runner,'locked_wheels',return_value=({},{})), patch.object(runner,'environment_inventory',return_value={}), patch.object(runner.sys,'version_info',(3,13,15)), patch.object(runner.platform,'system',return_value='Linux'), patch.object(runner.platform,'machine',return_value='x86_64'), patch.object(runner.subprocess,'run',side_effect=subprocess.CalledProcessError(1,['cargo'])):
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
        self.assertEqual(runner.suite_summary(['python','test_conformance.py'],'249 passed\n159 passed')['passed'],[249,159])
        self.assertEqual(runner.suite_summary(['cargo','test'],'test result: ok. 97 passed; 0 failed; 0 ignored')['passed'],97)
        for text in ('1 passed','249 passed\n159 passed, 1 deselected','249 passed\n158 passed, 1 skipped'):
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
            project=Path(__file__).parents[2]
            subprocess.run(['cargo','+1.98.1','build','--locked','--offline','--example','audit_semver'],cwd=project/'implementation',check=True)
            helper=project/'implementation/target/debug/examples/audit_semver'
            result=audit.rustsec_matches({'package':[{'name':'demo','version':'1.2.2'},{'name':'demo','version':'1.2.3'}]},path,helper)
            statuses={(e.get('id'),e.get('version')):e['status'] for e in result}
            self.assertEqual(statuses['fixed','1.2.2'],'BLOCKER');self.assertEqual(statuses['fixed','1.2.3'],'NOT_AFFECTED')
            for ident in ('prerelease','build','partial_equal'):
                self.assertEqual(statuses[ident,'1.2.3'],'NOT_AFFECTED')
            self.assertEqual(statuses['partial','1.2.3'],'BLOCKER')
            self.assertEqual(statuses['caret_zero','1.2.3'],'BLOCKER')
            self.assertEqual(statuses['withdrawn','1.2.2'],'WITHDRAWN')
            self.assertTrue(any(e.get('path','').endswith('broken.md') and e['status']=='UNKNOWN' for e in result))

            tampered=Path(temp)/'tampered-helper';shutil.copyfile(helper,tampered);tampered.chmod(0o755)
            tampered.write_bytes(b'not executable evidence')
            unknown=audit.rustsec_matches({'package':[{'name':'demo','version':'1.2.3'}]},path,tampered)
            self.assertTrue(all(e['status'] in ('UNKNOWN','WITHDRAWN') for e in unknown))

    def test_audit_builds_fresh_locked_semver_helper(self):
        project=Path(__file__).parents[2]
        with tempfile.TemporaryDirectory() as temp:
            helper,evidence=audit.prepare_semver_helper(project,Path(temp))
            self.assertTrue(helper.is_file())
            self.assertEqual(evidence['sha256'],rc.sha(helper.read_bytes()))
            self.assertTrue(evidence['archives'] and evidence['extracted_source_sha256'])
            self.assertEqual(audit.semver_matches(helper,[{'version':'1.2.3','requirements':['>=1.2','<1.2']}]),[[True,False]])
            helper.write_bytes(b'substituted')
            self.assertEqual(audit.semver_matches(helper,[{'version':'1.2.3','requirements':['>=1.2']}]),[None])

    def test_audit_resolves_relative_controlled_paths_before_changing_cwd(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            root=Path(temp);(root/'implementation').mkdir();(root/'release').mkdir()
            (root/'implementation/Cargo.lock').write_text('package = []\n')
            (root/'release/verification-requirements.txt').write_text('')
            relative=root.relative_to(Path.cwd())
            with patch.object(audit,'rustsec_evidence',return_value={'status':'UNKNOWN'}),patch.object(audit.subprocess,'check_output',side_effect=OSError):
                report=audit.audit(relative,relative/'relative-output',wheelhouse=relative)
            self.assertEqual(report['cargo'],[])
            self.assertTrue((root/'relative-output/dependencies.json').is_file())

    def test_verifier_rejects_mismatched_helper_binary_hash(self):
        with tempfile.TemporaryDirectory() as temp:
            helper=Path(temp)/'helper';helper.write_bytes(b'actual');helper.chmod(0o755)
            with self.assertRaisesRegex(rc.Rejected,'binary mismatch'):
                runner.verify_helper_binary(helper,{'semver_helper_sha256':rc.sha(b'other')})

    def test_helper_build_ignores_forged_host_registry_source_and_requires_archive(self):
        with tempfile.TemporaryDirectory() as temp:
            base=Path(temp);root=base/'root';output=base/'output';host=base/'host'
            (root/'implementation').mkdir(parents=True);output.mkdir();cache=host/'.cargo/registry/cache/index';cache.mkdir(parents=True)
            forged=host/'.cargo/registry/src/index/semver-1.0.28';forged.mkdir(parents=True)
            (forged/'src.rs').write_bytes(b'forged self-consistent source')
            archive=cache/'semver-1.0.28.crate';archive.write_bytes(b'verified archive bytes')
            lock={'package':[{'name':'semver','version':'1.0.28','source':'registry+https://github.com/rust-lang/crates.io-index','checksum':rc.sha(archive.read_bytes())}]}
            def build(args,cwd,env,**kwargs):
                copied=list((Path(env['CARGO_HOME'])/'registry/cache').glob('*/*.crate'))
                if not copied: raise subprocess.CalledProcessError(101,args)
                helper=Path(env['CARGO_TARGET_DIR'])/'debug/examples/audit_semver';helper.parent.mkdir(parents=True);helper.write_text('#!/bin/sh\nprintf \'[{"matches":[true,false]}]\\n\'\n');helper.chmod(0o755)
                source=Path(env['CARGO_HOME'])/'registry/src/index/semver-1.0.28';source.mkdir(parents=True);(source/'src.rs').write_bytes(b'from verified archive')
                return subprocess.CompletedProcess(args,0)
            controlled={'CARGO_HOME':str(host/'.cargo'),'RUSTUP_HOME':str(host/'.rustup')}
            with patch.dict(audit.os.environ,controlled),patch.object(audit.subprocess,'run',side_effect=build),patch.object(audit,'semver_matches',return_value=[[True,False]]):
                helper,evidence=audit.prepare_semver_helper(root,output,lock)
            self.assertTrue(helper.is_file())
            forged_digest=rc.sha(json.dumps([('src.rs',rc.sha(b'forged self-consistent source'))],separators=(',',':')).encode())
            self.assertNotEqual(evidence['extracted_source_sha256']['semver-1.0.28'],forged_digest)
            archive.unlink();empty=base/'empty';empty.mkdir()
            with patch.dict(audit.os.environ,controlled),patch.object(audit.subprocess,'run',side_effect=build),patch.object(audit,'semver_matches',return_value=[[True,False]]):
                with self.assertRaises(subprocess.CalledProcessError):audit.prepare_semver_helper(root,empty,lock)
            rows=audit.rustsec_matches({'package':[{'name':'demo','version':'1.0.0'}]},self._advisory_archive(base),None)
            self.assertTrue(all(row['status'] in ('UNKNOWN','WITHDRAWN') for row in rows))

    @staticmethod
    def _advisory_archive(base):
        path=base/'missing-helper-advisories.tar.gz'
        with tarfile.open(path,'w:gz') as archive:
            for ident,withdrawn in (('active',False),('withdrawn',True)):
                text='```toml\n[advisory]\nid="'+ident+'"\npackage="demo"\n'+('withdrawn="2026-01-01"\n' if withdrawn else '')+'[versions]\npatched=[">=2"]\n```\n'
                data=text.encode();item=tarfile.TarInfo('db/crates/demo/'+ident+'.md');item.size=len(data);archive.addfile(item,io.BytesIO(data))
        return path

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
            self.assertIn('not a complete binary dependency inventory',result['limitations'][0])
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

    def test_wrong_provenance_types_are_unknown(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'meta'
            for value in (None,[],42,{'commit':None},{'commit':[]}):
                path.write_text(json.dumps(value))
                self.assertEqual(audit.rustsec_evidence(path,path)['status'],'UNKNOWN')

    def test_real_cli_producer_binding_before_build(self):
        from test_release_candidate import CandidateTests
        fixture=CandidateTests();fixture.setUp()
        try:
            base=Path(fixture.tmp.name);(fixture.root/'tools').mkdir();(fixture.root/'implementation').mkdir()
            files=['tools/'+n+'.py' for n in ('verify_candidate','release_candidate','verify_packages','audit_dependencies')]
            for name in files:
                (fixture.root/name).write_bytes((Path(__file__).parents[2]/name).read_bytes())
            for name in ('implementation/Cargo.lock','release/verification-requirements.txt'):
                (fixture.root/name).write_text('fixture');files.append(name)
            for name in files: fixture.policy['files'][name]={'action':'include','reason':'fixture'}
            fixture.commit();fixture.export();source=base/'unpacked';source.mkdir()
            with tarfile.open(base/'result/source.tar.gz') as archive: archive.extractall(source,filter='data')
            report=base/'report.json';report.write_text('{}')
            result=subprocess.run([sys.executable,str(Path(runner.__file__).resolve()),'--root',str(source),'--repo',str(fixture.root),'--commit',fixture.head,'--archive',str(base/'result/source.tar.gz'),'--manifest',str(base/'result/manifest.json'),'--output',str(base/'out'),'--wheelhouse',str(base),'--dependency-report',str(report)],capture_output=True,text=True)
            self.assertNotEqual(result.returncode,0)
            self.assertIn('dependency report lock mismatch',result.stderr)
            self.assertNotIn('KeyError',result.stderr)
            self.assertFalse((base/'out/result.json').exists())
        finally: fixture.doCleanups()

    def test_producer_mismatch(self):
        with patch.object(runner,'git',return_value=b'other tool'):
            with self.assertRaisesRegex(rc.Rejected,'executing verifier'):runner.producer_binding('.', 'a'*40)

    def test_dependency_binding(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/'implementation').mkdir();(root/'release').mkdir()
            files={'implementation/Cargo.lock':b'cargo','release/verification-requirements.txt':b'python','tools/audit_dependencies.py':b'tool','implementation/ordavyn-core/Cargo.toml':b'manifest','implementation/ordavyn-core/examples/audit_semver.rs':b'helper source'}
            for name,data in files.items():
                p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
            binding={'source_commit':'a'*40,'locks':{n:rc.sha(files[n]) for n in ('implementation/Cargo.lock','release/verification-requirements.txt')},'producer':{n:rc.sha(files[n]) for n in ('tools/audit_dependencies.py','implementation/ordavyn-core/Cargo.toml','implementation/ordavyn-core/examples/audit_semver.rs')},'semver_helper':{'sha256':'1'*64}}
            report=root/'report';report.write_text(json.dumps({'binding':binding}))
            with patch.object(runner,'git',side_effect=lambda repo,command,ref:files[ref.split(':',1)[1]]):
                self.assertEqual(runner.dependency_binding(root,report,'.','b'*40)['lock_binding'],'IDENTICAL_LOCK_BYTES_OTHER_COMMIT')
                with patch.object(runner,'git',side_effect=lambda repo,command,ref: b'changed auditor' if ref=='b'*40+':tools/audit_dependencies.py' else files[ref.split(':',1)[1]]):
                    with self.assertRaisesRegex(rc.Rejected,'producer mismatch'):runner.dependency_binding(root,report,'.','b'*40)
                binding['locks']['implementation/Cargo.lock']='0'*64;report.write_text(json.dumps({'binding':binding}))
                with self.assertRaisesRegex(rc.Rejected,'lock mismatch'):runner.dependency_binding(root,report,'.','b'*40)
                binding['locks']['implementation/Cargo.lock']=rc.sha(b'cargo');binding['producer']={};report.write_text(json.dumps({'binding':binding}))
                with self.assertRaisesRegex(rc.Rejected,'producer mismatch'):runner.dependency_binding(root,report,'.','b'*40)
            with self.assertRaisesRegex(rc.Rejected,'required'):runner.dependency_binding(root,None,'.','b'*40)

    def test_verified_helper_reproduces_report_and_rejects_status_change(self):
        project=Path(__file__).parents[2]
        subprocess.run(['cargo','+1.98.1','build','--locked','--offline','--example','audit_semver'],cwd=project/'implementation',check=True)
        helper=project/'implementation/target/debug/examples/audit_semver'
        row={'package':'demo','version':'1.2.3','id':'TEST','status':'NOT_AFFECTED','advisory':{'advisory':{'id':'TEST','package':'demo'},'versions':{'patched':['>=1.2.3'],'unaffected':[]}}}
        with tempfile.TemporaryDirectory() as temp:
            report=Path(temp)/'report';report.write_text(json.dumps({'rustsec_matches':[row]}))
            self.assertEqual(runner.verify_semver_results(helper,report,os.environ)['status'],'REPRODUCED')
            row['status']='BLOCKER';report.write_text(json.dumps({'rustsec_matches':[row]}))
            with self.assertRaisesRegex(rc.Rejected,'result mismatch'):
                runner.verify_semver_results(helper,report,os.environ)

    def test_verifier_rejects_malformed_helper_response(self):
        row={'package':'demo','version':'1.2.3','id':'TEST','status':'NOT_AFFECTED','advisory':{'advisory':{'id':'TEST','package':'demo'},'versions':{'patched':['>=1.2.3'],'unaffected':[]}}}
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);report=root/'report';report.write_text(json.dumps({'rustsec_matches':[row]}))
            helper=root/'helper';helper.write_text('#!/bin/sh\nprintf \'[]\\n\'\n');helper.chmod(0o755)
            with self.assertRaisesRegex(rc.Rejected,'response mismatch'):
                runner.verify_semver_results(helper,report,os.environ)
            helper.write_text('#!/bin/sh\nprintf \'[{"matches":[1]}]\\n\'\n');helper.chmod(0o755)
            with self.assertRaisesRegex(rc.Rejected,'response mismatch'):
                runner.verify_semver_results(helper,report,os.environ)

    def test_own_installed_payload_tampering(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);wheel=root/'ordavyn.whl';site=root/'site';site.mkdir();(site/'ordavyn').mkdir()
            with zipfile.ZipFile(wheel,'w') as archive: archive.writestr('ordavyn/client.py',b'reviewed')
            (site/'ordavyn/client.py').write_bytes(b'tampered')
            with patch.object(runner.subprocess,'check_output',return_value=str(site).encode()):
                with self.assertRaisesRegex(rc.Rejected,'installed wheel bytes mismatch: ordavyn'):
                    runner.installed_inputs('python',{'ordavyn':{'wheel':str(wheel),'wheel_sha256':rc.sha(wheel.read_bytes())}},{})

    def test_ambiguous_and_unreadable_wheels_preserve_partial_audit(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/'implementation').mkdir();(root/'release').mkdir()
            (root/'implementation/Cargo.lock').write_text('package=[]')
            lines=[]
            for name in ('demo','valid','broken','unreadable'):
                wheel=root/(name+'.whl')
                if name=='broken': wheel.write_bytes(b'invalid zip')
                else:
                    with zipfile.ZipFile(wheel,'w') as archive:
                        archive.writestr(name+'-1.0.0.dist-info/METADATA','Name: '+name+'\nVersion: 1.0.0\n')
                lines.append(name+'==1.0.0 --hash=sha256:'+rc.sha(wheel.read_bytes()))
            shutil.copyfile(root/'demo.whl',root/'demo-copy.whl')
            (root/'release/verification-requirements.txt').write_text('\n'.join(lines)+'\n')
            original=Path.read_bytes
            def read(path):
                if path.name=='unreadable.whl': raise PermissionError('fixture')
                return original(path)
            with patch.object(Path,'read_bytes',read),patch.object(audit,'PUBLIC_PYTHON',{n:'1.0.0' for n in ('demo','valid','broken','unreadable')}),patch.object(audit.subprocess,'check_output',side_effect=FileNotFoundError):
                locked,found=audit.locked_wheels(root/'release/verification-requirements.txt',root)
                self.assertEqual(set(found),{'valid'})
                report=audit.audit(root,root/'out',wheelhouse=root)
            self.assertEqual({e['name']:e['status'] for e in report['python']},{'demo':'UNKNOWN','valid':'HASH_VERIFIED_WHEEL','broken':'UNKNOWN','unreadable':'UNKNOWN'})
            self.assertTrue((root/'out/dependencies.json').exists())

    def test_runner_rejects_own_payload_tamper_in_each_installation(self):
        from contextlib import ExitStack
        for damaged in ('wheel','sdist'):
            with self.subTest(installation=damaged),tempfile.TemporaryDirectory() as temp:
                base=Path(temp);root=base/'source';root.mkdir();output=base/'output'
                readme=root/'implementation/python-sdk/README.md';readme.parent.mkdir(parents=True);readme.write_text('```python\npass\n```')
                lock=root/'release/verification-requirements.txt';lock.parent.mkdir();lock.write_text('fixture')
                entries=[{'path':str(p.relative_to(root)),'sha256':rc.sha(p.read_bytes()),'mode':'0644'} for p in (readme,lock)]
                for p in (readme,lock): p.chmod(0o644)
                manifest=base/'manifest.json';manifest.write_text(json.dumps({'files':entries}))
                installed=[]
                def command(args,**kwargs):
                    if 'build' in args and '--outdir' in args:
                        packages=Path(args[args.index('--outdir')+1]);packages.mkdir()
                        with zipfile.ZipFile(packages/'ordavyn-0.1.0-py3-none-any.whl','w') as archive: archive.writestr('ordavyn/client.py',b'original')
                        (packages/'ordavyn-0.1.0.tar.gz').write_bytes(b'sdist fixture')
                    if '--no-build-isolation' in args:
                        kind=Path(args[0]).parents[1].name;installed.append(kind)
                        site=output/kind/'site/ordavyn';site.mkdir(parents=True)
                        (site/'client.py').write_bytes(b'tampered' if kind==damaged else b'original')
                    return subprocess.CompletedProcess(args,0)
                def site_query(args,**kwargs):
                    return str(Path(args[0]).parents[1]/'site').encode()
                with ExitStack() as stack:
                    for name,value in {'bind_source':('a'*40,'b'*64),'producer_binding':{},'dependency_binding':{},'locked_wheels':({},{}),'prepare_rust_inputs':{},'environment_inventory':{},'verify':{},'suite_summary':None}.items():
                        stack.enter_context(patch.object(runner,name,return_value=value))
                    stack.enter_context(patch.object(runner.sys,'version_info',(3,13,15)))
                    stack.enter_context(patch.object(runner.platform,'system',return_value='Linux'))
                    stack.enter_context(patch.object(runner.platform,'machine',return_value='x86_64'))
                    stack.enter_context(patch.object(runner.platform,'platform',return_value='test platform'))
                    stack.enter_context(patch.object(runner.subprocess,'run',side_effect=command))
                    stack.enter_context(patch.object(runner.subprocess,'check_output',side_effect=site_query))
                    with self.assertRaisesRegex(rc.Rejected,'installed wheel bytes mismatch: ordavyn'):
                        runner.run_verification(root,manifest,output,base)
                self.assertEqual(installed,['wheel'] if damaged=='wheel' else ['wheel','sdist'])
                self.assertFalse((output/'result.json').exists())

    def test_rust_inputs_use_verified_archive_and_fresh_source(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/'implementation').mkdir();cache=root/'.cargo/registry/cache/index';cache.mkdir(parents=True)
            crate=cache/'demo-1.0.0.crate'
            with tarfile.open(crate,'w:gz') as tar:
                item=tarfile.TarInfo('demo-1.0.0/Cargo.toml');data=b'reviewed';item.size=len(data);tar.addfile(item,io.BytesIO(data))
            (root/'implementation/Cargo.lock').write_text('[[package]]\nname="demo"\nversion="1.0.0"\nsource="registry+https://github.com/rust-lang/crates.io-index"\nchecksum="'+rc.sha(crate.read_bytes())+'"\n')
            output=root/'out';output.mkdir()
            with patch.object(runner.Path,'home',return_value=root): env=runner.controlled_environment(output,root)
            self.assertFalse((Path(env['CARGO_HOME'])/'registry/src').exists())
            source=Path(env['CARGO_HOME'])/'registry/src/index/demo-1.0.0';source.mkdir(parents=True);(source/'Cargo.toml').write_bytes(b'reviewed')
            graph={'resolve':{'nodes':[{'id':'demo'}]},'packages':[{'id':'demo','name':'demo','version':'1.0.0','source':'registry','manifest_path':str(source/'Cargo.toml')}]}
            with patch.object(runner.Path,'home',return_value=root),patch.object(runner.subprocess,'check_output',return_value=json.dumps(graph).encode()):
                result=runner.prepare_rust_inputs(root,env)
                self.assertEqual(result['components'][0]['archive_sha256'],rc.sha(crate.read_bytes()))
                (source/'Cargo.toml').write_bytes(b'altered')
                with self.assertRaisesRegex(rc.Rejected,'payload mismatch'):runner.prepare_rust_inputs(root,env)
                crate.write_bytes(b'wrong checksum')
                with self.assertRaisesRegex(rc.Rejected,'lacks verified archive'):runner.prepare_rust_inputs(root,env)

    def test_cargo_cache_and_allowlist_drift(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/'implementation').mkdir();(root/'release').mkdir()
            cache=root/'.cargo/registry/cache/test';cache.mkdir(parents=True)
            source=root/'.cargo/registry/src/test/demo-1.0.0';source.mkdir(parents=True)
            archive=cache/'demo-1.0.0.crate'
            with tarfile.open(archive,'w:gz') as tar:
                for name,data in {'Cargo.toml':b'[package]\nname="demo"\nversion="1.0.0"\nlicense="MIT"\n','lib.rs':b'original','LICENSE':b'notice'}.items():
                    item=tarfile.TarInfo('demo-1.0.0/'+name);item.size=len(data);tar.addfile(item,io.BytesIO(data));(source/name).write_bytes(data)
            (source/'lib.rs').write_bytes(b'altered')
            (source/'.cargo-checksum.json').write_text(json.dumps({'files':{'lib.rs':rc.sha(b'altered')}}))
            (source/'Cargo.toml').write_text('not valid TOML [')
            (root/'implementation/Cargo.lock').write_text('[[package]]\nname="demo"\nversion="1.0.0"\nsource="registry+https://github.com/rust-lang/crates.io-index"\nchecksum="'+rc.sha(archive.read_bytes())+'"\n')
            (root/'release/verification-requirements.txt').write_text('unreviewed==1.0.0 --hash=sha256:'+'0'*64+'\n')
            with patch.object(audit.Path,'home',return_value=root),patch.object(audit.subprocess,'check_output',side_effect=FileNotFoundError),patch.object(audit,'fetch',return_value={'status':'UNKNOWN'}) as network:
                report=audit.audit(root,root/'out',online=True,wheelhouse=root)
            self.assertEqual(report['cargo'][0]['archive_status'],'MATCH')
            self.assertEqual(report['cargo'][0]['source_file_checks'],'MISMATCH')
            self.assertEqual(report['cargo'][0]['license_expression'],'MIT')
            self.assertEqual(report['python_allowlist_status'],'BLOCKED')
            self.assertTrue(any(e['name']=='unreviewed' and e['status']=='UNKNOWN' for e in report['python']))
            self.assertFalse(any('unreviewed' in str(c) for c in network.call_args_list))




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
