"""Adversarial checks for missing evidence and package/runner failures."""
import base64
import csv
import io
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
            self.assertEqual(audit.rustsec_evidence(path,meta,commit)['freshness'],'CURRENT_HEAD')
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
            with patch.object(runner.sys,'version_info',(3,13,15)), patch.object(runner.platform,'system',return_value='Linux'), patch.object(runner.platform,'machine',return_value='x86_64'), patch.object(runner.subprocess,'run',side_effect=subprocess.CalledProcessError(1,['cargo'])):
                with self.assertRaises(subprocess.CalledProcessError):runner.run_verification(root,manifest,output,Path(temp))
            self.assertFalse((output/'result.json').exists())



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
            for name,data in self.wheel_data.items():z.writestr(name,data)
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


if __name__=='__main__':unittest.main()
