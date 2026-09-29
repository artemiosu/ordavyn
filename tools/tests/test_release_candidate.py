import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
import zipfile

spec = importlib.util.spec_from_file_location('release_candidate', Path(__file__).parents[1] / 'release_candidate.py')
rc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rc)


class CandidateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'repo'
        self.root.mkdir()
        self.git('init', '-q')
        self.git('config', 'user.name', 'Test')
        self.git('config', 'user.email', 'test@example.invalid')
        (self.root / 'release').mkdir()
        (self.root / 'file.txt').write_text('reviewed\n')
        self.policy = {'files': {n: {'action': 'include', 'reason': 'test fixture'} for n in ('file.txt', 'release/files.json')}}
        self.commit()

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.root), *args])

    def commit(self):
        (self.root / 'release/files.json').write_text(json.dumps(self.policy))
        self.git('add', '.')
        self.git('commit', '-qm', 'fixture')
        self.head = self.git('rev-parse', 'HEAD').decode().strip()

    def export(self, name='result'):
        return rc.export(self.root, self.head, Path(self.tmp.name) / name)

    def test_repeat_snapshot(self):
        first = self.export('one')
        second = self.export('two')
        self.assertEqual(first, second)
        self.assertEqual((Path(self.tmp.name)/'one/source.tar.gz').read_bytes(), (Path(self.tmp.name)/'two/source.tar.gz').read_bytes())
        self.assertEqual(first['commit'], self.head)
        with self.assertRaises(FileExistsError):
            self.export('one')

    def test_dirty_tracked(self):
        (self.root/'file.txt').write_text('changed')
        with self.assertRaises(rc.Rejected): self.export()

    def test_assume_unchanged_does_not_hide_edits(self):
        self.git('update-index','--assume-unchanged','file.txt')
        (self.root/'file.txt').write_text('hidden edit')
        self.assertEqual(self.git('status','--porcelain'),b'')
        with self.assertRaises(rc.Rejected):self.export()


    def test_untracked(self):
        (self.root/'extra.txt').write_text('extra')
        with self.assertRaises(rc.Rejected): self.export()

    def test_undeclared_tracked(self):
        (self.root/'extra.txt').write_text('extra')
        self.commit()
        with self.assertRaises(rc.Rejected): self.export()

    def test_missing_policy(self):
        self.git('rm', 'release/files.json')
        self.git('commit', '-qm', 'remove policy')
        self.head = self.git('rev-parse','HEAD').decode().strip()
        with self.assertRaises(rc.Rejected): self.export()

    def test_symlink(self):
        (self.root/'link').symlink_to('file.txt')
        self.policy['files']['link'] = {'action':'include','reason':'fixture'}
        self.commit()
        with self.assertRaises(rc.Rejected): self.export()

    def test_private_and_secret(self):
        for name, data in [('state.sqlite', b'x'), ('.private/data', b'x'), ('secret.txt', b'-----BEGIN '+b'PRIVATE KEY-----\nsecret')]:
            with self.subTest(name=name), self.assertRaises(rc.Rejected): rc.inspect_content(name, data)

    def test_reviewed_github_path_is_public_but_other_hidden_paths_are_private(self):
        rc.inspect_content('.github/workflows/ci.yml', b'name: CI\n')
        for name in ('.github/.private/data', '.other/config.yml'):
            with self.subTest(name=name), self.assertRaises(rc.Rejected):
                rc.inspect_content(name, b'x')

    def test_paths(self):
        for path in ('../x', '/x', 'a/../x', 'a//x', './x', 'a\\x'):
            with self.subTest(path=path), self.assertRaises(rc.Rejected): rc.safe_path(path)

    def test_archive_duplicate_traversal_symlink(self):
        dest = Path(self.tmp.name)/'bad.tar'
        for names in [('x','x'), ('../x',), ('/x',), ('link',)]:
            with tarfile.open(dest,'w') as archive:
                for name in names:
                    info=tarfile.TarInfo(name)
                    if name=='link': info.type=tarfile.SYMTYPE; info.linkname='x'
                    else: info.size=1
                    archive.addfile(info,io.BytesIO(b'x'))
            with self.subTest(names=names), self.assertRaises(rc.Rejected): rc.archive_entries(dest)

    def test_full_content_and_list_validation(self):
        dest=Path(self.tmp.name)/'test.zip'
        with zipfile.ZipFile(dest,'w') as archive: archive.writestr('x',b'actual')
        with self.assertRaises(rc.Rejected): rc.verify_archive(dest,{'x':rc.sha(b'changed')})
        with self.assertRaises(rc.Rejected): rc.verify_archive(dest,{'y':rc.sha(b'actual')})
        self.assertEqual(rc.verify_archive(dest,{'x':rc.sha(b'actual')}),{'x':b'actual'})

    def test_excluded_file(self):
        self.policy['files']['file.txt']={'action':'exclude','reason':'explicit administrative exclusion'}
        self.commit()
        self.assertEqual([x['path'] for x in self.export()['files']],['release/files.json'])

    def test_archive_mode_tampering(self):
        result=self.export()
        path=Path(self.tmp.name)/'result/source.tar.gz'
        rc.verify_source(path,result)
        result['files'][0]['mode']='0755'
        with self.assertRaises(rc.Rejected):rc.verify_source(path,result)

    def test_zip_symlink_and_duplicate(self):
        import warnings
        path=Path(self.tmp.name)/'bad.zip'
        with zipfile.ZipFile(path,'w') as archive:
            link=zipfile.ZipInfo('link');link.external_attr=0o120777 << 16
            archive.writestr(link,b'target')
        with self.assertRaises(rc.Rejected):rc.archive_entries(path)
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            with zipfile.ZipFile(path,'w') as archive:
                archive.writestr('x',b'a');archive.writestr('x',b'b')
        with self.assertRaises(rc.Rejected):rc.archive_entries(path)

    def test_unexplained_directory(self):
        path=Path(self.tmp.name)/'bad.tar'
        with tarfile.open(path,'w') as archive:
            info=tarfile.TarInfo('empty');info.type=tarfile.DIRTYPE;archive.addfile(info)
        with self.assertRaises(rc.Rejected):rc.archive_entries(path)

    def test_failed_export_has_no_success_marker(self):
        (self.root/'state.db').write_bytes(b'private')
        self.policy['files']['state.db']={'action':'include','reason':'fixture'}
        self.commit()
        with self.assertRaises(rc.Rejected):self.export()
        self.assertFalse((Path(self.tmp.name)/'result/COMPOSITION-PASS').exists())


    def test_export_preserves_history_without_exporting_it(self):
        (self.root/'file.txt').write_text('former-protocol-label')
        self.commit();historical=self.head
        (self.root/'file.txt').write_text('current-protocol-label')
        self.commit();history_before=self.git('rev-list','--all')
        self.export()
        members=rc.archive_entries(Path(self.tmp.name)/'result/source.tar.gz')
        self.assertFalse(any(name.startswith('.git/') for name in members))
        self.assertNotIn(b'former-protocol-label',b''.join(members.values()))
        self.assertEqual(self.git('show',historical+':file.txt'),b'former-protocol-label')
        self.assertEqual(self.git('rev-list','--all'),history_before)


    def test_old_snapshot_rejected(self):
        old=self.head
        (self.root/'file.txt').write_text('new')
        self.commit()
        with self.assertRaises(rc.Rejected): rc.export(self.root,old,Path(self.tmp.name)/'old')


class SourceBindingTests(unittest.TestCase):
    setUp=CandidateTests.setUp
    git=CandidateTests.git
    commit=CandidateTests.commit
    export=CandidateTests.export
    def test_trusted_git_binding_and_mutations(self):
        import verify_candidate as runner
        manifest=self.export();archive=Path(self.tmp.name)/'result/source.tar.gz'
        self.assertEqual(runner.bind_source(self.root,manifest,archive,self.root,self.head)[0],self.head)
        import copy
        for field,value in [('commit','0'*40),('source_sha256','0'*64)]:
            changed=copy.deepcopy(manifest);changed[field]=value
            with self.assertRaises(ValueError):runner.bind_source(self.root,changed,archive,self.root,self.head)
        changed=copy.deepcopy(manifest);changed['files'].append(changed['files'][0])
        with self.assertRaises(ValueError):runner.bind_source(self.root,changed,archive,self.root,self.head)
        changed=copy.deepcopy(manifest);changed['files'][0]['size']+=1
        with self.assertRaises(ValueError):runner.bind_source(self.root,changed,archive,self.root,self.head)
        # A coherent attacker-created archive + manifest still must match Git.
        with tarfile.open(archive,'r:gz') as source: entries=[(m,source.extractfile(m).read()) for m in source]
        with tarfile.open(archive,'w:gz') as target:
            for item,data in entries:
                if item.name=='file.txt': data=b'forged!!\n';item.size=len(data)
                target.addfile(item,io.BytesIO(data))
        changed=copy.deepcopy(manifest);changed['source_sha256']=rc.sha(archive.read_bytes())
        for entry in changed['files']:
            if entry['path']=='file.txt':entry['sha256']=rc.sha(b'forged!!\n');entry['size']=len(b'forged!!\n')
        with self.assertRaises(ValueError):runner.bind_source(self.root,changed,archive,self.root,self.head)


if __name__=='__main__': unittest.main()
