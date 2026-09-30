import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location("export_release",ROOT/"tools/export_release.py")
export=importlib.util.module_from_spec(spec);spec.loader.exec_module(export)


class ExportCheckTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.git("init","-q");self.git("config","user.name","Test");self.git("config","user.email","test@example.invalid")
        (self.root/"release").mkdir();(self.root/"README.md").write_text("public\n")
        self.policy={"README.md":{"action":"include","reason":"fixture"},"release/files.json":{"action":"include","reason":"fixture"}}
        self.write();self.git("add",".");self.git("commit","-qm","base")
    def git(self,*args):return subprocess.check_output(["git","-C",str(self.root),*args])
    def write(self):(self.root/"release/files.json").write_text(json.dumps({"schema":1,"files":self.policy}))
    def test_accepts_complete_source_only_classification(self):self.assertEqual(export.check(self.root),2)
    def test_rejects_unclassified_tracked_and_untracked(self):
        for name,tracked in (("tracked",True),("untracked",False)):
            path=self.root/(name+".txt");path.write_text("x")
            if tracked:self.git("add",path.name)
            with self.subTest(name=name),self.assertRaises(export.Rejected):export.check(self.root)
            if tracked:self.git("rm","--cached",path.name)
            path.unlink()
    def test_rejects_stale_extra(self):
        self.policy["missing"]={"action":"include","reason":"stale"};self.write()
        with self.assertRaises(export.Rejected):export.check(self.root)
    def test_rejects_private_path_even_if_classified(self):
        path=self.root/"private.txt";path.write_text("x");self.git("add","private.txt")
        self.policy["private.txt"]={"action":"include","reason":"fixture"};self.write()
        path.write_text("-----BEGIN PRIVATE " + "KEY-----\nx")
        with self.assertRaises(export.Rejected):export.check(self.root)
    def test_rejects_deployment_certificate_extensions(self):
        for suffix in (".crt",".cer",".der"):
            name="deployment"+suffix;path=self.root/name;path.write_bytes(b"certificate")
            self.git("add",name);self.policy[name]={"action":"include","reason":"fixture"};self.write()
            with self.subTest(suffix=suffix),self.assertRaisesRegex(export.Rejected,"certificate extension"):
                export.check(self.root)
            self.git("rm","--cached",name);path.unlink();del self.policy[name];self.write()
    def test_rejects_former_name_in_included_file(self):
        name="history.txt";path=self.root/name;path.write_text("agent"+"bridge")
        self.git("add",name);self.policy[name]={"action":"include","reason":"fixture"};self.write()
        with self.assertRaisesRegex(export.Rejected,"former name"):export.check(self.root)
    def test_rejects_symlink(self):
        link=self.root/"link";link.symlink_to("README.md");self.policy["link"]={"action":"exclude","reason":"fixture"};self.write()
        with self.assertRaisesRegex(export.Rejected,"symlink"):export.check(self.root)
    def test_rejects_submodule_mode(self):
        self.git("update-index","--add","--cacheinfo","160000,"+self.git("rev-parse","HEAD").decode().strip()+",module")
        self.policy["module"]={"action":"exclude","reason":"fixture"};self.write()
        with self.assertRaisesRegex(export.Rejected,"submodule"):export.check(self.root)
    def test_rejects_working_mode_mismatch(self):
        self.git("update-index","--chmod=+x","README.md")
        with self.assertRaisesRegex(export.Rejected,"mode differs"):export.check(self.root)


if __name__=="__main__":unittest.main()
