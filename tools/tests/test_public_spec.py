import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location("verify_guides",ROOT/"tools/verify_guides.py")
verify=importlib.util.module_from_spec(spec);spec.loader.exec_module(verify)


class PublicSpecTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        shutil.copytree(ROOT/"spec",self.root/"spec")
        for relative in ("GOVERNANCE.md","README.md","ROADMAP.md","docs/RELEASE-STATUS.md",*verify.conformance_evidence_paths(ROOT)):
            target=self.root/relative;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/relative,target)
    def test_checked_in_spec_is_complete(self):verify.verify_public_spec(ROOT)
    def test_rejects_duplicate_or_missing_id(self):
        path=self.root/"spec/ORDAVYN-WIRE-V3.md";path.write_text(path.read_text()+"\n#### ORD-ENV-001 — duplicate\n")
        with self.assertRaises(ValueError):verify.verify_public_spec(self.root)
    def test_rejects_missing_selector(self):
        path=self.root/"spec/CONFORMANCE.md";path.write_text(path.read_text().replace("::strict_json_rejections","::not_a_test",1))
        with self.assertRaisesRegex(ValueError,"selector"):verify.verify_public_spec(self.root)
    def test_rejects_helper_comment_and_uncollected_selectors(self):
        cases=(
            ("::test_frozen_vectors","::helper_case","implementation/python-sdk/tests/test_interop.py","\ndef helper_case(): pass\n"),
            ("::test_frozen_vectors","::commented_case","implementation/python-sdk/tests/test_interop.py","\n# def commented_case(): pass\n"),
            ("::strict_json_rejections","::uncollected_case","implementation/ordavyn-core/tests/interop.rs","\nfn uncollected_case() {}\n"),
        )
        original=(self.root/"spec/CONFORMANCE.md").read_text()
        for old,new,relative,addition in cases:
            path=self.root/relative;source=path.read_text()
            (self.root/"spec/CONFORMANCE.md").write_text(original.replace(old,new,1));path.write_text(source+addition)
            with self.subTest(selector=new),self.assertRaisesRegex(ValueError,"selector"):
                verify.verify_public_spec(self.root)
            path.write_text(source)
    def test_accepts_explicit_unsupported_row(self):
        path=self.root/"spec/CONFORMANCE.md";text=path.read_text();row=verify._spec_rows(self.root)[0]
        old=f"| implemented | `{row[2]}` | `{row[3]}` |"
        path.write_text(text.replace(old,"| unsupported | — | — |",1))
        verify.verify_public_spec(self.root)
    def test_rejects_missing_evidence_class(self):
        path=self.root/"spec/CONFORMANCE.md";text=path.read_text();row=verify._spec_rows(self.root)[0]
        path.write_text(text.replace(f"`{row[3]}`",f"`{row[2]}`",1))
        with self.assertRaisesRegex(ValueError,"evidence classes"):verify.verify_public_spec(self.root)
    def test_rejects_unsupported_inventory_drift(self):
        path=self.root/"spec/CONFORMANCE.md";path.write_text(path.read_text().replace("- delegation\n",""))
        with self.assertRaisesRegex(ValueError,"inventory drift"):verify.verify_public_spec(self.root)


if __name__=="__main__":unittest.main()
