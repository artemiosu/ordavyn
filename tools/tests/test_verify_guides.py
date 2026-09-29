import json
from pathlib import Path
import shutil
import tempfile
import unittest

from tools.verify_guides import REQUIRED_GITHUB_FILES, verify_github_package


PROJECT_ROOT = Path(__file__).resolve().parents[2]


class GithubPackageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        for relative in REQUIRED_GITHUB_FILES:
            source = PROJECT_ROOT / relative
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)

    def tearDown(self):
        self.temporary.cleanup()

    def workflow(self, name):
        path = self.root / ".github/workflows" / name
        return path, json.loads(path.read_text())

    def assert_rejected(self, pattern):
        with self.assertRaisesRegex(ValueError, pattern):
            verify_github_package(self.root)

    def test_accepts_checked_in_package(self):
        verify_github_package(self.root)

    def test_rejects_missing_permissions(self):
        path, data = self.workflow("ci.yml")
        del data["permissions"]
        path.write_text(json.dumps(data))
        self.assert_rejected("top-level keys")

    def test_rejects_missing_job_permissions(self):
        path, data = self.workflow("ci.yml")
        del data["jobs"]["verify"]["permissions"]
        path.write_text(json.dumps(data))
        self.assert_rejected("jobs.verify keys")

    def test_rejects_quoted_yaml_trigger_spelling(self):
        path, _ = self.workflow("ci.yml")
        path.write_text('name: CI\n"on":\n  pull_request:\npermissions: {contents: read}\njobs: {}\n')
        self.assert_rejected("canonical JSON-subset YAML")

    def test_rejects_inline_yaml_trigger_spelling(self):
        path, _ = self.workflow("ci.yml")
        path.write_text("name: CI\non: [pull_request]\npermissions:\n  contents: read\njobs: {}\n")
        self.assert_rejected("canonical JSON-subset YAML")

    def test_rejects_alternate_indent_uses_spelling(self):
        path, _ = self.workflow("ci.yml")
        path.write_text("name: CI\non:\n  pull_request:\npermissions:\n  contents: read\njobs:\n  verify:\n   steps:\n    - uses: actions/checkout@v4\n")
        self.assert_rejected("canonical JSON-subset YAML")

    def test_rejects_mutable_action(self):
        path, data = self.workflow("ci.yml")
        data["jobs"]["verify"]["steps"][0]["uses"] = "actions/checkout@v4"
        path.write_text(json.dumps(data))
        self.assert_rejected(r"steps\[0\]\.uses")

    def test_rejects_bracket_secret(self):
        path, data = self.workflow("ci.yml")
        data["jobs"]["verify"]["steps"].append({"run": "echo ${{ secrets['TOKEN'] }}"})
        path.write_text(json.dumps(data))
        self.assert_rejected("token or secret reference")

    def test_rejects_github_token(self):
        path, data = self.workflow("ci.yml")
        data["jobs"]["verify"]["steps"].append({"run": "echo ${{ github.token }}"})
        path.write_text(json.dumps(data))
        self.assert_rejected("token or secret reference")

    def test_rejects_bracket_github_token(self):
        path, data = self.workflow("ci.yml")
        data["jobs"]["verify"]["steps"].append({"run": "echo ${{ github['token'] }}"})
        path.write_text(json.dumps(data))
        self.assert_rejected("token or secret reference")

    def test_rejects_misplaced_security_events_write(self):
        path, data = self.workflow("codeql.yml")
        data["permissions"]["security-events"] = "write"
        path.write_text(json.dumps(data))
        self.assert_rejected("unsafe permissions")

    def test_rejects_unreviewed_codeql_action(self):
        path, data = self.workflow("codeql.yml")
        data["jobs"]["analyze"]["steps"].insert(1, {"uses": "owner/action@1111111111111111111111111111111111111111"})
        path.write_text(json.dumps(data))
        self.assert_rejected("jobs.analyze.steps")

    def test_rejects_missing_required_file(self):
        (self.root / "CONTRIBUTING.md").unlink()
        self.assert_rejected("CONTRIBUTING.md")

    def test_rejects_empty_issue_form(self):
        (self.root / ".github/ISSUE_TEMPLATE/bug.yml").write_text("{}")
        self.assert_rejected("top-level keys")

    def test_rejects_personal_data_issue_field(self):
        path = self.root / ".github/ISSUE_TEMPLATE/feature.yml"
        data = json.loads(path.read_text())
        data["body"].append({"type": "input", "id": "email", "attributes": {"label": "Email"}, "validations": {"required": True}})
        path.write_text(json.dumps(data))
        self.assert_rejected(r"body\[4\]\.id")


if __name__ == "__main__":
    unittest.main()
