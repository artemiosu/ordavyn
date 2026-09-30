import json
import importlib.util
import io
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("verify_guides", PROJECT_ROOT / "tools/verify_guides.py")
VERIFY_GUIDES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY_GUIDES)
REQUIRED_GITHUB_FILES = VERIFY_GUIDES.REQUIRED_GITHUB_FILES
verify_github_package = VERIFY_GUIDES.verify_github_package
run_quickstart_demo = VERIFY_GUIDES._run_quickstart_demo


class GithubPackageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        for relative in REQUIRED_GITHUB_FILES:
            source = PROJECT_ROOT / relative
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        for relative in VERIFY_GUIDES.conformance_evidence_paths(PROJECT_ROOT):
            source = PROJECT_ROOT / relative
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            if not target.exists():
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
        with redirect_stdout(io.StringIO()):
            verify_github_package(self.root)

    def test_accepts_explicit_unsupported_spec_row(self):
        path=self.root/"spec/CONFORMANCE.md";text=path.read_text();row=VERIFY_GUIDES._spec_rows(self.root)[0]
        path.write_text(text.replace(f"| implemented | `{row[2]}` | `{row[3]}` |","| unsupported | — | — |",1))
        with redirect_stdout(io.StringIO()):verify_github_package(self.root)

    def test_rejects_uncollected_spec_selector(self):
        table=self.root/"spec/CONFORMANCE.md"
        table.write_text(table.read_text().replace("::test_frozen_vectors","::helper_case",1))
        evidence=self.root/"implementation/python-sdk/tests/test_interop.py"
        evidence.write_text(evidence.read_text()+"\ndef helper_case(): pass\n")
        self.assert_rejected("selector")

    def test_checked_in_quickstart_prints_documented_result(self):
        with redirect_stdout(io.StringIO()):
            run_quickstart_demo(PROJECT_ROOT)

    def test_demo_success_checks_survive_optimized_python(self):
        environment = os.environ.copy()
        environment.pop("PYTHONPATH", None)
        result = subprocess.run(
            [sys.executable, "-O", str(PROJECT_ROOT / "implementation/demo/demo_multi.py")],
            cwd=PROJECT_ROOT,
            env=environment,
            check=True,
            capture_output=True,
            text=True,
            timeout=20,
        )
        self.assertEqual(result.stdout.strip().splitlines()[-1], VERIFY_GUIDES.QUICKSTART_OUTPUT)

    def test_quickstart_removes_pythonpath_bypass(self):
        hostile = self.root / "hostile"
        package = hostile / "ordavyn"
        package.mkdir(parents=True)
        (package / "__init__.py").write_text("raise RuntimeError('PYTHONPATH bypass used')\n")
        with patch.dict(os.environ, {"PYTHONPATH": str(hostile)}):
            with redirect_stdout(io.StringIO()):
                run_quickstart_demo(PROJECT_ROOT)

    def test_rejects_missing_readme_section(self):
        path = self.root / "README.md"
        path.write_text(path.read_text().replace("## Why Ordavyn", "## Motivation"))
        self.assert_rejected("missing required section")

    def test_rejects_missing_readme_evidence_link(self):
        path = self.root / "README.md"
        path.write_text(path.read_text().replace("](docs/LOCAL-THREAT-MODEL.md)", "](docs/missing.md)"))
        self.assert_rejected("missing evidence link")

    def test_rejects_stale_unpublished_repository_claim(self):
        path = self.root / "CONTRIBUTING.md"
        path.write_text(path.read_text() + "\nThis is an unpublished protocol.\n")
        self.assert_rejected("stale repository-publication claim")

    def test_rejects_quickstart_output_drift(self):
        path = self.root / "README.md"
        path.write_text(path.read_text().replace(VERIFY_GUIDES.QUICKSTART_OUTPUT, "Unexpected output"))
        self.assert_rejected("documented quickstart output")

    def test_rejects_missing_pinned_verification_setup(self):
        path = self.root / "README.md"
        path.write_text(path.read_text().replace(VERIFY_GUIDES.VERIFICATION_REQUIREMENTS_INSTALL, "python -m pip install pytest"))
        self.assert_rejected("verification setup shell sequence")

    def test_rejects_out_of_order_quickstart_commands(self):
        path = self.root / "README.md"
        contents = path.read_text()
        first, second = VERIFY_GUIDES.QUICKSTART_SEQUENCE[3:5]
        path.write_text(contents.replace(first + "\n" + second, second + "\n" + first))
        self.assert_rejected("source quickstart shell sequence")

    def test_rejects_roadmap_without_independent_implementations(self):
        path = self.root / "ROADMAP.md"
        contents = path.read_text().replace("Independent implementations", "Reference implementations")
        path.write_text(contents.replace("independent implementations", "reference implementations"))
        self.assert_rejected("independent implementations")

    def test_rejects_removed_registry_publish_block(self):
        path = self.root / "implementation/ordavyn-core/Cargo.toml"
        path.write_text(path.read_text().replace("publish = false", "publish = true"))
        self.assert_rejected("registry publish block")

    def test_rejects_commented_cargo_publish_block(self):
        path = self.root / "implementation/ordavyn-core/Cargo.toml"
        path.write_text(path.read_text().replace("publish = false", "# publish = false"))
        self.assert_rejected("registry publish block")

    def test_rejects_commented_python_publish_classifier(self):
        path = self.root / "implementation/python-sdk/pyproject.toml"
        path.write_text(path.read_text().replace('    "Private :: Do Not Upload",', '    # "Private :: Do Not Upload",'))
        self.assert_rejected("registry publish block")

    def test_rejects_generic_blocked_publication_status(self):
        path = self.root / "tools/release_candidate.py"
        path.write_text(path.read_text() + "\n# Publication remains BLOCKED.\n")
        self.assert_rejected("stale repository-publication claim")

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

    def test_rejects_ci_pythonpath_source_bypass(self):
        path, data = self.workflow("ci.yml")
        data["jobs"]["verify"]["env"] = {"PYTHONPATH": "implementation/python-sdk"}
        path.write_text(json.dumps(data))
        self.assert_rejected("jobs.verify keys")

    def test_rejects_missing_ordinary_source_install_smoke(self):
        path, data = self.workflow("ci.yml")
        del data["jobs"]["verify"]["steps"][2]
        path.write_text(json.dumps(data))
        self.assert_rejected("ordinary source install smoke test")

    def test_rejects_missing_checkout_sdk_install(self):
        path, data = self.workflow("ci.yml")
        del data["jobs"]["verify"]["steps"][4]
        path.write_text(json.dumps(data))
        self.assert_rejected("checkout SDK install")

    def test_rejects_checkout_sdk_install_with_dependency_resolution(self):
        path, data = self.workflow("ci.yml")
        data["jobs"]["verify"]["steps"][4]["run"] = "python -m pip install ./implementation/python-sdk"
        path.write_text(json.dumps(data))
        self.assert_rejected("checkout SDK install")

    def test_rejects_rust_warmup_after_offline_suite(self):
        path, data = self.workflow("ci.yml")
        steps = data["jobs"]["verify"]["steps"]
        warmup = steps.pop(6)
        steps.insert(10, warmup)
        path.write_text(json.dumps(data))
        self.assert_rejected("locked Rust dependency warm-up order")

    def test_rejects_rust_warmup_after_repository_checks(self):
        path, data = self.workflow("ci.yml")
        steps = data["jobs"]["verify"]["steps"]
        warmup = steps.pop(6)
        steps.insert(9, warmup)
        path.write_text(json.dumps(data))
        self.assert_rejected("locked Rust dependency warm-up order")

    def test_rejects_missing_rust_warmup(self):
        path, data = self.workflow("ci.yml")
        del data["jobs"]["verify"]["steps"][6]
        path.write_text(json.dumps(data))
        self.assert_rejected("locked Rust dependency warm-up")

    def test_rejects_duplicate_rust_warmup(self):
        path, data = self.workflow("ci.yml")
        steps = data["jobs"]["verify"]["steps"]
        steps.insert(7, dict(steps[6]))
        path.write_text(json.dumps(data))
        self.assert_rejected("locked Rust dependency warm-up")

    def test_rejects_duplicate_offline_command_replacing_other_required_command(self):
        path, data = self.workflow("ci.yml")
        steps = data["jobs"]["verify"]["steps"]
        steps[9]["run"] = steps[12]["run"]
        path.write_text(json.dumps(data))
        self.assert_rejected("required offline command occurrences")

    def test_rejects_missing_rust_examples_build(self):
        path, data = self.workflow("ci.yml")
        steps = data["jobs"]["verify"]["steps"]
        del steps[7]
        path.write_text(json.dumps(data))
        self.assert_rejected("locked offline Rust examples build")

    def test_rejects_duplicate_rust_examples_build(self):
        path, data = self.workflow("ci.yml")
        steps = data["jobs"]["verify"]["steps"]
        steps.insert(8, dict(steps[7]))
        path.write_text(json.dumps(data))
        self.assert_rejected("locked offline Rust examples build")

    def test_rejects_rust_examples_build_after_python_interoperability(self):
        path, data = self.workflow("ci.yml")
        steps = data["jobs"]["verify"]["steps"]
        example_build = steps.pop(7)
        steps.insert(11, example_build)
        path.write_text(json.dumps(data))
        self.assert_rejected("locked offline Rust examples build order")

    def test_rejects_missing_pinned_rustfmt_setup(self):
        path, data = self.workflow("ci.yml")
        del data["jobs"]["verify"]["steps"][5]
        path.write_text(json.dumps(data))
        self.assert_rejected("pinned rustfmt setup")

    def test_rejects_duplicate_pinned_rustfmt_setup(self):
        path, data = self.workflow("ci.yml")
        steps = data["jobs"]["verify"]["steps"]
        steps.insert(6, dict(steps[5]))
        path.write_text(json.dumps(data))
        self.assert_rejected("pinned rustfmt setup")

    def test_rejects_pinned_rustfmt_setup_after_format(self):
        path, data = self.workflow("ci.yml")
        steps = data["jobs"]["verify"]["steps"]
        setup = steps.pop(5)
        steps.insert(12, setup)
        path.write_text(json.dumps(data))
        self.assert_rejected("pinned rustfmt setup order")

    def test_rejects_extra_ci_command(self):
        path, data = self.workflow("ci.yml")
        data["jobs"]["verify"]["steps"].append({"name": "Extra", "run": "echo extra"})
        path.write_text(json.dumps(data))
        self.assert_rejected("reviewed CI steps")

    def test_rejects_disabled_required_ci_step(self):
        path, data = self.workflow("ci.yml")
        data["jobs"]["verify"]["steps"][8]["if"] = False
        path.write_text(json.dumps(data))
        self.assert_rejected("reviewed CI steps")

    def test_rejects_continue_on_error_required_ci_step(self):
        path, data = self.workflow("ci.yml")
        data["jobs"]["verify"]["steps"][8]["continue-on-error"] = True
        path.write_text(json.dumps(data))
        self.assert_rejected("reviewed CI steps")

    def test_rejects_security_policy_without_private_advisory_form(self):
        path = self.root / "SECURITY.md"
        path.write_text(path.read_text().replace("security/advisories/new", "issues/new"))
        self.assert_rejected("security/advisories/new")

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
