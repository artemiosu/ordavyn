#!/usr/bin/env python3
"""Execute documented snippets with disposable journals and TLS test certificates."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


REQUIRED_GITHUB_FILES = {
    ".github/workflows/ci.yml",
    ".github/workflows/codeql.yml",
    ".github/ISSUE_TEMPLATE/bug.yml",
    ".github/ISSUE_TEMPLATE/feature.yml",
    ".github/ISSUE_TEMPLATE/config.yml",
    ".github/pull_request_template.md",
    ".github/FUNDING.yml",
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
    "SECURITY.md",
    "CHANGELOG.md",
}
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
CHECKOUT = "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683"
SETUP_PYTHON = "actions/setup-python@e797f83bcb11b83ae66e0230d6156d7c80228e7c"
CODEQL = "github/codeql-action/{action}@2892aa5e19bbd11bc0cff5427e3b750a04d9e3c2"
RUST_FETCH = "cargo +1.98.1 fetch --manifest-path implementation/Cargo.toml --locked --target x86_64-unknown-linux-gnu"
RUST_EXAMPLES = "cargo +1.98.1 build --manifest-path implementation/Cargo.toml --examples --locked --offline"
PYTHON_INTEROP = "python -m pytest -q implementation/python-sdk/tests implementation/tests"
OFFLINE_RUST_COMMANDS = (
    "python -m unittest discover -s tools/tests -v",
    "cargo +1.98.1 test --manifest-path implementation/Cargo.toml --locked --offline",
    "python tools/verify_guides.py --root .",
)


def _fail(path, field, value):
    raise ValueError(f"{path}: unsafe {field}: {value}")


def _json_object(root, relative):
    try:
        value = json.loads((root / relative).read_text())
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{relative}: only canonical JSON-subset YAML is accepted: {error}") from error
    if not isinstance(value, dict):
        raise ValueError(f"{relative}: top level must be an object")
    return value


def _keys(relative, field, value, expected):
    actual = set(value) if isinstance(value, dict) else set()
    if actual != set(expected):
        raise ValueError(f"{relative}: {field} keys must be {sorted(expected)}, got {sorted(actual)}")


def _verify_workflow(root, relative):
    text = (root / relative).read_text()
    if re.search(r"\$\{\{\s*(?:secrets\s*(?:\.|\[)|github\s*(?:\.token\b|\[\s*['\"]token['\"]\s*\]))", text, re.I):
        _fail(relative, "token or secret reference", "workflow expression")
    data = _json_object(root, relative)
    _keys(relative, "top-level", data, {"name", "on", "permissions", "jobs"})
    if data["permissions"] != {"contents": "read"}:
        _fail(relative, "permissions", data["permissions"])
    expected_on = {"pull_request": None, "push": {"branches": ["main"]}}
    expected_job = "verify"
    if relative.endswith("codeql.yml"):
        expected_on["schedule"] = [{"cron": "17 4 * * 1"}]
        expected_job = "analyze"
    if data["on"] != expected_on:
        _fail(relative, "on", data["on"])
    _keys(relative, "jobs", data["jobs"], {expected_job})
    job = data["jobs"][expected_job]
    required = {"runs-on", "permissions", "steps"}
    if relative.endswith("codeql.yml"):
        required |= {"strategy"}
    else:
        required |= {"env"}
    _keys(relative, f"jobs.{expected_job}", job, required)
    expected_permissions = {"contents": "read"}
    if relative.endswith("codeql.yml"):
        expected_permissions["security-events"] = "write"
    if job["permissions"] != expected_permissions:
        _fail(relative, f"jobs.{expected_job}.permissions", job["permissions"])
    if job["runs-on"] != "ubuntu-24.04" or not isinstance(job["steps"], list):
        _fail(relative, f"jobs.{expected_job}", "unexpected runner or steps")
    references = []
    for index, step in enumerate(job["steps"]):
        if not isinstance(step, dict):
            _fail(relative, f"jobs.{expected_job}.steps[{index}]", step)
        if "uses" in step:
            reference = step["uses"]
            if not isinstance(reference, str) or "@" not in reference or not FULL_SHA.fullmatch(reference.rsplit("@", 1)[1]):
                _fail(relative, f"jobs.{expected_job}.steps[{index}].uses", reference)
            references.append(reference)
    allowed = {CHECKOUT, SETUP_PYTHON}
    if relative.endswith("codeql.yml"):
        allowed = {CHECKOUT, *(CODEQL.format(action=action) for action in ("init", "autobuild", "analyze"))}
        if len(job["steps"]) != 4 or any("uses" not in step for step in job["steps"]):
            _fail(relative, f"jobs.{expected_job}.steps", "only the four reviewed actions are allowed")
        if references != [CHECKOUT, CODEQL.format(action="init"), CODEQL.format(action="autobuild"), CODEQL.format(action="analyze")]:
            _fail(relative, f"jobs.{expected_job}.actions", references)
    if any(reference not in allowed for reference in references):
        _fail(relative, f"jobs.{expected_job}.actions", references)
    if relative.endswith("ci.yml"):
        steps = job["steps"]
        warmups = [index for index, step in enumerate(steps) if step.get("run") == RUST_FETCH]
        if len(warmups) != 1:
            _fail(relative, "locked Rust dependency warm-up", warmups)
        offline = {
            command: [index for index, step in enumerate(steps) if step.get("run") == command]
            for command in OFFLINE_RUST_COMMANDS
        }
        if any(len(indices) != 1 for indices in offline.values()):
            _fail(relative, "required offline command occurrences", offline)
        offline_indices = [indices[0] for indices in offline.values()]
        if warmups[0] >= min(offline_indices):
            _fail(relative, "locked Rust dependency warm-up order", {"warm-up": warmups[0], "offline": offline})
        example_builds = [index for index, step in enumerate(steps) if step.get("run") == RUST_EXAMPLES]
        python_interop = [index for index, step in enumerate(steps) if step.get("run") == PYTHON_INTEROP]
        if len(example_builds) != 1:
            _fail(relative, "locked offline Rust examples build", example_builds)
        if len(python_interop) != 1 or not warmups[0] < example_builds[0] < python_interop[0]:
            _fail(
                relative,
                "locked offline Rust examples build order",
                {"warm-up": warmups[0], "examples": example_builds[0], "python interoperability": python_interop},
            )


def _verify_issue_forms(root):
    schemas = {
        "bug.yml": {"markdown": "markdown", "behavior": "textarea", "reproduce": "textarea", "version": "input", "scope": "dropdown", "tests": "textarea"},
        "feature.yml": {"problem": "textarea", "scope": "textarea", "compatibility": "textarea", "verification": "textarea"},
    }
    for name, schema in schemas.items():
        relative = f".github/ISSUE_TEMPLATE/{name}"
        data = _json_object(root, relative)
        allowed_top = {"name", "description", "title", "body"} | ({"labels"} if name == "bug.yml" else set())
        _keys(relative, "top-level", data, allowed_top)
        if not all(isinstance(data[field], str) and data[field].strip() for field in ("name", "description", "title")):
            raise ValueError(f"{relative}: name, description and title must be non-empty strings")
        if not isinstance(data["body"], list) or not data["body"]:
            raise ValueError(f"{relative}: body must be a non-empty list")
        found = {}
        for index, item in enumerate(data["body"]):
            if not isinstance(item, dict) or "type" not in item or "attributes" not in item:
                raise ValueError(f"{relative}: body[{index}] missing type or attributes")
            item_id = item.get("id", "markdown")
            expected_item_keys = {"type", "attributes"} if item["type"] == "markdown" else {"type", "id", "attributes", "validations"}
            if item_id == "tests":
                expected_item_keys.remove("validations")
            _keys(relative, f"body[{index}]", item, expected_item_keys)
            if re.search(r"(?:name|email|phone|address|company|organization|contact)", item_id, re.I):
                _fail(relative, f"body[{index}].id", item_id)
            if item_id in found:
                raise ValueError(f"{relative}: duplicate body id: {item_id}")
            found[item_id] = item["type"]
            if not isinstance(item["attributes"], dict) or not item["attributes"]:
                raise ValueError(f"{relative}: body[{index}].attributes must be non-empty")
            expected_attributes = {"value"} if item["type"] == "markdown" else {"label"}
            if item["type"] != "markdown" and "description" in item["attributes"]:
                expected_attributes.add("description")
            if item["type"] == "dropdown":
                expected_attributes.add("options")
            _keys(relative, f"body[{index}].attributes", item["attributes"], expected_attributes)
            if item["type"] != "markdown" and item.get("validations") != {"required": True} and item_id != "tests":
                raise ValueError(f"{relative}: body[{index}].validations.required must be true")
        if found != schema:
            raise ValueError(f"{relative}: body id/type schema mismatch: {found}")
    config = _json_object(root, ".github/ISSUE_TEMPLATE/config.yml")
    if config != {"blank_issues_enabled": False}:
        raise ValueError(".github/ISSUE_TEMPLATE/config.yml: unexpected configuration")


def verify_github_package(root):
    """Fail closed on missing repository files and unsafe workflow capabilities."""
    root = Path(root)
    missing = sorted(path for path in REQUIRED_GITHUB_FILES if not (root / path).is_file())
    if missing:
        raise ValueError("github package missing required files: " + ", ".join(missing))

    for relative in (".github/workflows/ci.yml", ".github/workflows/codeql.yml"):
        _verify_workflow(root, relative)
    _verify_issue_forms(root)

    if _json_object(root, ".github/FUNDING.yml") != {}:
        _fail(".github/FUNDING.yml", "funding platform", "configured")

    security = (root / "SECURITY.md").read_text()
    for required in (
        "No released version is currently supported",
        "https://github.com/artemiosu/ordavyn/security/advisories/new",
        "Do not publish sensitive vulnerability details in a public issue",
        "No response SLA is promised",
    ):
        if required not in security:
            raise ValueError(f"SECURITY.md: missing required limitation: {required}")

    print("GitHub repository package passed")


def guides(root):
    root=Path(root)
    verify_github_package(root)
    with tempfile.TemporaryDirectory(prefix='ordavyn-guide-') as temp:
        temp=Path(temp)
        for name in ['docs/LOCAL-JOURNAL.md','docs/LOCAL-LIFECYCLE.md','implementation/TUTORIAL.md']:
            text=(root/name).read_text().replace('/trusted/local/service.sqlite',str(temp/'python.sqlite'))
            for snippet in re.findall(r'```python\n(.*?)```',text,re.S):
                ns={};exec(snippet,ns)
                if 'journal' in ns:ns['journal'].close()
            print(name,'Python passed')
        journal=re.search(r'```rust\n(.*?)```',(root/'docs/LOCAL-JOURNAL.md').read_text(),re.S)[1].replace('/trusted/local/service.sqlite',str(temp/'rust.sqlite'))
        journal='\n'.join(x[2:] if x.startswith('# ') else x for x in journal.splitlines())
        lifecycle=re.search(r'```rust\n(.*?)```',(root/'docs/LOCAL-LIFECYCLE.md').read_text(),re.S)[1]
        setup='let old_key=Ed25519Keypair::generate();let new_key=Ed25519Keypair::generate();let server=OrdavynServer::new().with_signer(Ed25519Keypair::generate());server.trust(old_key.public_key(), Identifier::new("participant","caller"), &["status"])?;'
        code=journal+'\n#[tokio::main(flavor="current_thread")] async fn main()->ordavyn_core::Result<()>{example()?;'+setup+lifecycle+'\nOk(())}'
        def rust(code):
            path=root/'implementation/ordavyn-core/examples/release_documentation.rs'
            with path.open('x') as f:f.write(code)
            try:subprocess.run(['cargo','+1.98.1','run','--locked','--offline','--example','release_documentation'],cwd=root/'implementation',check=True)
            finally:path.unlink()
        rust(code)
        spec=importlib.util.spec_from_file_location('exchange',root/'implementation/tests/test_authenticated_exchange.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        ca,(cert,key),_=module.certificates.__wrapped__(temp)[:3]
        doc=(root/'docs/LOCAL-WIRE-V3.md').read_text()
        for old,new in [('/tmp/test-chain.pem',str(cert)),('/tmp/test-key.pem',str(key)),('/tmp/test-ca.pem',str(ca))]:doc=doc.replace(old,new)
        exec(re.search(r'```python\n(.*?)```',doc,re.S)[1],{})
        snippet=re.search(r'```rust\n(.*?)```',doc,re.S)[1]
        snippet='\n'.join(x[2:] if x.startswith('# ') else x for x in snippet.splitlines())
        rust(snippet+'\nfn main(){configured().unwrap();}\n')
        print('Journal, lifecycle and TLS Rust guide fragments passed')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',required=True);a=p.parse_args();guides(a.root)
