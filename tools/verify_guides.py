#!/usr/bin/env python3
"""Execute documented snippets with disposable journals and TLS test certificates."""
import argparse
import ast
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import tomllib


REQUIRED_GITHUB_FILES = {
    ".github/workflows/ci.yml",
    ".github/workflows/codeql.yml",
    ".github/ISSUE_TEMPLATE/bug.yml",
    ".github/ISSUE_TEMPLATE/feature.yml",
    ".github/ISSUE_TEMPLATE/config.yml",
    ".github/pull_request_template.md",
    "DCO.txt",
    "GOVERNANCE.md",
    ".github/FUNDING.yml",
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
    "SECURITY.md",
    "CHANGELOG.md",
    "README.md",
    "ROADMAP.md",
    "docs/LOCAL-JOURNAL.md",
    "docs/LOCAL-LIFECYCLE.md",
    "docs/LOCAL-THREAT-MODEL.md",
    "docs/LOCAL-WIRE-V3.md",
    "docs/RELEASE-STATUS.md",
    "implementation/Cargo.toml",
    "implementation/README.md",
    "implementation/TUTORIAL.md",
    "implementation/demo/demo_multi.py",
    "implementation/ordavyn-core/Cargo.toml",
    "implementation/tests/test_authenticated_exchange.py",
    "implementation/tests/test_interop.py",
    "implementation/python-sdk/README.md",
    "implementation/python-sdk/pyproject.toml",
    "docs/PROVENANCE.md",
    "spec/README.md",
    "spec/ORDAVYN-WIRE-V3.md",
    "spec/CONFORMANCE.md",
    "docs/LOCAL-WIRE-V2.md",
    "release/README.md",
    "tools/audit_dependencies.py",
    "tools/release_candidate.py",
    "tools/verify_candidate.py",
    "tools/verify_dco.py",
    "tools/export_release.py",
}
README_HEADINGS = (
    "## Why Ordavyn",
    "## How the exchange works",
    "## What works today",
    "## Quickstart from source",
    "## Documentation",
    "## Roadmap to an open standard",
    "## Verify and contribute",
)
README_LINKS = (
    "docs/LOCAL-WIRE-V3.md",
    "docs/LOCAL-THREAT-MODEL.md",
    "docs/LOCAL-JOURNAL.md",
    "docs/LOCAL-LIFECYCLE.md",
    "docs/RELEASE-STATUS.md",
    "implementation/TUTORIAL.md",
    "implementation/tests/test_authenticated_exchange.py",
    "implementation/tests/test_interop.py",
    "ROADMAP.md",
    "release/README.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "GOVERNANCE.md",
    "DCO.txt",
    "spec/README.md",
    "spec/ORDAVYN-WIRE-V3.md",
    "spec/CONFORMANCE.md",
)
VERIFICATION_REQUIREMENTS_INSTALL = '"$ORDAVYN_VENV/bin/python" -m pip install --require-hashes -r release/verification-requirements.txt'
QUICKSTART_SEQUENCE = (
    "git clone https://github.com/artemiosu/ordavyn.git",
    "cd ordavyn",
    'ORDAVYN_VENV="$(mktemp -d "${TMPDIR:-/tmp}/ordavyn-quickstart.XXXXXX")"',
    'python3 -m venv "$ORDAVYN_VENV"',
    '"$ORDAVYN_VENV/bin/python" -m pip install ./implementation/python-sdk',
    '"$ORDAVYN_VENV/bin/python" implementation/demo/demo_multi.py',
)
VERIFICATION_SEQUENCE = (
    VERIFICATION_REQUIREMENTS_INSTALL,
    "cargo +1.98.1 fetch --manifest-path implementation/Cargo.toml --locked --target x86_64-unknown-linux-gnu",
    "cargo +1.98.1 build --manifest-path implementation/Cargo.toml --examples --locked --offline",
    '"$ORDAVYN_VENV/bin/python" -m unittest discover -s tools/tests -v',
    '"$ORDAVYN_VENV/bin/python" tools/verify_guides.py --root .',
)
QUICKSTART_OUTPUT = "Ordavyn two-way service exchange: both authorized requests succeeded"
PUBLIC_STATUS_FILES = (
    "README.md",
    "ROADMAP.md",
    "CONTRIBUTING.md",
    "CHANGELOG.md",
    "SECURITY.md",
    "GOVERNANCE.md",
    "DCO.txt",
    "spec/README.md",
    "spec/ORDAVYN-WIRE-V3.md",
    "spec/CONFORMANCE.md",
    "docs/RELEASE-STATUS.md",
    "implementation/Cargo.toml",
    "implementation/README.md",
    "implementation/python-sdk/README.md",
    "implementation/python-sdk/pyproject.toml",
    "docs/LOCAL-JOURNAL.md",
    "docs/LOCAL-THREAT-MODEL.md",
    "docs/LOCAL-WIRE-V2.md",
    "docs/PROVENANCE.md",
    "release/README.md",
    "tools/audit_dependencies.py",
    "tools/release_candidate.py",
    "tools/verify_candidate.py",
)
STALE_REPOSITORY_CLAIMS = (
    re.compile(r"\bunpublished (?:protocol|repository|project|local candidate)", re.I),
    re.compile(r"not approved for publication", re.I),
    re.compile(r"publication is \*\*blocked\*\*", re.I),
    re.compile(r"publication (?:of this candidate )?is not authorized", re.I),
    re.compile(r"publication requires a separate decision", re.I),
    re.compile(r"does not authorize publication", re.I),
    re.compile(r"publication remains\s+\**blocked", re.I),
    re.compile(r"['\"]publication['\"]\s*:\s*['\"]blocked['\"]", re.I),
    re.compile(r"\bno publication(?:\s|,)", re.I),
)
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
CHECKOUT = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
SETUP_PYTHON = "actions/setup-python@e797f83bcb11b83ae66e0230d6156d7c80228e7c"
CODEQL = "github/codeql-action/{action}@2892aa5e19bbd11bc0cff5427e3b750a04d9e3c2"
RUST_FETCH = "cargo +1.98.1 fetch --manifest-path implementation/Cargo.toml --locked --target x86_64-unknown-linux-gnu"
RUST_EXAMPLES = "cargo +1.98.1 build --manifest-path implementation/Cargo.toml --examples --locked --offline"
SDK_INSTALL = "python -m pip install --no-deps --no-build-isolation ./implementation/python-sdk"
LOCKED_REQUIREMENTS_INSTALL = "python -m pip install --require-hashes -r release/verification-requirements.txt"
ORDINARY_INSTALL_SMOKE = 'smoke_venv="$(mktemp -d "${RUNNER_TEMP}/ordavyn-smoke.XXXXXX")"\npython -m venv "$smoke_venv"\n"$smoke_venv/bin/python" -m pip install ./implementation/python-sdk\n"$smoke_venv/bin/python" implementation/demo/demo_multi.py'
PYTHON_INTEROP = "python -m pytest -q implementation/python-sdk/tests implementation/tests"
RUSTFMT_SETUP = "rustup component add rustfmt --toolchain 1.98.1"
RUST_FORMAT = "cargo +1.98.1 fmt --manifest-path implementation/Cargo.toml --all --check"
EXPORT_CHECK = "python tools/export_release.py --check"
DCO_CHECK = 'python tools/verify_dco.py --head "${{ github.event.pull_request.head.sha || github.sha }}"'
OFFLINE_RUST_COMMANDS = (
    "python -m unittest discover -s tools/tests -v",
    "cargo +1.98.1 test --manifest-path implementation/Cargo.toml --locked --offline",
    "python tools/verify_guides.py --root .",
)
EXPECTED_CI_STEPS = [
    {"uses": CHECKOUT, "with": {"persist-credentials": False, "fetch-depth": 0}},
    {"uses": SETUP_PYTHON, "with": {"python-version": "3.13.15"}},
    {"name": "Smoke test ordinary source install", "run": ORDINARY_INSTALL_SMOKE},
    {"name": "Install locked verification dependencies", "run": LOCKED_REQUIREMENTS_INSTALL},
    {"name": "Install checkout SDK without dependency resolution", "run": SDK_INSTALL},
    {"name": "Install pinned rustfmt", "run": RUSTFMT_SETUP},
    {"name": "Fetch locked Rust dependencies", "run": RUST_FETCH},
    {"name": "Build locked Rust examples", "run": RUST_EXAMPLES},
    {"name": "Repository checks", "run": "python -m unittest discover -s tools/tests -v"},
    {"name": "Guide and GitHub package checks", "run": "python tools/verify_guides.py --root ."},
    {"name": "Python and interoperability tests", "run": PYTHON_INTEROP},
    {"name": "Rust format", "run": RUST_FORMAT},
    {"name": "Rust tests", "run": "cargo +1.98.1 test --manifest-path implementation/Cargo.toml --locked --offline"},
    {"name": "Real checkout export composition", "run": EXPORT_CHECK},
    {"name": "Prospective DCO range", "run": DCO_CHECK},
]


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
        smoke_tests = [index for index, step in enumerate(steps) if step.get("run") == ORDINARY_INSTALL_SMOKE]
        if len(smoke_tests) != 1:
            _fail(relative, "ordinary source install smoke test", smoke_tests)
        locked_installs = [index for index, step in enumerate(steps) if step.get("run") == LOCKED_REQUIREMENTS_INSTALL]
        if len(locked_installs) != 1:
            _fail(relative, "locked verification dependency install", locked_installs)
        sdk_installs = [index for index, step in enumerate(steps) if step.get("run") == SDK_INSTALL]
        if len(sdk_installs) != 1:
            _fail(relative, "checkout SDK install", sdk_installs)
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
        if not smoke_tests[0] < locked_installs[0] < sdk_installs[0] < min(offline_indices):
            _fail(
                relative,
                "source and verification install order",
                {"smoke": smoke_tests[0], "locked": locked_installs[0], "sdk": sdk_installs[0], "offline": offline},
            )
        if sdk_installs[0] >= min(offline_indices):
            _fail(relative, "checkout SDK install order", {"install": sdk_installs[0], "offline": offline})
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
        rustfmt_setup = [index for index, step in enumerate(steps) if step.get("run") == RUSTFMT_SETUP]
        rust_format = [index for index, step in enumerate(steps) if step.get("run") == RUST_FORMAT]
        if len(rustfmt_setup) != 1:
            _fail(relative, "pinned rustfmt setup", rustfmt_setup)
        if len(rust_format) != 1 or rustfmt_setup[0] >= rust_format[0]:
            _fail(relative, "pinned rustfmt setup order", {"setup": rustfmt_setup[0], "format": rust_format})
        if steps != EXPECTED_CI_STEPS:
            _fail(relative, "reviewed CI steps", steps)


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


def _verify_public_front_door(root):
    readme = (root / "README.md").read_text()
    for heading in README_HEADINGS:
        if heading not in readme:
            raise ValueError(f"README.md: missing required section: {heading}")
    shell_blocks = [
        [line.strip() for line in block.splitlines() if line.strip()]
        for block in re.findall(r"```sh\n(.*?)```", readme, re.S)
    ]
    for label, sequence in (("source quickstart", QUICKSTART_SEQUENCE), ("verification setup", VERIFICATION_SEQUENCE)):
        if not any(
            all(command in lines for command in sequence)
            and [lines.index(command) for command in sequence] == sorted(lines.index(command) for command in sequence)
            for lines in shell_blocks
        ):
            raise ValueError(f"README.md: missing or out-of-order {label} shell sequence")
    if QUICKSTART_OUTPUT not in readme:
        raise ValueError("README.md: documented quickstart output does not match demo contract")
    for relative in README_LINKS:
        if f"]({relative})" not in readme:
            raise ValueError(f"README.md: missing evidence link: {relative}")
        if not (root / relative).is_file():
            raise ValueError(f"README.md: evidence link target is missing: {relative}")
    for required in (
        "public experimental repository",
        "No package has been released to crates.io or PyPI",
        "not production",
        "not a standard",
        "no automatic retries",
        "exactly-once external effects",
        "Rust 1.98.1 toolchain",
    ):
        if required not in readme:
            raise ValueError(f"README.md: missing maturity or boundary statement: {required}")

    for relative in PUBLIC_STATUS_FILES:
        contents = (root / relative).read_text()
        for pattern in STALE_REPOSITORY_CLAIMS:
            if pattern.search(contents):
                raise ValueError(f"{relative}: stale repository-publication claim: {pattern.pattern}")

    release_status = (root / "docs/RELEASE-STATUS.md").read_text()
    for required in ("source repository is public", "no supported package", "publish = false", "Private :: Do Not Upload"):
        if required not in release_status:
            raise ValueError(f"docs/RELEASE-STATUS.md: missing repository/package distinction: {required}")

    cargo = tomllib.loads((root / "implementation/Cargo.toml").read_text())
    crate = tomllib.loads((root / "implementation/ordavyn-core/Cargo.toml").read_text())
    python = tomllib.loads((root / "implementation/python-sdk/pyproject.toml").read_text())
    if "experimental" not in cargo["workspace"]["package"]["description"].lower() or "experimental" not in python["project"]["description"].lower():
        raise ValueError("package metadata: descriptions must identify the experimental profile")
    if "Private :: Do Not Upload" not in python["project"].get("classifiers", []):
        raise ValueError("implementation/python-sdk/pyproject.toml: registry publish block is missing")
    if crate["package"].get("publish") is not False:
        raise ValueError("implementation/ordavyn-core/Cargo.toml: registry publish block is missing")

    roadmap = (root / "ROADMAP.md").read_text().lower()
    for required in (
        "independent implementations",
        "conformance suite",
        "interoperability",
        "independent security review",
        "open governance",
        "not a standard",
    ):
        if required not in roadmap:
            raise ValueError(f"ROADMAP.md: missing evidence gate: {required}")


def _run_quickstart_demo(root):
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    result = subprocess.run(
        [sys.executable, str(root / "implementation/demo/demo_multi.py")],
        cwd=root,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
        timeout=20,
    )
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if not lines or lines[-1] != QUICKSTART_OUTPUT:
        raise ValueError(f"README.md: quickstart output drifted: {result.stdout!r}")
    print("README source quickstart passed")


def verify_github_package(root):
    """Fail closed on missing repository files and unsafe workflow capabilities."""
    root = Path(root)
    missing = sorted(path for path in REQUIRED_GITHUB_FILES if not (root / path).is_file())
    if missing:
        raise ValueError("github package missing required files: " + ", ".join(missing))

    _verify_public_front_door(root)
    verify_public_spec(root)

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


UNSUPPORTED_DRAFT_01 = {
    "automatic retries", "CBOR decoder resource-limit enforcement",
    "CBOR transport decoding", "delegation", "discovery",
    "exactly-once external effects", "event dispatch and delivery semantics",
    "HTTP/2 streams and concurrent-stream limits", "mTLS", "negotiation",
    "post-quantum signatures", "production or remote-deployment profile",
    "streaming transport", "vendor extension registry",
}


def _spec_rows(root):
    text=(Path(root)/"spec/CONFORMANCE.md").read_text()
    pattern = r"^\| \[(ORD-[A-Z0-9-]+)\]\([^|\n]+\) \| (implemented|unsupported) \| (?:(?:`([^`]+)` \| `([^`]+)`)|(?:— \| —)) \|$"
    return re.findall(pattern,text,re.M)


def _selector_exists(root, token):
    if "::" not in token: return False
    relative,selector=token.split("::",1);path=Path(root)/relative
    if not path.is_file(): return False
    source=path.read_text()
    if path.suffix == ".py":
        try: tree=ast.parse(source)
        except SyntaxError: return False
        parts=selector.split(".")
        if len(parts)==1:
            return parts[0].startswith("test_") and any(
                isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)) and node.name==parts[0]
                for node in tree.body)
        if len(parts)==2:
            class_name,method=parts
            return method.startswith("test_") and any(
                isinstance(node,ast.ClassDef) and node.name==class_name and any(
                    isinstance(item,(ast.FunctionDef,ast.AsyncFunctionDef)) and item.name==method
                    for item in node.body)
                for node in tree.body)
        return False
    if path.suffix == ".rs" and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*",selector):
        source=re.sub(r"/\*.*?\*/|//[^\n]*","",source,flags=re.S)
        return re.search(
            rf"(?m)^\s*#\[(?:tokio::)?test(?:\([^\]]*\))?\]\s*(?:#\[[^\]]+\]\s*)*(?:async\s+)?fn\s+{re.escape(selector)}\s*\(",
            source,
        ) is not None
    return False


def conformance_evidence_paths(root):
    return sorted({token.split("::",1)[0] for _,_,positive,negative in _spec_rows(root) for token in (positive,negative) if token})


def verify_public_spec(root):
    root=Path(root);contract=(root/"spec/ORDAVYN-WIRE-V3.md").read_text()
    ids=re.findall(r"^#### (ORD-[A-Z0-9-]+)\b",contract,re.M)
    if not ids or len(ids)!=len(set(ids)): raise ValueError("duplicate or missing normative ID")
    rows=_spec_rows(root);mapped=[row[0] for row in rows]
    if len(mapped)!=len(set(mapped)) or set(mapped)!=set(ids):
        raise ValueError("conformance coverage must map each normative ID exactly once")
    for requirement,status,positive,negative in rows:
        if status=="unsupported":
            if positive or negative: raise ValueError(f"{requirement}: unsupported rows cannot claim evidence")
            continue
        if not positive or not negative or positive==negative:
            raise ValueError(f"{requirement}: positive and negative evidence classes required")
        for token in (positive,negative):
            if not _selector_exists(root,token): raise ValueError(f"missing executable selector: {token}")
    section=(root/"spec/CONFORMANCE.md").read_text().split("## Unsupported inventory — Draft 0.1",1)
    if len(section)!=2: raise ValueError("missing versioned unsupported inventory")
    actual={line[2:].strip() for line in section[1].splitlines() if line.startswith("- ")}
    if actual!=UNSUPPORTED_DRAFT_01: raise ValueError("unsupported inventory drift")
    for heading in ("## Status and scope","## Data and trust model","## Admission, replay, and lifecycle","## Transport and resource profile","## Evolution, privacy, and evidence"):
        if heading not in contract: raise ValueError(f"missing normative section: {heading}")
    public="\n".join((root/path).read_text() for path in ("spec/README.md","spec/ORDAVYN-WIRE-V3.md","spec/CONFORMANCE.md","GOVERNANCE.md","README.md","ROADMAP.md","docs/RELEASE-STATUS.md"))
    for claim in (r"\bOrdavyn is (?:a )?standard\b",r"\bOrdavyn is production[- ]ready\b",r"\bOrdavyn is security audited\b",r"\bcertified implementation\b"):
        if re.search(claim,public,re.I): raise ValueError(f"forbidden public claim: {claim}")


def guides(root):
    root=Path(root)
    verify_github_package(root)
    _run_quickstart_demo(root)
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
