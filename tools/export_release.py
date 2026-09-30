#!/usr/bin/env python3
"""Fail-closed check of the real source-only checkout composition."""
import argparse
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess


def _release_module():
    path = Path(__file__).with_name("release_candidate.py")
    spec = importlib.util.spec_from_file_location("ordavyn_release_candidate", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_RC = _release_module()
Rejected, inspect_content = _RC.Rejected, _RC.inspect_content
FORMER_NAME = re.compile(rb"agent[-_ ]?" rb"bridge", re.I)
DEPLOYMENT_CERTIFICATE_SUFFIXES = {".crt", ".cer", ".der"}


def _names(raw):
    return [name for name in raw.decode("utf-8").split("\0") if name]


def check(root):
    root = Path(root).resolve()
    index = subprocess.check_output(["git", "-C", str(root), "ls-files", "--stage", "-z"])
    tracked = {}
    for row in index.split(b"\0"):
        if not row:
            continue
        meta, raw_name = row.split(b"\t", 1)
        mode, _, stage = meta.decode().split()
        name = raw_name.decode()
        if stage != "0" or mode not in {"100644", "100755"}:
            raise Rejected(f"submodule, conflict, or non-regular tracked mode: {name} ({mode}, stage {stage})")
        tracked[name] = mode
    untracked = set(_names(subprocess.check_output([
        "git", "-C", str(root), "ls-files", "--others", "--exclude-standard", "-z"
    ])))
    policy = json.loads((root / "release/files.json").read_text())["files"]
    expected = set(tracked) | untracked
    if set(policy) != expected:
        raise Rejected(f"classification mismatch; missing={sorted(expected-set(policy))}, extra={sorted(set(policy)-expected)}")
    for name in expected:
        if PurePosixPath(name).is_absolute() or ".." in PurePosixPath(name).parts:
            raise Rejected(f"unsafe path: {name}")
        path = root / name
        mode = path.lstat().st_mode
        if not stat.S_ISREG(mode):
            raise Rejected(f"symlink or non-regular checkout path: {name}")
        if name in tracked and bool(mode & 0o111) != (tracked[name] == "100755"):
            raise Rejected(f"working executable mode differs from Git: {name}")
        rule = policy[name]
        if set(rule) != {"action", "reason"} or rule["action"] not in {"include", "exclude"} or not rule["reason"]:
            raise Rejected(f"invalid classification: {name}")
        if rule["action"] == "include":
            if path.suffix.lower() in DEPLOYMENT_CERTIFICATE_SUFFIXES:
                raise Rejected(f"deployment certificate extension in public export: {name}")
            data = path.read_bytes()
            inspect_content(name, data)
            if FORMER_NAME.search(data):
                raise Rejected(f"former name in public file: {name}")
    return sum(rule["action"] == "include" for rule in policy.values())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".")
    parser.add_argument("--check", action="store_true", required=True)
    args = parser.parse_args(argv)
    try:
        count = check(args.root)
    except (Rejected, OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"EXPORT BLOCKED: {error}\n")
    print(f"Source-only export composition passed: {count} public files")


if __name__ == "__main__":
    main()
