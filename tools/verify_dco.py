#!/usr/bin/env python3
"""Validate every commit in an explicit prospective DCO range."""
import argparse
from pathlib import Path
import re
import subprocess

ZERO = "0" * 40
ADOPTION_BASELINE = "1fe370a0b64cbfa5a302c1a6a881f1d99a503c48"
IDENTITY = re.compile(r"^\s*([^<>\r\n]+?)\s+<([^<>\s@]+@[^<>\s@]+)>\s*$")
SIGNOFF_LIKE = re.compile(r"^\s*Signed-off-by\b", re.I)
SIGNOFF_LINE = re.compile(r"^Signed-off-by:\s*(.*)$", re.I)


class DCOError(ValueError):
    pass


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args], text=True, stderr=subprocess.STDOUT).strip()


def verify_range(root, revision_range):
    root = Path(root)
    if not revision_range or revision_range.count("..") != 1 or "..." in revision_range:
        raise DCOError("explicit BASE..HEAD range required")
    base, head = revision_range.split("..", 1)
    if not base or not head or base == ZERO:
        raise DCOError("existing non-zero base and head required")
    try:
        subprocess.run(
            ["git", "-C", str(root), "merge-base", "--is-ancestor", base, head],
            check=True, capture_output=True, text=True,
        )
        commits = git(root, "rev-list", "--reverse", revision_range).splitlines()
    except subprocess.CalledProcessError as error:
        raise DCOError("base must be an ancestor of head") from error
    if not commits:
        raise DCOError("range has no contribution commits")
    for commit in commits:
        author_name, author_email, body = git(root, "show", "-s", "--format=%an%x00%ae%x00%B", commit).split("\x00", 2)
        raw = [line for line in body.splitlines() if SIGNOFF_LIKE.match(line)]
        if any(SIGNOFF_LINE.fullmatch(line) is None for line in raw):
            raise DCOError(f"{commit}: malformed sign-off-like line")
        parsed_text = subprocess.run(
            ["git", "-C", str(root), "interpret-trailers", "--parse"], input=body,
            text=True, capture_output=True, check=True,
        ).stdout
        parsed = [match.group(1) for line in parsed_text.splitlines() if (match := SIGNOFF_LINE.fullmatch(line))]
        if len(raw) != len(parsed):
            raise DCOError(f"{commit}: malformed or misplaced sign-off-like line")
        if not parsed:
            raise DCOError(f"{commit}: author sign-off required")
        identities = []
        for value in parsed:
            match = IDENTITY.fullmatch(value)
            if not match:
                raise DCOError(f"{commit}: malformed Signed-off-by trailer")
            identities.append((match.group(1).strip().casefold(), match.group(2).casefold()))
        if len(identities) != len(set(identities)):
            raise DCOError(f"{commit}: duplicate Signed-off-by trailer")
        if (author_name.strip().casefold(), author_email.strip().casefold()) not in identities:
            raise DCOError(f"{commit}: no sign-off matches commit author")
    return commits


def verify_head(root, head, baseline=ADOPTION_BASELINE):
    if not head or ".." in head:
        raise DCOError("single head revision required")
    return verify_range(root, f"{baseline}..{head}")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".")
    parser.add_argument("--head", required=True)
    args = parser.parse_args(argv)
    try:
        commits = verify_head(args.root, args.head)
    except (DCOError, OSError, subprocess.CalledProcessError, ValueError) as error:
        parser.exit(1, f"DCO BLOCKED: {error}\n")
    print(f"DCO passed for {len(commits)} contribution commit(s)")


if __name__ == "__main__":
    main()
