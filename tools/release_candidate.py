#!/usr/bin/env python3
"""Fail-closed, local-only snapshot export. Never stages, commits or publishes."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import zipfile


class Rejected(ValueError):
    pass


def sha(data):
    return hashlib.sha256(data).hexdigest()


def git(root, *args):
    return subprocess.check_output(['git', '-C', str(root), *args])


def safe_path(name):
    p = PurePosixPath(name)
    if not name or '\\' in name or p.is_absolute() or any(x in ('', '.', '..') for x in name.split('/')):
        raise Rejected('unsafe path')
    return name


def inspect_content(name, data):
    safe_path(name)
    parts = name.lower().split('/')
    if any(p.startswith('.') and p not in ('.gitignore', '.gitattributes') for p in parts) or any(p in ('_bmad', '_bmad-output', 'node_modules', '__pycache__') for p in parts):
        raise Rejected(f'private path: {name}')
    if re.search(r'\.(?:sqlite3?|db|pem|key|p12|pfx)$|(?:-wal|-shm|-journal)$', name, re.I):
        raise Rejected(f'key or journal path: {name}')
    if re.search(rb'-----BEGIN (?:[A-Z ]*PRIVATE KEY|OPENSSH PRIVATE KEY)-----|(?:AKIA|ASIA)[A-Z0-9]{16}|gh[pousr]_[A-Za-z0-9]{30,}', data):
        raise Rejected(f'potential secret: {name}; sha256={sha(data)}')


def archive_entries(path):
    entries = {}
    seen = set()
    directories = set()
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            for item in archive.infolist():
                name = safe_path(item.filename.rstrip('/') if item.is_dir() else item.filename)
                if name in seen:
                    raise Rejected('duplicate archive member')
                seen.add(name)
                if (item.external_attr >> 16) & 0o170000 == 0o120000:
                    raise Rejected('archive contains symlink')
                if item.is_dir():
                    inspect_content(name, b'')
                    directories.add(name)
                    continue
                if name in entries:
                    raise Rejected('duplicate archive member')
                entries[name] = archive.read(item)
    else:
        with tarfile.open(path, 'r:*') as archive:
            for item in archive:
                name = safe_path(item.name)
                if name in seen:
                    raise Rejected('duplicate archive member')
                seen.add(name)
                if item.isdir():
                    inspect_content(name, b'')
                    directories.add(name)
                    continue
                if not item.isfile():
                    raise Rejected('non-regular or duplicate archive member')
                entries[name] = archive.extractfile(item).read()
    parents = {str(parent) for name in entries for parent in PurePosixPath(name).parents if str(parent) != '.'}
    if not directories <= parents:
        raise Rejected('unexplained archive directory')
    for name, data in entries.items():
        inspect_content(name, data)
    return entries


def verify_archive(path, expected):
    """Compare every path and byte against explicit {path: sha256} inventory."""
    actual = archive_entries(path)
    if set(actual) != set(expected):
        raise Rejected('archive member list differs from inventory')
    if any(sha(data) != expected[name] for name, data in actual.items()):
        raise Rejected('archive content differs from inventory')
    return actual


def verify_source(archive_path, manifest):
    expected={entry['path']:entry['sha256'] for entry in manifest['files']}
    if len(expected)!=len(manifest['files']): raise Rejected('duplicate manifest path')
    verify_archive(archive_path,expected)
    if sha(Path(archive_path).read_bytes())!=manifest['source_sha256']:
        raise Rejected('source archive digest differs from manifest')
    entries={entry['path']:entry for entry in manifest['files']}
    with tarfile.open(archive_path,'r:*') as archive:
        for item in archive:
            if not item.isfile(): raise Rejected('source archive has non-file member')
            expected=entries[item.name]
            if item.size!=expected['size'] or item.mode!=int(expected['mode'],8) or item.uid or item.gid or item.mtime or item.uname or item.gname:
                raise Rejected('source archive metadata mismatch')


def export(root, commit, output):
    root, output = Path(root), Path(output)
    commit = git(root, 'rev-parse', '--verify', commit + '^{commit}').decode().strip()
    if git(root, 'rev-parse', 'HEAD').decode().strip() != commit:
        raise Rejected('selected snapshot must be checked-out HEAD')
    if git(root, 'status', '--porcelain=v1', '--untracked-files=all'):
        raise Rejected('working tree has changed or untracked files')
    blobs = {}
    modes = {}
    for row in git(root, 'ls-tree', '-rz', '--full-tree', commit).split(b'\0'):
        if not row:
            continue
        metadata, path = row.split(b'\t', 1)
        mode, kind, oid = metadata.decode().split()
        name = path.decode('utf-8')
        safe_path(name)
        if kind != 'blob' or mode not in ('100644', '100755'):
            raise Rejected(f'non-regular snapshot entry: {name}')
        blobs[name] = git(root, 'cat-file', 'blob', oid)
        modes[name] = int(mode, 8) & 0o777
    try:
        policy = json.loads(blobs['release/files.json'])
        declared = policy['files']
    except (KeyError, ValueError) as exc:
        raise Rejected('missing or invalid release/files.json') from exc
    if set(declared) != set(blobs):
        raise Rejected('every tracked file must be explicitly classified')
    selected = {}
    for name, rule in declared.items():
        if not isinstance(rule, dict) or rule.get('action') not in ('include', 'exclude') or not rule.get('reason'):
            raise Rejected('invalid file classification')
        if rule['action'] == 'include':
            inspect_content(name, blobs[name])
            selected[name] = blobs[name]
    manifest = {'schema': 1, 'commit': commit, 'files': [
        {'path': name, 'size': len(data), 'mode': format(modes[name], '04o'), 'sha256': sha(data)}
        for name, data in sorted(selected.items())]}
    # Reserve output atomically; no successful marker until verification finishes.
    output.mkdir(parents=True, exist_ok=False)
    archive_path = output / 'source.tar.gz'
    with archive_path.open('xb') as raw:
        with gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0) as zipped:
            with tarfile.open(fileobj=zipped, mode='w', format=tarfile.USTAR_FORMAT) as archive:
                for name, data in sorted(selected.items()):
                    item = tarfile.TarInfo(name)
                    item.size, item.mode, item.mtime = len(data), modes[name], 0
                    item.uid = item.gid = 0
                    item.uname = item.gname = ''
                    archive.addfile(item, io.BytesIO(data))
    verify_archive(archive_path, {name: sha(data) for name, data in selected.items()})
    manifest['source_sha256'] = sha(archive_path.read_bytes())
    verify_source(archive_path, manifest)
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    (output / 'COMPOSITION-PASS').write_text('Source composition verified. Publication remains BLOCKED.\n')
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    build = commands.add_parser('export')
    build.add_argument('--root', default='.')
    build.add_argument('--commit', required=True)
    build.add_argument('--output', required=True)
    verify = commands.add_parser('verify-archive')
    verify.add_argument('archive')
    verify.add_argument('inventory', help='JSON object mapping each archive path to expected SHA-256')
    source = commands.add_parser('verify-source')
    source.add_argument('archive')
    source.add_argument('manifest')
    args = parser.parse_args()
    try:
        if args.command == 'export':
            export(args.root, args.commit, args.output)
        elif args.command == 'verify-source':
            verify_source(args.archive, json.loads(Path(args.manifest).read_text()))
        else:
            verify_archive(args.archive, json.loads(Path(args.inventory).read_text()))
    except (Rejected, OSError, subprocess.CalledProcessError, tarfile.TarError, zipfile.BadZipFile) as exc:
        parser.exit(1, f'BLOCKED: {exc}\n')


if __name__ == '__main__':
    main()
