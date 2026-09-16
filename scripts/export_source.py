#!/usr/bin/env python3
"""Export an allowlisted source tree; never include local runtime credentials."""
import argparse
import hashlib
import io
import json
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FILES = {'README.md', 'LICENSE', 'NOTICE', '.gitignore', 'antiFpProbe.p4',
         'nmap_tofino.p4', 'p0f_tofino.p4'}
DIRS = {'common', 'configs', 'config', 'test_nmap', 'test_p0f', 'monitor', 'HTML', 'scripts', 'tests', 'docs'}
PRIVATE_PARTS = {'runtime', '__pycache__', 'backups', 'build', '.venv', '.git'}


def selected(path, args):
    rel = path.relative_to(ROOT)
    if path.is_symlink() or any(part in PRIVATE_PARTS for part in rel.parts):
        return False
    if str(rel).startswith(('HTML/vendor/', 'HTML/vendor_wheels/')):
        return False
    if len(rel.parts) == 1 and rel.name not in FILES:
        return False
    if len(rel.parts) > 1 and rel.parts[0] not in DIRS:
        return False
    if str(rel) == 'config/deployment.json' or path.suffix in {'.pyc', '.log', '.token', '.key', '.pem', '.pcap', '.pcapng', '.sqlite3'}:
        return False
    if str(rel) == 'common/util.p4' and not args.include_sdk_helper:
        return False
    profile = ((path.suffix == '.json' and rel.parts[0] in {'test_nmap', 'test_p0f'}) or
               str(rel).startswith(('HTML/profiles/', 'HTML/profiles_p0f/', 'HTML/validation/')))
    if profile and not args.include_profiles:
        return False
    if str(rel).startswith('HTML/static/images/') and not args.include_artwork:
        return False
    return path.is_file()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True)
    parser.add_argument('--include-profiles', action='store_true')
    parser.add_argument('--include-sdk-helper', action='store_true')
    parser.add_argument('--include-artwork', action='store_true')
    args = parser.parse_args()
    requested = Path(args.output).absolute()
    out = requested.parent.resolve() / requested.name
    if out == ROOT or ROOT in out.parents:
        parser.error('Write the archive outside the project tree')
    if out.exists():
        parser.error('Output already exists; choose a new filename')
    paths = [p for p in sorted(ROOT.rglob('*')) if selected(p, args)]
    manifest = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    public_notes = '''# Public source setup

This archive does not contain deployment credentials or SDK binaries.
See docs/部署.md and docs/发布说明.md before use.
If omitted from this export, supply these files from authorized sources:
- common/util.p4: your licensed SDE 9.7.0 tna_counter/common/util.p4.
- test_nmap/fps.json: a supported Nmap profile you may use.
- test_p0f/fps.json: a supported timestamp-bearing p0f profile you may use.
- Optional profile libraries: HTML/profiles and HTML/profiles_p0f.
- Optional landing artwork: HTML/static/images/testbed-gateway.png.

The omitted candidate catalog is optional; imported profiles remain usable.
Author-owned code uses Apache-2.0; third-party material retains its own terms.
'''
    with tarfile.open(str(out), 'w:gz') as archive:
        for p in paths:
            info = archive.gettarinfo(str(p), 'OSDisguise/' + str(p.relative_to(ROOT)))
            info.uid = info.gid = 0
            info.uname = info.gname = ''
            info.mode = 0o644
            with p.open('rb') as stream:
                archive.addfile(info, stream)
        for name, value in [('SOURCE_MANIFEST.json', json.dumps(manifest, indent=2) + '\n'),
                            ('PUBLIC_SETUP.md', public_notes)]:
            raw = value.encode('utf-8')
            info = tarfile.TarInfo('OSDisguise/' + name)
            info.size, info.mode = len(raw), 0o644
            archive.addfile(info, io.BytesIO(raw))
    print('Exported {} source files to {}'.format(len(paths), out))


if __name__ == '__main__':
    main()
