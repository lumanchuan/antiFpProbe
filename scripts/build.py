#!/usr/bin/env python3
"""Build independent programs without installation or switch reload."""
import argparse
import copy
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'HTML'))
from release_config import SDE_INSTALL

MODES = {'nmap': ('antiFpProbe.p4', 'antiFpProbe', ['-DENB_NMAP=1', '-DENB_P0F=0']),
         'p0f': ('antiFpProbe.p4', 'antiFpProbe', ['-DENB_NMAP=0', '-DENB_P0F=1']),
         'monitor': ('monitor/scan_monitor/scan_monitor.p4', 'scan_monitor', [])}


def configure(mode, platform):
    out = ROOT / 'build' / mode
    _, program_name, _ = MODES[mode]
    required = [out / 'bf-rt.json', out / 'pipe/context.json', out / 'pipe/tofino.bin']
    for path in required:
        if not path.is_file() or path.stat().st_size == 0:
            raise RuntimeError('Missing build output: ' + str(path))
    if not platform.get('chip_list') or len(platform.get('p4_devices', [])) != 1:
        raise ValueError('Use a working, single-device Tofino1 platform configuration')
    device = copy.deepcopy(platform['p4_devices'][0])
    if device.get('device-id') != 0:
        raise ValueError('This release expects device-id 0')
    device['p4_programs'] = [{'program-name': program_name, 'bfrt-config': str(required[0]),
        'p4_pipelines': [{'p4_pipeline_name': 'pipe', 'pipe_scope': [0, 1, 2, 3],
                          'config': str(required[2]), 'context': str(required[1]), 'path': str(out)}]}]
    config = {'instance': platform.get('instance', 0), 'chip_list': platform['chip_list'], 'p4_devices': [device]}
    name = 'antiFpProbe_p0f' if mode == 'p0f' else program_name
    target = out / (name + '.conf')
    target.write_text(json.dumps(config, indent=2) + '\n')
    print('CONFIG ' + str(target))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=list(MODES) + ['all'])
    parser.add_argument('--platform-config', required=True,
                        help='Existing working switch configuration for this physical device (read-only)')
    parser.add_argument('--config-only', action='store_true', help='Regenerate paths after moving the folder')
    args = parser.parse_args()
    platform = json.loads(Path(args.platform_config).read_text())
    compiler = SDE_INSTALL / 'bin/bf-p4c'
    for mode in ['nmap', 'p0f', 'monitor'] if args.mode == 'all' else [args.mode]:
        source, program, defines = MODES[mode]
        out = ROOT / 'build' / mode
        out.mkdir(parents=True, exist_ok=True)
        if not args.config_only:
            command = [str(compiler), '--std', 'p4-16', '--target', 'tofino', '--arch', 'tna',
                       '--program-name', program, '--bf-rt-schema', str(out / 'bf-rt.json'),
                       '-o', str(out)] + defines + [str(ROOT / source)]
            with (out / 'compile.log').open('w') as log:
                result = subprocess.call(command, cwd=str(ROOT), stdout=log, stderr=subprocess.STDOUT)
            if result:
                raise RuntimeError('Compilation failed; see ' + str(out / 'compile.log'))
        configure(mode, platform)
    print('Build finished. No pipeline was loaded and no installed program was overwritten.')


if __name__ == '__main__':
    main()
