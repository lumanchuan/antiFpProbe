#!/usr/bin/env python3
"""Read-only deployment checks; never repairs drivers, ports, IPs or processes."""
import json
import os
import socket
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'HTML'))
from release_config import SDE, SDE_INSTALL, SDE_PYTHON, SETTINGS, switch_config


def main():
    failures = []
    def check(label, ok):
        print(('OK   ' if ok else 'FAIL ') + label)
        if not ok:
            failures.append(label)
    check('Local configuration', (ROOT / 'config/deployment.json').is_file())
    for name in ['run_switchd.sh', 'run_p4_tests.sh']:
        check(name, (SDE / name).is_file())
    check('bf-p4c', (SDE_INSTALL / 'bin/bf-p4c').is_file())
    result = subprocess.check_output([SDE_PYTHON, '-c', 'import sys;print("%s.%s"%sys.version_info[:2])']).decode().strip()
    site = SDE_INSTALL / 'lib' / ('python' + result) / 'site-packages'
    check('SDE Python ABI ' + result, (site / 'p4testutils/bf_switchd_dev_status.py').is_file())
    check('BFRT Python module', (site / 'tofino/bfrt_grpc/client.py').is_file())
    for mode in ['scan_monitor', 'antiFpProbe', 'p0f']:
        path = switch_config(mode)
        ok = path.is_file()
        if ok:
            try:
                program = json.loads(path.read_text())['p4_devices'][0]['p4_programs'][0]
                pipe = program['p4_pipelines'][0]
                ok = all(Path(v).is_file() for v in [program['bfrt-config'], pipe['config'], pipe['context']])
            except (KeyError, ValueError, IndexError):
                ok = False
        check('Build/config paths: ' + mode, ok)
    for mode in ['controller_state', 'p0f_state']:
        check('Initial fingerprint ' + mode, (ROOT / 'HTML/runtime' / mode / 'fps.json').is_file())
    port = SETTINGS.get('web_port', 5080)
    with socket.socket() as sock:
        busy = sock.connect_ex(('127.0.0.1', port)) == 0
    print('INFO Web port {}: {}'.format(port, 'occupied (do not start a second instance)' if busy else 'not listening'))
    print('INFO This doctor does NOT verify NIC IP/ARP or end-to-end forwarding. Run the host checks in docs/部署.md.')
    print('INFO Fixed testbed: nic-1=192.168.3.1/24, DEV60; nic-2=192.168.3.2/24, DEV52; 100G RS FEC.')
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
