#!/usr/bin/env python3
"""Initialize local state without starting a switch or changing interfaces."""
import argparse
import json
import os
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def initialize():
    runtime = ROOT / 'HTML/runtime'
    for rel in ['', 'configs', 'controller_state', 'p0f_state']:
        path = runtime / rel
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(0o700)
    for name in ('arp_rules.txt', 'ipv4_fwd_rules.txt'):
        shutil.copyfile(str(ROOT / 'configs' / name), str(runtime / 'configs' / name))
    for src, dst in [('test_nmap/fps.json', 'controller_state/fps.json'),
                     ('test_p0f/fps.json', 'p0f_state/fps.json')]:
        target = runtime / dst
        if not target.exists():
            shutil.copyfile(str(ROOT / src), str(target))
            target.chmod(0o600)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sde', default=os.environ.get('SDE'))
    parser.add_argument('--web-host')
    parser.add_argument('--web-port', type=int)
    parser.add_argument('--switch-address', help='Management address reachable from nic-2 and browser')
    parser.add_argument('--sensor-address', help='nic-2 management address as seen by the web server')
    args = parser.parse_args()
    config = ROOT / 'config/deployment.json'
    data = json.loads((config if config.exists() else ROOT / 'config/deployment.example.json').read_text())
    if args.sde:
        sde = Path(args.sde).resolve()
        if not (sde / 'install/bin/bf-p4c').is_file():
            parser.error('SDE compiler is missing: ' + str(sde))
        data['sde'] = str(sde)
    elif not config.exists():
        parser.error('--sde or SDE is required on first configuration')
    if args.web_host:
        data['web_host'] = args.web_host
    if args.web_port:
        if not 1 <= args.web_port <= 65535:
            parser.error('Invalid TCP port')
        data['web_port'] = args.web_port
    if args.switch_address:
        data['trusted_hosts'] = ['localhost', '127.0.0.1', args.switch_address]
        data['sensor_url'] = 'http://{}:{}/api/p0f/ingest'.format(args.switch_address, data['web_port'])
    if args.sensor_address:
        data['sensor_allowed_ips'] = ['127.0.0.1', args.sensor_address]
    config.write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n')
    config.chmod(0o600)
    initialize()
    print('Local configuration and private runtime directories are ready. No service started.')


if __name__ == '__main__':
    main()
