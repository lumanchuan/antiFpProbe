"""Deployment paths; compatible with both the SDE and web Python runtimes."""
import json
import os
from pathlib import Path

PROJECT = Path(__file__).resolve().parent.parent
local = PROJECT / 'config/deployment.json'
SETTINGS = json.loads(local.read_text()) if local.exists() else {}
SDE = Path(os.environ.get('SDE') or SETTINGS.get('sde') or '/opt/bf-sde-9.7.0')
SDE_INSTALL = Path(os.environ.get('SDE_INSTALL') or SETTINGS.get('sde_install') or str(SDE / 'install'))
SDE_PYTHON = SETTINGS.get('sde_python', '/usr/bin/python3')


def switch_config(mode):
    names = {'scan_monitor': ('monitor', 'scan_monitor'),
             'antiFpProbe': ('nmap', 'antiFpProbe'), 'p0f': ('p0f', 'antiFpProbe_p0f')}
    directory, name = names[mode]
    return PROJECT / 'build' / directory / (name + '.conf')


def sdk_python_paths():
    import sys
    version = '{}.{}'.format(sys.version_info[0], sys.version_info[1])
    root = SDE_INSTALL / 'lib' / ('python' + version) / 'site-packages'
    return [str(root / 'tofino/bfrt_grpc'), str(root / 'tofino'), str(root)]
