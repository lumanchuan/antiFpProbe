"""Check ownership of the loaded pipeline before a manual controller starts."""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'HTML'))
from release_config import SDE_PYTHON, switch_config

stage = 'data' if '--data' in sys.argv[2:] else 'control'
mode = {'nmap': 'antiFpProbe', 'p0f': 'p0f', 'monitor': 'scan_monitor'}[sys.argv[1]]
expected = str(switch_config(mode))
matched = False
for entry in Path('/proc').iterdir():
    if not entry.name.isdigit():
        continue
    try:
        args = (entry / 'cmdline').read_bytes().decode(errors='replace').split('\0')
        comm = (entry / 'comm').read_text().strip()
    except OSError:
        continue
    if comm == 'bf_switchd':
        if stage == 'data':
            raise SystemExit('A data plane is already running (PID {}). No process stopped.'.format(entry.name))
        if expected not in args:
            raise SystemExit('Another pipeline/configuration is running. Stop it explicitly first.')
        matched = True
    if any(Path(arg).name == 'bf-ptf' or arg.endswith('/scan_monitor/controller.py') for arg in args[:5]):
        raise SystemExit('A controller is already running (PID {}). No process stopped.'.format(entry.name))
if stage == 'data':
    config = json.loads(Path(expected).read_text())
    program = config['p4_devices'][0]['p4_programs'][0]
    pipe = program['p4_pipelines'][0]
    for asset in [program['bfrt-config'], pipe['config'], pipe['context']]:
        path = Path(asset).resolve()
        if not path.is_file() or Path(expected).parent.resolve() not in path.parents:
            raise SystemExit('Missing/stale build path. Rebuild or run build.py --config-only first.')
    sys.exit(0)
if not matched:
    raise SystemExit('Start this package data plane first and wait for initialization.')
program = 'antiFpProbe' if mode == 'p0f' else mode
subprocess.check_call([SDE_PYTHON, str(ROOT / 'HTML/tools/ready.py'), program])
