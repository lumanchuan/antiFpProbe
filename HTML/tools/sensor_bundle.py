"""Emit to an authenticated SSH pipe, never to a public HTTP endpoint."""
import base64
import argparse
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))
from release_config import SETTINGS
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--url', default=SETTINGS.get('sensor_url'))
args = parser.parse_args()
if not args.url or not args.url.startswith(('http://', 'https://')):
    parser.error('Configure sensor_url or pass --url http://SWITCH:5080/api/p0f/ingest')
token = (root / 'runtime/p0f-sensor.token').read_text().strip()
source = 'DEFAULT_TOKEN = ' + repr(token) + '\n'
source += 'SENSOR_URL = ' + repr(args.url) + '\n'
source += (root / 'tools/p0f_format.py').read_text() + '\n'
source += (root / 'agents/p0f_sensor.py').read_text()
print("import base64; exec(compile(base64.b64decode(%r), '<osdisguise-p0f-sensor>', 'exec'))" % base64.b64encode(source.encode()).decode())
