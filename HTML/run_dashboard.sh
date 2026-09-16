#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
PYTHON=${WEB_PYTHON:-$ROOT/../.venv/bin/python}
[[ -x "$PYTHON" ]] || { echo 'Install the web environment first; see docs/HTML.md'; exit 1; }
cd "$ROOT"
exec "$PYTHON" app.py
