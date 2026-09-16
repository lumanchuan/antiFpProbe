#!/usr/bin/env bash
set -euo pipefail
PROJECT_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
export PROJECT_ROOT
if [[ -z "${SDE:-}" && -f "$PROJECT_ROOT/config/deployment.json" ]]; then
  SDE=$(/usr/bin/python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["sde"])' "$PROJECT_ROOT/config/deployment.json")
fi
: "${SDE:?Set SDE to your installed Tofino SDE directory first}"
export SDE
export SDE_INSTALL="${SDE_INSTALL:-$SDE/install}"
export PATH="/usr/bin:/bin:$SDE_INSTALL/bin:$PATH"
unset PYTHONHOME PYTHONPATH
