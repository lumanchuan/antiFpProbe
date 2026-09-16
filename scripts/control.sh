#!/usr/bin/env bash
source "$(dirname -- "${BASH_SOURCE[0]}")/env.sh"
mode=${1:-}
case "$mode" in
  nmap) controller="$PROJECT_ROOT/HTML/control_plane"; program=antiFpProbe ;;
  p0f) controller="$PROJECT_ROOT/HTML/p0f_control"; program=antiFpProbe ;;
  monitor) program=scan_monitor ;;
  *) echo 'Usage: bash scripts/control.sh nmap|p0f|monitor'; exit 2 ;;
esac
/usr/bin/python3 "$PROJECT_ROOT/scripts/control_guard.py" "$mode"
cd "$SDE"
if [[ "$mode" == monitor ]]; then
  exec /usr/bin/python3 "$PROJECT_ROOT/monitor/scan_monitor/controller.py"
fi
exec "$SDE/run_p4_tests.sh" -p "$program" -t "$controller" --target tofino
