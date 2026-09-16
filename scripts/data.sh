#!/usr/bin/env bash
source "$(dirname -- "${BASH_SOURCE[0]}")/env.sh"
case "${1:-}" in
  nmap) config="$PROJECT_ROOT/build/nmap/antiFpProbe.conf" ;;
  p0f) config="$PROJECT_ROOT/build/p0f/antiFpProbe_p0f.conf" ;;
  monitor) config="$PROJECT_ROOT/build/monitor/scan_monitor.conf" ;;
  *) echo 'Usage: bash scripts/data.sh nmap|p0f|monitor'; exit 2 ;;
esac
[[ -s "$config" ]] || { echo 'Build this mode first.'; exit 1; }
/usr/bin/python3 "$PROJECT_ROOT/scripts/control_guard.py" "$1" --data
if pgrep -x bf_switchd >/dev/null; then
  ps -C bf_switchd -o pid,args
  echo 'Existing data plane detected. Stop it explicitly or use the web confirmation flow.'
  exit 1
fi
cd "$SDE"
exec "$SDE/run_switchd.sh" -c "$config" --server-listen-local-only
