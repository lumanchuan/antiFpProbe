#!/usr/bin/env python3
"""Manage only this checkout's web process; never signal a switch/controller."""
import argparse
import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'HTML'))
from release_config import SETTINGS
STATE = ROOT / 'HTML/runtime/web-service.json'


def identity(pid):
    try:
        proc = Path('/proc') / str(pid)
        argv = (proc / 'cmdline').read_bytes().decode().split('\0')
        stat = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
        if stat[0] == 'Z' or str(ROOT / 'HTML/app.py') not in argv:
            return None
        return {'pid': pid, 'start': stat[19]}
    except (OSError, ValueError, IndexError):
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['start', 'stop', 'status'])
    parser.add_argument('--python', default=str(ROOT / '.venv/bin/python'))
    args = parser.parse_args()
    saved = json.loads(STATE.read_text()) if STATE.exists() else None
    current = identity(saved['pid']) if saved else None
    owned = current is not None and saved == current
    if args.action == 'status':
        print('RUNNING PID {}'.format(current['pid']) if owned else 'NOT RUNNING (managed instance)')
        return
    if args.action == 'stop':
        if not owned:
            raise SystemExit('No matching managed process. No signal sent.')
        os.kill(current['pid'], signal.SIGTERM)
        for _ in range(50):
            if identity(current['pid']) != current:
                STATE.unlink()
                print('Web stopped. Data/control planes and NIC processes are unchanged.')
                return
            time.sleep(0.1)
        raise SystemExit('Web has not exited; inspect its log. No force kill sent.')
    if owned:
        raise SystemExit('Already running; PID ' + str(current['pid']))
    if not (ROOT / 'HTML/runtime/controller_state/fps.json').exists():
        raise SystemExit('Run scripts/configure.py first.')
    host, port = SETTINGS.get('web_host', '127.0.0.1'), SETTINGS.get('web_port', 5080)
    with socket.socket() as sock:
        try:
            sock.bind((host, port))
        except OSError as exc:
            raise SystemExit('Cannot bind web address; no process stopped: ' + str(exc))
    with (ROOT / 'HTML/runtime/web.log').open('ab') as log:
        proc = subprocess.Popen([args.python, str(ROOT / 'HTML/app.py')], cwd=str(ROOT / 'HTML'),
                                stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                start_new_session=True)
    for _ in range(50):
        if proc.poll() is not None:
            raise SystemExit('Web exited; see HTML/runtime/web.log')
        current = identity(proc.pid)
        with socket.socket() as sock:
            ready = sock.connect_ex(('127.0.0.1' if host == '0.0.0.0' else host, port)) == 0
        if current and ready:
            STATE.write_text(json.dumps(current))
            STATE.chmod(0o600)
            print('Web started; PID {}, port {}'.format(proc.pid, port))
            return
        time.sleep(0.1)
    proc.terminate()
    proc.wait(timeout=5)
    raise SystemExit('Web readiness timed out; own child stopped. See log.')


if __name__ == '__main__':
    main()
