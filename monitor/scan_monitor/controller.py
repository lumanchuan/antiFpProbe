#!/usr/bin/python3
"""SDE Python 3.5 controller; digest events supplement authoritative ASIC counters."""
import json
import os
import signal
import socket
import struct
import sys
import time
import uuid
from collections import deque

from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'HTML'))
from release_config import sdk_python_paths
sys.path[:0] = sdk_python_paths()
import bfrt_grpc.client as gc
sys.path.insert(0, str(ROOT / 'HTML/tools'))
from telemetry_support import pipeline_identity

NAMES = {1: 'SEQ', 2: 'ECN', 3: 'T2', 4: 'T3', 5: 'T4', 6: 'T5',
         7: 'T6', 8: 'T7', 9: 'IE1', 10: 'IE2', 11: 'U1'}
STATE = str(ROOT / 'HTML/runtime/telemetry.json')


def atomic_json(path, value):
    temp = path + '.tmp.' + str(os.getpid())
    with open(temp, 'w') as out:
        json.dump(value, out)
        out.flush()
        os.fsync(out.fileno())
    os.replace(temp, path)


def main():
    running = [True]
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: running.__setitem__(0, False))
    client = gc.ClientInterface('127.0.0.1:50052', client_id=81, device_id=0)
    client.bind_pipeline_config('scan_monitor')
    info = client.bfrt_info_get('scan_monitor')
    target = gc.Target(device_id=0, pipe_id=0xffff)
    ports = info.table_get('$PORT')
    configured = {key.to_dict()['$DEV_PORT']['value']
                  for _, key in ports.entry_get(target, [], {'from_hw': False})}
    for port in (52, 60):
        key = ports.make_key([gc.KeyTuple('$DEV_PORT', port)])
        data = ports.make_data([
            gc.DataTuple('$SPEED', str_val='BF_SPEED_100G'),
            gc.DataTuple('$FEC', str_val='BF_FEC_TYP_RS'),
            gc.DataTuple('$AUTO_NEGOTIATION', str_val='PM_AN_DEFAULT'),
            gc.DataTuple('$LOOPBACK_MODE', str_val='BF_LPBK_NONE'),
            gc.DataTuple('$PORT_ENABLE', bool_val=True)])
        (ports.entry_mod if port in configured else ports.entry_add)(target, [key], [data])
    counters = info.table_get('SwitchIngress.probe_counts')
    learn = info.learn_get('probe_digest')
    boot = pipeline_identity('scan_monitor')
    event_stream = uuid.uuid4().hex
    events = deque(maxlen=512)
    sequence = 0
    last_snapshot = 0
    print('MONITOR_READY ' + boot, flush=True)
    try:
        while running[0]:
            try:
                digest = client.digest_get(timeout=0.3)
            except RuntimeError as error:
                if str(error) != 'Digest list not received.':
                    raise
                digest = None
            if digest is not None:
                for data in learn.make_data_list(digest):
                    row = data.to_dict()
                    category = NAMES.get(row['category'])
                    if not category:
                        continue
                    sequence += 1
                    events.append({'id': event_stream + ':' + str(sequence), 'time': time.time(),
                        'source': socket.inet_ntoa(struct.pack('!I', row['source'])),
                        'target': socket.inet_ntoa(struct.pack('!I', row['destination'])),
                        'sport': row['sport'], 'dport': row['dport'], 'category': category,
                        'mode': 'scan_monitor'})
            if time.monotonic() - last_snapshot >= 1:
                counts = {}
                for index, name in NAMES.items():
                    key = counters.make_key([gc.KeyTuple('$COUNTER_INDEX', index)])
                    result = list(counters.entry_get(target, [key], {'from_hw': True}))
                    counts[name] = sum(row.to_dict().get('$COUNTER_SPEC_PKTS', 0) for row, _ in result)
                port_state = []
                for row, key in ports.entry_get(target, [], {'from_hw': True}):
                    port = key.to_dict()['$DEV_PORT']['value']
                    if port in (52, 60):
                        d = row.to_dict()
                        port_state.append({'port': port, 'up': d.get('$PORT_UP', False),
                                           'enabled': d.get('$PORT_ENABLE', False)})
                atomic_json(STATE, {'time': time.time(), 'boot': boot, 'pid': os.getpid(),
                    'program': 'scan_monitor', 'ready': True, 'counts': counts,
                    'events': list(events), 'ports': port_state,
                    'coverage': 'ingress-60-to-192.168.3.2'})
                last_snapshot = time.monotonic()
    finally:
        client.tear_down_stream()


if __name__ == '__main__':
    main()
