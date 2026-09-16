"""Isolated dashboard adapter. The original antiFpProbe controller stays untouched."""
import hashlib
import importlib.util
import json
import os
import sys
import time
import uuid

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'tools'))
from telemetry_support import pipeline_identity
spec = importlib.util.spec_from_file_location(
    'legacy_nmap', os.path.join(ROOT, '..', 'test_nmap', 'test.py'))
legacy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(legacy)
legacy.TEST_DIR = os.path.join(ROOT, 'runtime', 'controller_state')


class DashboardNmapController(legacy.NMAP_Test):
    def setUp(self):
        super(DashboardNmapController, self).setUp()
        self.web_boot = pipeline_identity('antiFpProbe')
        self.web_counts = {}
        self.web_active = None

    def refresh_fingerprint(self, *args, **kwargs):
        result = super(DashboardNmapController, self).refresh_fingerprint(*args, **kwargs)
        if self.active_fingerprint:
            raw = json.dumps(self.active_fingerprint, sort_keys=True, separators=(',', ':'))
            self.web_active = {'os': self.active_fingerprint.get('OS', 'Unspecified'),
                               'sha': hashlib.sha256(raw.encode()).hexdigest()}
        return result

    def dump_reg(self, table, index, name, target):
        key = table.make_key([legacy.gc.KeyTuple('$REGISTER_INDEX', index)])
        row, _ = next(table.entry_get(target, [key], {'from_hw': True}))
        values = row.to_dict()['SwitchIngress.{}.f1'.format(name)]
        value = sum(values) if isinstance(values, list) else values
        self.web_counts[name + ':' + str(index)] = value
        if name == 'return_pkts_reg':
            counts = {name: self.web_counts.get('ecn_1_to_7_reg:' + str(i), 0)
                      for i, name in enumerate(['ECN', 'T2', 'T3', 'T4', 'T5', 'T6', 'T7'], 1)}
            counts['SEQ'] = sum(self.web_counts.get('ecn_1_to_7_reg:' + str(i), 0)
                                for i in range(8, 14))
            ports = []
            for data, key in self.port_table.entry_get(target, [], {'from_hw': True}):
                port = key.to_dict()['$DEV_PORT']['value']
                if port in (52, 60):
                    d = data.to_dict()
                    ports.append({'port': port, 'up': d.get('$PORT_UP', False),
                                  'enabled': d.get('$PORT_ENABLE', False)})
            state = {'time': time.time(), 'boot': self.web_boot, 'pid': os.getpid(),
                     'program': 'antiFpProbe', 'ready': self.web_active is not None,
                     'active': self.web_active, 'counts': counts, 'events': [], 'ports': ports,
                     'coverage': 'legacy-tcp-counters-only', 'raw_counts': self.web_counts}
            path = os.path.join(ROOT, 'runtime', 'telemetry.json')
            with open(path + '.tmp', 'w') as out:
                json.dump(state, out)
                out.flush()
                os.fsync(out.fileno())
            os.replace(path + '.tmp', path)
