"""Dashboard-only adapter for the already compiled p0f pipeline, SDE Python 3.5."""
import hashlib
import importlib.util
import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOURCE = os.path.abspath(os.path.join(ROOT, '..', 'test_p0f'))
sys.path.insert(0, SOURCE)
sys.path.insert(0, os.path.join(ROOT, 'tools'))
from telemetry_support import pipeline_identity
spec = importlib.util.spec_from_file_location('legacy_p0f', os.path.join(SOURCE, 'test.py'))
legacy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(legacy)


class DashboardP0fController(legacy.P0F_Test):
    def runTest(self):
        info = self.interface.bfrt_info_get(self.p4_name)
        target = legacy.gc.Target(device_id=0, pipe_id=0xffff)
        self.port_table = info.table_get('$PORT')
        self.open_port(target)
        configs = os.path.join(SOURCE, '..', 'configs')
        self.load_arp_rules(info.table_get('SwitchIngress.handle_arp_table'), os.path.join(configs, 'arp_rules.txt'), target)
        self.setup_preprocess_ipv4_tcp_length_rules(info.table_get('SwitchIngress.preprocess_ipv4_tcp_length_table'), target)
        self.load_ipv4_fwd_rules_from_file(info.table_get('SwitchIngress.ipv4_fwd_table'), os.path.join(configs, 'ipv4_fwd_rules.txt'), target)
        table = info.table_get('SwitchIngress.finger_ob_table')
        options = [info.table_get('SwitchIngress.finger_ob_tcp_table_' + str(i)) for i in range(10)]
        boot = pipeline_identity('p0f')
        previous, active, last_error = None, None, None
        path = os.path.join(ROOT, 'runtime', 'telemetry.json')
        source_ip = '192.168.3.1'
        print('P0F_DASHBOARD_READY: pipeline bound, waiting for fingerprint', flush=True)
        while True:
            try:
                with open(os.path.join(ROOT, 'runtime/p0f_state/fps.json')) as stream:
                    raw = json.load(stream)
                normalized = legacy.normalize(raw)
                if not normalized['needs_ts']:
                    raise ValueError('This precompiled pipeline cannot safely remove Linux TCP timestamps; keep a timestamp-bearing target.')
                digest = hashlib.sha256(json.dumps(raw, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
            except (OSError, ValueError, TypeError) as exc:
                if str(exc) != last_error:
                    print('PROFILE_REJECTED: ' + str(exc), flush=True)
                    last_error = str(exc)
                raw = None
            if raw is not None and digest != previous:
                key = table.make_key([legacy.gc.KeyTuple('hdr.ipv4.src_addr', legacy.gc.ipv4_to_bytes(source_ip))])
                if legacy.entry_exists(table, target, key):
                    table.entry_del(target, [key])
                for option in options:
                    option_key = option.make_key([legacy.gc.KeyTuple('hdr.ipv4.src_addr', legacy.gc.ipv4_to_bytes(source_ip))])
                    if legacy.entry_exists(option, target, option_key):
                        option.entry_del(target, [option_key])
                self.fp_ip_dict.clear()
                self.refresh_table_tuple_list.clear()
                self.add_fp_rule(table, options, (0, source_ip, normalized['os'], normalized), target)
                previous, last_error = digest, None
                active = dict(os=normalized['os'], sha=digest)
                print('P0F_READY ' + json.dumps(active), flush=True)
            ports = []
            for row, key in self.port_table.entry_get(target, [], {'from_hw': True}):
                port = key.to_dict()['$DEV_PORT']['value']
                if port in (52, 60):
                    value = row.to_dict()
                    ports.append(dict(port=port, up=value.get('$PORT_UP', False), enabled=value.get('$PORT_ENABLE', False)))
            state = dict(time=time.time(), boot=boot, pid=os.getpid(), program='p0f',
                         ready=active is not None, active=active, counts={}, events=[], ports=ports,
                         coverage='nic2-p0f-observer', profile_error=last_error)
            with open(path + '.tmp', 'w') as stream:
                json.dump(state, stream)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(path + '.tmp', path)
            time.sleep(1)
