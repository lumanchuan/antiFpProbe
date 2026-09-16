"""Control-plane regression tests; no BFRT connection or hardware writes."""
import contextlib
import copy
import importlib.util
import io
import json
import os
import sys
import tempfile
import types
import unittest


class RpcError(Exception):
    def __init__(self, code):
        self.code = code

    def sub_errors_get(self):
        return [(0, types.SimpleNamespace(canonical_code=self.code))]


class Field:
    def __init__(self, name, value=None, **kwargs):
        self.name = name
        self.value = value if value is not None else next(iter(kwargs.values()))
        self.extra = kwargs


class Key:
    def __init__(self, fields):
        self.fields = {f.name: dict({'value': f.value}, **f.extra) for f in fields}

    def to_dict(self):
        return self.fields

    def __hash__(self):
        return hash(repr(sorted((k, sorted(v.items())) for k, v in self.fields.items())))

    def __eq__(self, other):
        return self.fields == other.fields


class Table:
    def __init__(self):
        self.rows = {}
        self.writes = 0
        self.fail_once = False

    def make_key(self, fields):
        return Key(fields)

    def make_data(self, fields, action=None):
        return dict({'action_name': action}, **{f.name: f.value for f in fields})

    def entry_add(self, target, keys, data):
        self.writes += 1
        if self.fail_once:
            self.fail_once = False
            raise RpcError(13)
        for key, value in zip(keys, data):
            if key in self.rows:
                raise RpcError(6)
            self.rows[key] = value

    def entry_mod(self, target, keys, data):
        self.writes += 1
        for key, value in zip(keys, data):
            if key not in self.rows:
                raise RpcError(5)
            self.rows[key] = value

    def entry_del(self, target, keys):
        self.writes += 1
        for key in keys:
            del self.rows[key]

    def entry_get(self, target, keys, flags):
        return iter((value, key) for key, value in self.rows.items())


gc = types.ModuleType('bfrt_grpc.client')
gc.KeyTuple = gc.DataTuple = Field
gc.BfruntimeReadWriteRpcException = RpcError
gc.ipv4_to_bytes = lambda ip: int(__import__('ipaddress').IPv4Address(ip))
base = types.ModuleType('bfruntime_client_base_tests')
base.BfRuntimeTest = type('BfRuntimeTest', (), {'setUp': lambda *args: None})
sys.modules['bfruntime_client_base_tests'] = base
sys.modules['bfrt_grpc'] = types.ModuleType('bfrt_grpc')
sys.modules['bfrt_grpc'].client = gc
sys.modules['bfrt_grpc.client'] = gc
root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location('nmap_control', os.path.join(root, 'test_nmap', 'test.py'))
control = importlib.util.module_from_spec(spec)
spec.loader.exec_module(control)


class ControlTests(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(root, 'test_nmap', 'fps.json')) as source:
            self.fp = json.load(source)
        self.agent = control.NMAP_Test()
        self.agent.setUp()
        self.header = Table()
        self.options = [Table() for _ in range(10)]
        self.icmp, self.filter, self.gate = Table(), Table(), Table()
        self.tables = (self.header, self.options, self.icmp, self.filter, self.gate)
        self.all_tables = [self.header] + self.options + [self.icmp, self.filter, self.gate]
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, 'fps.json')
        self.write(self.fp)
        self.stdout = contextlib.redirect_stdout(io.StringIO())
        self.stdout.__enter__()

    def tearDown(self):
        self.stdout.__exit__(None, None, None)
        self.tmp.cleanup()

    def write(self, fp):
        with open(self.path, 'w') as target:
            json.dump(fp, target)

    def refresh(self):
        return self.agent.refresh_fingerprint(self.path, self.tables, '192.168.3.2', None)

    def headers(self):
        return {k.to_dict()['packet_seq']['value']: v for k, v in self.header.rows.items()}

    def counts(self):
        return [t.writes for t in self.all_tables]

    def test_six_isns_and_ids(self):
        self.fp['ISN']['s1'] = 0
        self.fp['ISN']['s6'] = 0xffffffff
        self.write(self.fp)
        self.assertTrue(self.refresh())
        hdr = self.headers()
        self.assertEqual(set(hdr), set(range(1, 14)))
        for i, seq in enumerate(control.P1_6_IDS, 1):
            self.assertEqual(hdr[seq]['m_seq_from_isn'], self.fp['ISN']['s{}'.format(i)])
            self.assertEqual(hdr[seq]['wsize'], self.fp['WIN']['W{}'.format(i)])
            self.assertEqual(hdr[seq]['m_seq_no_opcode'], 3)
        self.assertEqual({v['seq'] for v in self.filter.rows.values()}, set(range(8, 14)))

    def test_invalid_isns_before_writes(self):
        for invalid in (None, -1, 1 << 32, True, 1.2, '123'):
            with self.subTest(value=invalid):
                self.fp['ISN']['s3'] = invalid
                self.write(self.fp)
                with self.assertRaises(ValueError):
                    self.refresh()
                self.assertEqual(self.counts(), [0] * len(self.all_tables))

    def test_missing_isn_before_writes(self):
        del self.fp['ISN']
        self.write(self.fp)
        with self.assertRaises(ValueError):
            self.refresh()
        self.assertEqual(sum(self.counts()), 0)

    def test_unchanged_file_has_no_writes(self):
        self.refresh()
        before = self.counts()
        self.write(self.fp)
        self.assertFalse(self.refresh())
        self.assertEqual(self.counts(), before)

    def test_invalid_reload_retains_active_rules(self):
        self.refresh()
        before = self.counts()
        with open(self.path, 'w') as target:
            target.write('{')
        self.assertFalse(self.refresh())
        self.assertEqual(self.counts(), before)
        self.write(self.fp)
        self.assertFalse(self.refresh())

    def test_changed_fingerprint_replaces_rules(self):
        self.refresh()
        self.fp['ISN']['s4'] = 12345
        self.fp['OPS']['O4'] = []
        self.write(self.fp)
        self.assertTrue(self.refresh())
        self.assertEqual(self.headers()[11]['m_seq_from_isn'], 12345)
        self.assertEqual(self.headers()[11]['m_new_data_offset'], 5)
        for table in self.options:
            self.assertFalse(any(k.to_dict()['packet_seq']['value'] == 11 for k in table.rows))

    def test_failed_update_rolls_back(self):
        self.refresh()
        before = copy.deepcopy(self.agent.active_fingerprint)
        self.fp['ISN']['s3'] = 42
        self.write(self.fp)
        self.filter.fail_once = True
        self.assertFalse(self.refresh())
        self.assertEqual(self.agent.active_fingerprint, before)
        self.assertEqual(self.headers()[10]['m_seq_from_isn'], before['ISN']['s3'])
        self.assertEqual(len(self.gate.rows), 1)

    def test_overflow_rejected_before_writes(self):
        for options in ([{'nop': 1}] * 10, [{'ts': 1}] * 5, [{'unknown': 1}]):
            with self.subTest(options=options):
                self.fp['OPS']['O6'] = options
                self.write(self.fp)
                with self.assertRaises(ValueError):
                    self.refresh()
                self.assertEqual(sum(self.counts()), 0)

    def test_nop_labels_and_eol_alignment(self):
        config = control.option_config([{'mss': 1460}, {'nop': 1}, {'nop': 2}, {'eol': 1}])
        self.assertEqual(config['olayout'], ['mss', 'nop', 'nop', 'eop'])
        self.agent.fp_ip_dict['192.168.3.2'] = {}
        offset, length, _ = self.agent.add_fp_option_rule(
            self.options, (0, '192.168.3.2', 'test', config), 8, None)
        self.assertEqual((offset, length), (7, 8))
        self.assertEqual(sum(len(t.rows) for t in self.options), 5)

    def test_normalization_does_not_mutate_input(self):
        before = copy.deepcopy(self.fp)
        self.agent.handle_fp_rules(self.header, self.options, self.icmp, 0,
                                   '192.168.3.2', 'test', self.fp, None)
        self.assertEqual(self.fp, before)

    def test_tcp_flags_and_ecn_cc(self):
        self.fp['ECN']['CC'] = 'S'
        self.fp['T3']['F'] = 'APUF'
        self.fp['T3']['S'] = 'O'
        self.write(self.fp)
        self.refresh()
        self.assertEqual(self.headers()[1]['tcp_flag_bits'], 0xd2)
        self.assertEqual(self.headers()[3]['tcp_flag_bits'], 0x39)
        self.assertNotEqual(self.headers()[3]['m_seq_from_isn'], 0)

    def test_no_reply_needs_no_isns(self):
        self.fp = {'T1': {'R': 'N'}}
        self.write(self.fp)
        self.refresh()
        self.assertEqual(len(self.headers()), 6)
        self.assertTrue(all(row['should_reply'] == 0 for row in self.headers().values()))

    def test_restart_removes_only_this_hosts_stale_rules(self):
        old = self.header.make_key([Field('packet_seq', 16), Field('hdr.ipv4.dst_addr', gc.ipv4_to_bytes('192.168.3.2'))])
        other = self.header.make_key([Field('packet_seq', 16), Field('hdr.ipv4.dst_addr', gc.ipv4_to_bytes('192.168.3.3'))])
        self.header.entry_add(None, [old, other], [{}, {}])
        self.agent.track_existing_fingerprint(self.all_tables, '192.168.3.2', None)
        self.refresh()
        self.assertNotIn(old, self.header.rows)
        self.assertIn(other, self.header.rows)

    def test_upsert_propagates_other_errors(self):
        key = self.header.make_key([Field('x', 1)])
        control.upsert(self.header, None, [key], [{}])
        control.upsert(self.header, None, [key], [{'changed': 1}])
        self.assertEqual(self.header.rows[key], {'changed': 1})
        self.header.fail_once = True
        with self.assertRaises(RpcError):
            control.upsert(self.header, None, [key], [{}])

    def test_ie_df_and_code(self):
        for dfi, expected in [('N', (0, 0)), ('Y', (1, 1)), ('S', (1, 0)), ('O', (0, 1))]:
            with self.subTest(dfi=dfi):
                ie = {'DFI': dfi, 'CD': 'S'}
                self.assertEqual(control.icmp_reply_fields(ie, 0), (expected[0], 9))
                self.assertEqual(control.icmp_reply_fields(ie, 1), (expected[1], 0))
        self.refresh()
        self.assertEqual(len(self.icmp.rows), 2)
        self.assertTrue(all(r['action_name'].endswith('generate_icmp_reply') for r in self.icmp.rows.values()))
        self.assertTrue(all(r['df'] == 0 for r in self.icmp.rows.values()))

    def test_ie_no_reply(self):
        self.fp['IE'] = {'R': 'N'}
        self.write(self.fp)
        self.refresh()
        self.assertEqual(len(self.icmp.rows), 2)
        self.assertTrue(all(r['action_name'].endswith('ignore_icmp_request') for r in self.icmp.rows.values()))

    def test_option_checksum_includes_odd_alignment(self):
        config = control.option_config([{'nop': 1}, {'w': 7}, {'mss': 1460}])
        # Bytes: 01 03 03 07 02 04 05 b4.
        self.assertEqual(control.tcp_option_sum(config), 0x0103 + 0x0307 + 0x0204 + 0x05b4)
        self.assertEqual(control.tcp_option_sum(control.option_config([])), 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
