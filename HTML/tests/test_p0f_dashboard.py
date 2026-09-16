import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'vendor'), str(ROOT / 'tools')]
from p0f_format import Decoder, fields, signature_matches
from services.p0f import P0fProfiles, P0fMonitor
from services.storage import Store
from services.runtime import Runtime, processes

LINUX = '4:64+0:0:16396:mss*2,0:mss,sok,ts,nop,ws:df,id+:0'
MAC = '4:64+0:0:1460:65535,1:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+:0'


class P0fTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=str(ROOT / 'runtime'))
        self.root = Path(self.temp.name)
        (self.root / 'runtime').mkdir()
        self.store = Store(self.root / 'runtime/db')
        self.profiles = P0fProfiles(self.root)
        for profile in self.profiles.catalog():
            if 'loopback' in profile['name']:
                self.profiles.select(profile['id'])
        self.monitor = P0fMonitor(self.root, self.store, self.profiles)
        self.boot = 'a' * 32
        self.runtime = dict(busy=False, telemetry=dict(fresh=True, ready=True, program='p0f',
            boot='pipeline-1', active=dict(sha=self.profiles.selected()['id'])))

    def tearDown(self):
        self.store.db.close()
        self.temp.cleanup()

    def batch(self, **updates):
        event = dict(id=self.boot + ':1', source='192.168.3.1', target='192.168.3.2',
                     sport=31000, dport=5001, side='SYN', os='Linux 2.4.x (loopback)',
                     raw_sig=LINUX, params='none', captured_at=time.time(),
                     epoch=self.monitor.context(self.runtime)['epoch'])
        event.update(updates)
        return dict(boot=self.boot, events=[event], status=dict(pid=100, p0f_pid=101, capture=True))

    def test_profiles_are_isolated_from_nmap_and_original(self):
        self.assertEqual(self.profiles.active_path, self.root / 'runtime/p0f_state/fps.json')
        self.assertTrue((self.root / 'profiles_p0f').is_dir())
        self.assertFalse((self.root / 'profiles').exists())

    def test_timestamp_removal_target_cannot_be_selected(self):
        value = self.profiles.get(self.profiles.selected()['id'])
        value.update(os='Without timestamp', raw='*:64:0:1460:8192,0:mss,nop,nop,sok:df,id+:0:Test',
                     olayout=['mss','nop','nop','sok'], packet_size=48,
                     wsize=8192, wsize_raw='8192', mss=1460)
        ident = self.profiles.add(value)
        before = self.profiles.selected()['id']
        self.assertFalse(next(item for item in self.profiles.catalog() if item['id']==ident)['supported'])
        with self.assertRaises(ValueError):
            self.profiles.select(ident)
        self.assertEqual(self.profiles.selected()['id'], before)

    def test_export_is_not_limited_to_visible_rows(self):
        for i in range(301):
            self.monitor.ingest(self.batch(id=self.boot + ':' + str(i)), self.runtime)
        self.assertEqual(len(self.monitor.snapshot(self.runtime)['events']), 300)
        self.assertEqual(len(self.monitor.snapshot(self.runtime, export=True)['events']), 301)

    def test_observations_do_not_increment_nmap_counters(self):
        self.monitor.ingest(self.batch(), self.runtime)
        self.assertEqual(self.store.snapshot()['total'], 0)
        self.assertEqual(self.monitor.snapshot(self.runtime)['counts']['SYN'], 1)

    def test_duplicate_upload_is_idempotent(self):
        batch = self.batch()
        self.monitor.ingest(batch, self.runtime)
        self.monitor.ingest(batch, self.runtime)
        result = self.monitor.snapshot(self.runtime)
        self.assertEqual((result['evaluated'], result['matched']), (1, 1))
        self.assertEqual(len(result['events']), 1)

    def test_changed_pipeline_epoch_never_claims_match(self):
        self.monitor.ingest(self.batch(epoch='previous-pipeline'), self.runtime)
        self.assertEqual(self.monitor.snapshot(self.runtime)['evaluated'], 0)

    def test_nmap_mode_cannot_claim_p0f_protection(self):
        self.runtime['telemetry']['program'] = 'antiFpProbe'
        self.monitor.ingest(self.batch(), self.runtime)
        self.assertEqual(self.monitor.snapshot(self.runtime)['evaluated'], 0)

    def test_pending_profile_or_switch_busy_not_evaluated(self):
        for change in ('profile', 'busy'):
            if change == 'profile':
                self.runtime['telemetry']['active']['sha'] = 'different'
            else:
                self.runtime['busy'] = True
            self.monitor.ingest(self.batch(id=self.boot + ':' + change), self.runtime)
        self.assertEqual(self.monitor.snapshot(self.runtime)['evaluated'], 0)

    def test_synack_not_counted_as_client_match(self):
        self.monitor.ingest(self.batch(side='SYN-ACK'), self.runtime)
        result = self.monitor.snapshot(self.runtime)
        self.assertEqual(result['counts']['SYN-ACK'], 1)
        self.assertEqual(result['evaluated'], 0)

    def test_freshness_expires(self):
        self.monitor.ingest(self.batch(), self.runtime)
        self.monitor.sensor['time'] -= 10
        self.assertFalse(self.monitor.snapshot(self.runtime)['sensor']['online'])

    def test_invalid_batch_is_not_partially_inserted(self):
        batch = self.batch()
        batch['events'].append(dict(batch['events'][0], source='10.0.0.1'))
        with self.assertRaises(ValueError):
            self.monitor.ingest(batch, self.runtime)
        self.assertEqual(self.monitor.snapshot(self.runtime)['events'], [])

    def test_invalid_sensor_status_rejected_before_insert(self):
        batch = self.batch()
        batch['status']['ipv4'] = 'not-an-address-list'
        with self.assertRaises(ValueError):
            self.monitor.ingest(batch, self.runtime)
        self.assertEqual(self.monitor.snapshot(self.runtime)['events'], [])

    def test_chart_clock_comes_from_server(self):
        with patch('services.p0f.time.time', return_value=1780000000):
            self.assertEqual(self.monitor.snapshot(self.runtime)['now'], 1780000000)

    def test_actual_signatures_and_mismatch(self):
        expected = self.profiles.normalize(self.profiles.get(self.profiles.selected()['id']))
        self.assertTrue(signature_matches(LINUX, expected))
        self.assertFalse(signature_matches(LINUX.replace('df,id+', 'df,id+,ecn'), expected))
        mac = next(profile for profile in self.profiles.catalog() if 'Mac OS' in profile['name'])
        self.assertTrue(signature_matches(MAC, self.profiles.normalize(self.profiles.get(mac['id']))))

    def test_decoder_ignores_uptime_and_handles_synack(self):
        decoder = Decoder()
        records = []
        sample = '''.-[ 192.168.3.1/31000 -> 192.168.3.2/5001 (syn) ]-
|
| os = Linux 2.4.x (loopback)
| params = none
| raw_sig = SIGNATURE
`----
.-[ 192.168.3.1/31000 -> 192.168.3.2/5001 (uptime) ]-
| uptime = 15 days
`----
.-[ 192.168.3.1/31000 -> 192.168.3.2/5001 (syn+ack) ]-
| os = ???
| params = none
| raw_sig = SIGNATURE
`----'''.replace('SIGNATURE', LINUX)
        for line in sample.splitlines():
            record = decoder.feed(line)
            if record:
                records.append(record)
        self.assertEqual([record['side'] for record in records], ['SYN', 'SYN-ACK'])


class P0fRuntimeTests(unittest.TestCase):
    def test_cancel_invalidates_confirmation_without_signals(self):
        runtime = Runtime(ROOT, Mock())
        runtime.stop_event.set()
        with patch('services.runtime.processes', return_value=[]), patch('services.runtime.os.kill') as kill:
            challenge = runtime.prepare('p0f', 'start')
            self.assertTrue(challenge['confirmation_required'])
            runtime.cancel(challenge['token'])
            with self.assertRaises(ValueError):
                runtime.commit(challenge['token'])
            kill.assert_not_called()

    def test_missing_build_does_not_stop_existing_program(self):
        runtime = Runtime(ROOT, Mock())
        runtime.stop_event.set()
        with patch.object(runtime, 'preflight', side_effect=RuntimeError('missing build')), patch.object(runtime, 'stop_confirmed') as stop:
            runtime.execute(dict(mode='p0f', action='start', processes=[]))
            stop.assert_not_called()
            self.assertEqual(runtime.state['stage'], 'error')

    def test_p0f_and_nmap_share_name_but_not_mode(self):
        with tempfile.TemporaryDirectory(dir=str(ROOT / 'runtime')) as folder:
            proc = Path(folder)
            commands = [['bf_switchd', '--conf-file', '/sde/test_p0f/build/antiFpProbe_p0f.conf'],
                        ['python3', '/sde/install/bin/bf-ptf', '--test-dir', '/sde/HTML/p0f_control'],
                        ['python3', '/sde/install/bin/bf-ptf', '--test-dir', '/sde/test_nmap']]
            for index, command in enumerate(commands, 1):
                entry = proc / str(index)
                entry.mkdir()
                (entry / 'cmdline').write_bytes(('\0'.join(command) + '\0').encode())
                (entry / 'stat').write_text('{} (program) S {}'.format(index, ' '.join(['0']*18+['1'])))
            actual = {item['pid']: item['program'] for item in processes(proc)}
            self.assertEqual(actual[1], 'p0f')
            self.assertEqual(actual[2], 'p0f')
            self.assertNotEqual(actual[3], 'p0f')


class P0fApiTests(unittest.TestCase):
    from test_dashboard import ApiTests as Fixture
    setUp = Fixture.setUp
    tearDown = Fixture.tearDown
    login = Fixture.login

    def test_private_p0f_endpoints_require_login(self):
        for path in ('state', 'profiles', 'export'):
            self.assertEqual(self.client.get('/api/p0f/' + path).status_code, 401)

    def test_sensor_requires_its_own_token_and_source(self):
        self.login()
        body = dict(boot='a' * 32, events=[], status={})
        self.assertEqual(self.client.post('/api/p0f/ingest', json=body).status_code, 403)
        headers = {'X-Sensor-Token': self.app.extensions['p0f'].token}
        self.assertEqual(self.client.post('/api/p0f/ingest', json=body, headers=headers,
            environ_overrides={'REMOTE_ADDR': '192.168.30.130'}).status_code, 403)
        self.assertEqual(self.client.post('/api/p0f/ingest', json=body, headers=headers).status_code, 200)

    def test_sensor_control_requires_csrf_and_boolean(self):
        csrf = self.login()
        self.assertEqual(self.client.post('/api/p0f/sensor', json={'enabled': False}).status_code, 403)
        self.assertEqual(self.client.post('/api/p0f/sensor', json={'enabled': 'false'},
            headers={'X-CSRF-Token': csrf}).status_code, 400)

    def test_state_has_server_clock_but_not_sensor_secret(self):
        self.login()
        response = self.client.get('/api/p0f/state')
        self.assertEqual(response.status_code, 200)
        self.assertIn('now', response.get_json()['statistics'])
        self.assertNotIn(self.app.extensions['p0f'].token, response.get_data(as_text=True))


if __name__ == '__main__':
    unittest.main()
