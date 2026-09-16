import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch, Mock

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'vendor')]
from services.storage import Store
from services.runtime import Runtime, processes, python_entrypoint, pending_ports
from services.profiles import Profiles


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=str(ROOT / 'runtime'))
        self.store = Store(Path(self.tmp.name) / 'db')

    def tearDown(self):
        self.store.db.close()
        self.tmp.cleanup()

    def telemetry(self, t, category='SEQ', ident='a', value=1, boot='boot'):
        return {'boot': boot, 'time': t, 'counts': {category: value}, 'events': [
            {'id': ident, 'time': t, 'source': '192.168.3.1', 'target': '192.168.3.2',
             'category': category, 'dport': 445, 'mode': 'scan_monitor'}]}

    def test_duplicate_digest_and_counter_not_double_counted(self):
        value = self.telemetry(time.time())
        self.store.ingest(value)
        self.store.ingest(value)
        result = self.store.snapshot()
        self.assertEqual(result['total'], 1)
        self.assertEqual(len(result['events']), 1)
        self.assertEqual(result['scan_sessions'], 1)

    def test_session_grouping_and_confidence(self):
        now = time.time()
        self.store.ingest(self.telemetry(now))
        self.store.ingest(self.telemetry(now + 1, 'ECN', 'b'))
        self.assertEqual(self.store.snapshot()['scan_sessions'], 1)
        self.assertEqual(self.store.snapshot()['high_confidence'], 1)
        self.store.ingest(self.telemetry(now + 34, ident='c', value=2))
        self.assertEqual(self.store.snapshot()['scan_sessions'], 2)

    def test_restart_does_not_lose_old_counts(self):
        now = time.time()
        self.store.ingest(self.telemetry(now, value=23))
        self.store.ingest(self.telemetry(now + 1, value=2, boot='restart', ident='b'))
        self.assertEqual(self.store.snapshot()['total'], 25)

    def test_counter_decrease_does_not_create_negative_samples(self):
        now = time.time()
        self.store.ingest(self.telemetry(now, value=9))
        self.store.ingest(self.telemetry(now + 1, value=3, ident='b'))
        self.assertEqual(self.store.snapshot()['total'], 9)


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.runtime = Runtime(ROOT, Mock())
        self.runtime.stop_event.set()
        self.proc = {'pid': 1234, 'start': '90', 'command': 'bf_switchd --conf-file /tmp/other.conf',
                     'plane': 'data', 'program': 'other', 'name': 'bf_switchd'}

    def test_prepare_and_cancel_never_send_signal(self):
        with patch('services.runtime.processes', return_value=[self.proc]), patch('services.runtime.os.kill') as kill:
            result = self.runtime.prepare('scan_monitor', 'start')
            self.assertTrue(result['confirmation_required'])
            self.assertEqual(result['processes'][0]['pid'], 1234)
            kill.assert_not_called()

    def test_changed_process_rejected(self):
        with patch('services.runtime.processes', return_value=[self.proc]):
            result = self.runtime.prepare('scan_monitor', 'start')
        with patch('services.runtime.processes', return_value=[dict(self.proc, start='91')]), patch('services.runtime.os.kill') as kill:
            with self.assertRaises(ValueError):
                self.runtime.commit(result['token'])
            kill.assert_not_called()

    def test_mode_injection_rejected(self):
        with self.assertRaises(ValueError):
            self.runtime.prepare('scan_monitor; touch /tmp/pwn', 'start')

    def test_failed_data_plane_never_starts_controller(self):
        child = Mock()
        child.poll.return_value = 1
        with patch.object(self.runtime, 'preflight'), patch('services.runtime.processes', return_value=[]), patch.object(self.runtime, 'launch', return_value=child) as launch, patch.object(self.runtime, 'device_ready', return_value=False):
            self.runtime.execute({'mode': 'scan_monitor', 'action': 'start', 'processes': []})
            self.assertEqual(launch.call_count, 1)
            self.assertEqual(self.runtime.state['stage'], 'error')

    def test_stop_controller_before_data_plane(self):
        controller = dict(self.proc, pid=20, plane='control', command='python bf-ptf')
        alive = [self.proc, controller]
        signaled = []

        def terminate(pid, sig):
            signaled.append((pid, sig))
            alive[:] = [p for p in alive if p['pid'] != pid]

        with patch('services.runtime.processes', side_effect=lambda: list(alive)), patch('services.runtime.os.kill', side_effect=terminate):
            self.runtime.stop_confirmed([self.proc, controller])
        self.assertEqual(signaled, [(20, signal.SIGINT), (1234, signal.SIGQUIT)])

    def test_pid_reused_immediately_before_signal_is_rejected(self):
        with patch('services.runtime.processes', return_value=[dict(self.proc, start='new')]), patch('services.runtime.os.kill') as kill:
            with self.assertRaises(RuntimeError):
                self.runtime.stop_confirmed([self.proc])
            kill.assert_not_called()


class LinkReadinessTests(unittest.TestCase):
    def setUp(self):
        self.runtime = Runtime(ROOT, Mock())
        self.runtime.stop_event.set()
        self.child = Mock()
        self.child.poll.return_value = None

    def sample(self, up=True, **values):
        return dict({'fresh': True, 'ready': True, 'program': 'scan_monitor', 'time': 100,
                     'ports': [{'port': 52, 'up': True, 'enabled': True},
                               {'port': 60, 'up': up, 'enabled': True}]}, **values)

    def run_wait(self, samples, timeout=6, advancing=True):
        clock = [0]

        def sleep(seconds):
            clock[0] += seconds

        def telemetry():
            value = dict(samples[min(int(clock[0]), len(samples) - 1)])
            if advancing:
                value['time'] += clock[0]
            return value

        with patch('services.runtime.time.monotonic', side_effect=lambda: clock[0]), \
             patch('services.runtime.time.sleep', side_effect=sleep), \
             patch.object(self.runtime, 'telemetry', side_effect=telemetry):
            self.runtime.wait_for_links('scan_monitor', 90, self.child, timeout=timeout)
        return clock[0]

    def test_control_ready_waits_for_both_links_and_stability(self):
        self.assertEqual(self.run_wait([self.sample(False), self.sample()]), 3)
        self.assertEqual(self.runtime.state['stage'], 'links')

    def test_missing_or_disabled_port_is_not_ready(self):
        self.assertEqual(pending_ports({'ports': []}), [52, 60])
        data = self.sample()
        data['ports'][1]['enabled'] = False
        self.assertEqual(pending_ports(data), [60])

    def test_link_loss_resets_stability_window(self):
        samples = [self.sample(), self.sample(False), self.sample()]
        self.assertEqual(self.run_wait(samples), 4)

    def test_stale_wrong_program_or_old_sample_cannot_complete(self):
        for value in [self.sample(fresh=False), self.sample(program='antiFpProbe'), self.sample(time=80)]:
            with self.subTest(value=value):
                with self.assertRaises(RuntimeError):
                    self.run_wait([value])

    def test_repeated_telemetry_cannot_confirm_stability(self):
        with self.assertRaises(RuntimeError):
            self.run_wait([self.sample()], advancing=False)

    def test_timeout_names_missing_port_and_does_not_kill(self):
        with patch('services.runtime.os.kill') as kill:
            with self.assertRaisesRegex(RuntimeError, 'DEV 60'):
                self.run_wait([self.sample(False)])
            kill.assert_not_called()

    def test_controller_exit_during_link_wait_is_reported(self):
        self.child.poll.return_value = 1
        with self.assertRaisesRegex(RuntimeError, '控制面已退出'):
            self.run_wait([self.sample()])

    def test_execute_cannot_report_running_before_links(self):
        with patch('services.runtime.processes', return_value=[]), \
             patch.object(self.runtime, 'preflight'), \
             patch.object(self.runtime, 'launch', return_value=self.child), \
             patch.object(self.runtime, 'device_ready', return_value=True), \
             patch.object(self.runtime, 'telemetry', return_value=self.sample(time=time.time() + 1)), \
             patch.object(self.runtime, 'wait_for_links', side_effect=RuntimeError('DEV 60 link timeout')) as wait:
            self.runtime.execute({'mode': 'scan_monitor', 'action': 'start', 'processes': []})
            wait.assert_called_once()
            self.assertEqual(self.runtime.state['stage'], 'error')

    def test_snapshot_reflects_live_link_loss(self):
        with patch('services.runtime.processes', return_value=[]), \
             patch.object(self.runtime, 'telemetry', side_effect=[self.sample(), self.sample(False)]):
            self.assertTrue(self.runtime.snapshot()['link_ready'])
            value = self.runtime.snapshot()
            self.assertFalse(value['link_ready'])
            self.assertEqual(value['pending_ports'], [60])


class ProcessDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=str(ROOT / 'runtime'))
        self.proc = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def add_process(self, pid, argv, state='S'):
        folder = self.proc / str(pid)
        folder.mkdir()
        (folder / 'cmdline').write_bytes(('\0'.join(argv) + '\0').encode())
        (folder / 'stat').write_text('{} (python3) {} {}'.format(pid, state, ' '.join(['0'] * 18 + ['1234'])))

    def test_real_ptf_worker_not_waiting_launcher(self):
        self.add_process(8023, ['python3', '/sde/p4testutils/run_ptf_tests.py',
                               '--p4-name=antiFpProbe', '--ptf', 'bf-ptf'])
        self.add_process(8029, ['/usr/bin/python3', '/sde/install/bin/bf-ptf',
                               '--test-dir', '/sde/GXC/antiFpProbe/HTML/control_plane'])
        found = processes(self.proc)
        self.assertEqual([p['pid'] for p in found], [8029])
        self.assertEqual(found[0]['program'], 'antiFpProbe')

    def test_arguments_cannot_impersonate_control_process(self):
        self.add_process(1, ['python3', '/some/unrelated.py', '/sde/bin/bf-ptf'])
        self.add_process(2, ['python3', '-c', '/sde/bin/bf-ptf'])
        self.assertEqual(processes(self.proc), [])

    def test_monitor_worker_and_zombie_filter(self):
        argv = ['python3', '-u', '/sde/GXC/test/scan_monitor/controller.py']
        self.add_process(1, argv)
        self.add_process(2, argv, state='Z')
        self.assertEqual([p['pid'] for p in processes(self.proc)], [1])

    def test_python_interpreter_flags(self):
        self.assertEqual(python_entrypoint(['python3', '-u', '-W', 'ignore', '-X', 'faulthandler', '/sde/bin/bf-ptf']), '/sde/bin/bf-ptf')
        self.assertEqual(python_entrypoint(['python3', '-m', 'some_module', 'bf-ptf']), '')

    def test_real_waiting_launcher_exits_when_worker_stops(self):
        # Reproduce the SDE process tree using disposable processes, not switch services.
        worker = self.proc / 'bf-ptf'
        worker.write_text('import signal,time\nsignal.signal(signal.SIGINT, signal.SIG_DFL)\nprint("READY", flush=True)\ntime.sleep(60)\n')
        launcher = self.proc / 'run_ptf_tests.py'
        launcher.write_text('import signal,subprocess,sys\nsignal.signal(signal.SIGINT, signal.SIG_IGN)\np=subprocess.Popen([sys.executable,sys.argv[1]])\np.wait()\n')
        parent = subprocess.Popen([sys.executable, str(launcher), str(worker), '--ptf', 'bf-ptf'],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        worker_pid = None
        try:
            import select
            self.assertTrue(select.select([parent.stdout], [], [], 5)[0], 'worker did not start')
            self.assertEqual(parent.stdout.readline().strip(), 'READY')
            found = [p for p in processes() if str(self.proc) in p['command']]
            self.assertEqual(len(found), 1)
            worker_pid = found[0]['pid']
            self.assertNotEqual(worker_pid, parent.pid)
            runtime = Runtime(ROOT, Mock())
            runtime.stop_event.set()
            runtime.stop_confirmed(found)
            self.assertEqual(parent.wait(timeout=5), 0)
        finally:
            if worker_pid is not None and any(p['pid'] == worker_pid and str(self.proc) in p['command'] for p in processes()):
                try:
                    os.kill(worker_pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
            if parent.poll() is None:
                parent.terminate()
            parent.communicate(timeout=5)


class ProfileTests(unittest.TestCase):
    def test_source_validator_accepts_current_and_rejects_bad_isn(self):
        profiles = Profiles(ROOT)
        value = json.loads(profiles.active_path.read_text())
        profiles.validate(value)
        value['ISN']['s1'] = -1
        with self.assertRaises(ValueError):
            profiles.validate(value)

    def test_path_traversal_rejected(self):
        with self.assertRaises(ValueError):
            Profiles(ROOT).get('../../test_nmap/fps')


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=str(ROOT / 'runtime'))
        self.root = Path(self.tmp.name)
        (self.root / 'runtime/controller_state').mkdir(parents=True)
        original = ROOT / 'runtime/controller_state/fps.json'
        (self.root / 'runtime/controller_state/fps.json').write_bytes(original.read_bytes())
        from app import create_app
        self.app = create_app(self.root, testing=True)
        self.client = self.app.test_client()

    def tearDown(self):
        self.app.extensions['runtime'].stop_event.set()
        self.app.extensions['store'].db.close()
        self.tmp.cleanup()

    def login(self):
        secret = (self.root / 'runtime/admin.token').read_text()
        return self.client.post('/api/login', json={'token': secret}).get_json()['csrf']

    def test_unauthorized_access_denied(self):
        self.assertEqual(self.client.get('/api/state').status_code, 401)
        self.assertEqual(self.client.get('/api/export').status_code, 401)

    def test_mutation_requires_csrf(self):
        self.login()
        self.assertEqual(self.client.post('/api/operation/prepare', json={'mode': 'scan_monitor', 'action': 'start'}).status_code, 403)

    def test_external_origin_denied(self):
        csrf = self.login()
        self.assertEqual(self.client.post('/api/operation/prepare', json={},
            headers={'X-CSRF-Token': csrf, 'Origin': 'https://attacker.invalid'}).status_code, 403)

    def test_readonly_state(self):
        self.login()
        response = self.client.get('/api/state')
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('admin.token', response.get_data(as_text=True))

    def test_malformed_body_is_friendly(self):
        self.assertEqual(self.client.post('/api/login', json=[]).status_code, 400)


if __name__ == '__main__':
    unittest.main()
