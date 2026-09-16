import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from services.runtime import Runtime


class PortableReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.runtime = Runtime(self.root, Mock())
        self.runtime.stop_event.set()

    def tearDown(self):
        self.temp.cleanup()

    def test_all_modes_check_missing_config_before_stop(self):
        for mode in ('scan_monitor', 'antiFpProbe', 'p0f'):
            with patch('services.runtime.switch_config', return_value=self.root / 'missing.conf'), \
                 patch.object(self.runtime, 'stop_confirmed') as stop, \
                 patch.object(self.runtime, 'launch') as launch:
                self.runtime.execute({'mode': mode, 'action': 'start', 'processes': []})
                stop.assert_not_called()
                launch.assert_not_called()
                self.assertEqual(self.runtime.state['stage'], 'error')

    def test_config_checks_every_build_artifact(self):
        paths = [self.root / name for name in ('bfrt.json', 'tofino.bin', 'context.json')]
        config = self.root / 'program.conf'
        config.write_text(json.dumps({'p4_devices': [{'p4_programs': [{'bfrt-config': str(paths[0]),
            'p4_pipelines': [{'config': str(paths[1]), 'context': str(paths[2])}]}]}]}))
        with patch('services.runtime.switch_config', return_value=config):
            for path in paths:
                with self.assertRaises(RuntimeError):
                    self.runtime.preflight('antiFpProbe')
                path.write_text('test')
            self.runtime.preflight('antiFpProbe')

    def test_old_checkout_paths_are_rejected_even_when_files_exist(self):
        old = self.root / 'old'
        new = self.root / 'new'
        old.mkdir()
        new.mkdir()
        asset = old / 'artifact'
        asset.write_text('test')
        config = new / 'program.conf'
        config.write_text(json.dumps({'p4_devices': [{'p4_programs': [{'bfrt-config': str(asset),
            'p4_pipelines': [{'config': str(asset), 'context': str(asset)}]}]}]}))
        with patch('services.runtime.switch_config', return_value=config):
            with self.assertRaises(RuntimeError):
                self.runtime.preflight('p0f')


if __name__ == '__main__':
    unittest.main()
