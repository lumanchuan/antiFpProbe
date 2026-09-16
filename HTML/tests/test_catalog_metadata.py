import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from services.profiles import Profiles, atomic_json, canonical
from services.p0f import P0fProfiles


class CatalogMetadataTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=str(ROOT / 'runtime'))
        self.root = Path(self.temp.name)
        (self.root / 'validation/catalog').mkdir(parents=True)
        (self.root / 'runtime/controller_state').mkdir(parents=True)
        self.profiles = Profiles(self.root)
        self.value = dict(OS='Apple Mac OS X 10.3.9', ISN=dict(s1=1), T1=dict(TG=64))
        self.ident = hashlib.sha256(canonical(self.value).encode()).hexdigest()
        atomic_json(self.profiles.directory / (self.ident + '.json'), self.value)
        atomic_json(self.profiles.active_path, self.value)

    def tearDown(self):
        self.temp.cleanup()

    def test_source_metadata_does_not_change_payload_or_selection(self):
        before = self.profiles.active_path.read_bytes()
        atomic_json(self.root / 'validation/catalog/candidates.json', [
            dict(tool='nmap', id=self.ident, source_index=250, schema_valid=True),
            dict(tool='p0f', id=self.ident, source_index=50, schema_valid=True)])
        item = self.profiles.catalog()[0]
        self.assertTrue(item['candidate'])
        self.assertEqual(item['variant'], '库条目 #251')
        self.assertEqual(item['family'], 'Mac')
        self.assertEqual(self.profiles.get(self.ident), self.value)
        self.assertEqual(self.profiles.active_path.read_bytes(), before)

    def test_failed_source_record_does_not_mark_existing_profile(self):
        atomic_json(self.root / 'validation/catalog/candidates.json', [
            dict(tool='nmap', id=self.ident, source_index=250, schema_valid=False)])
        self.assertNotIn('candidate', self.profiles.catalog()[0])

    def test_families_and_existing_catalog_without_manifest(self):
        for name, family in [('Microsoft Windows 7', 'Windows'), ('FreeBSD 8.x', 'FreeBSD'),
                             ('MacOS X:10.x', 'Mac'), ('Linux 2.4', 'Linux'), ('OpenVMS', 'Other')]:
            self.assertEqual(Profiles.family(name), family)
        self.assertNotIn('candidate', self.profiles.catalog()[0])

    def test_p0f_metadata_keeps_normalized_options_and_compatibility(self):
        value = dict(os='Mac OS X:10.x', df=1, ttl=64, mss=1460, wsize=65535,
                     wsize_raw='65535', scale=1, packet_size=64,
                     olayout=['mss', 'nop', 'ws', 'nop', 'nop', 'ts', 'sok', 'eol+1'],
                     raw='*:64:0:*:65535,1:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+:0:Mac OS X:10.x')
        ident = hashlib.sha256(canonical(value).encode()).hexdigest()
        directory = self.root / 'profiles_p0f'
        directory.mkdir()
        active = self.root / 'runtime/p0f_state/fps.json'
        active.parent.mkdir()
        atomic_json(directory / (ident + '.json'), value)
        atomic_json(active, value)
        atomic_json(self.root / 'validation/catalog/candidates.json', [
            dict(tool='p0f', id=ident, source_index=50, schema_valid=True)])
        profiles = P0fProfiles(self.root)
        item = profiles.catalog()[0]
        self.assertEqual(item['variant'], '库条目 #51')
        self.assertEqual(item['scale'], 1)
        self.assertTrue(item['candidate'])
        self.assertTrue(item['supported'])
        self.assertEqual(profiles.selected()['id'], ident)


if __name__ == '__main__':
    unittest.main()
