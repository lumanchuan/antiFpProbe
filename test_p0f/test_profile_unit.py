import copy
import unittest
from p0f_profile import normalize


class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.value = dict(df=1, mss=16396, ttl=64, scale=0, wsize=32792, wsize_raw='mss*2',
                          packet_size=60, os='Linux:2.4.x (loopback)',
                          olayout=['mss', 'sok', 'ts', 'nop', 'ws'],
                          raw='*:64:0:16396:mss*2,0:mss,sok,ts,nop,ws:df,id+:0:Linux:2.4.x (loopback)')

    def test_current_linux(self):
        result = normalize(self.value)
        self.assertEqual(result['option_bytes'], 20)
        self.assertEqual(result['wsize'], result['mss'] * 2)
        self.assertEqual(result['option_sum'], 0x521f)
        self.assertEqual(result['ecn'], 0)

    def test_wildcard_mss_and_multiplier(self):
        self.value.update(mss=0, wsize=0, wsize_raw='mss*4', raw='*:64:0:*:mss*4,0:mss,sok,ts,nop,ws:df,id+:0:Linux:2.4.x')
        result = normalize(self.value)
        self.assertEqual((result['mss'], result['wsize']), (1460, 5840))

    def test_mac_eol_padding(self):
        self.value.update(mss=0, wsize=65535, wsize_raw='65535', scale=1, packet_size=64,
                          raw='*:64:0:*:65535,1:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+:0:Mac OS X:10.x',
                          olayout=['mss','nop','ws','nop','nop','ts','sok','eol+1'])
        result = normalize(self.value)
        self.assertEqual(result['option_bytes'], 24)
        self.assertEqual(result['olayout'][-2:], ['end', 'end'])
        self.assertEqual(result['option_sum'], 0x18c9)

    def test_zero_fields_and_ecn(self):
        self.value.update(df=0, wsize=0, wsize_raw='0', raw='*:64:0:16396:0,0:mss,sok,ts,nop,ws:ecn:0:Test')
        result = normalize(self.value)
        self.assertEqual((result['df'], result['wsize'], result['ecn']), (0, 0, 1))

    def test_no_options(self):
        self.value.update(olayout=[], packet_size=40, raw='')
        result = normalize(self.value)
        self.assertEqual((result['option_bytes'], result['option_sum'], result['needs_ts']), (0, 0, False))

    def test_reject_invalid_profiles(self):
        changes = [dict(mss=-1), dict(wsize_raw='mss*999'), dict(scale=15), dict(df=2),
                   dict(olayout=['bogus']), dict(olayout=['nop'] * 40),
                   dict(olayout=['eol+1','mss']), dict(packet_size=44), dict(raw=None), dict(raw=[]),
                   dict(olayout=['ts', 'ts'], packet_size=60),
                   dict(olayout=['nop', 'ts'], packet_size=52)]
        for change in changes:
            value = copy.deepcopy(self.value)
            value.update(change)
            with self.subTest(change=change):
                with self.assertRaises(ValueError):
                    normalize(value)


if __name__ == '__main__':
    unittest.main()
