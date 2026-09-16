import hashlib
import importlib.util
import ipaddress
import json
import math
import os
import secrets
import sys
import threading
import time
from pathlib import Path

from services.profiles import Profiles, atomic_json, canonical

SOURCE = Path(__file__).resolve().parents[2] / 'test_p0f'
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from p0f_format import fields, signature_matches


def normalizer():
    spec = importlib.util.spec_from_file_location('p0f_validation', str(SOURCE / 'p0f_profile.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.normalize


class P0fProfiles(Profiles):
    kind = 'p0f'

    def __init__(self, root):
        self.root = root
        self.directory = root / 'profiles_p0f'
        self.directory.mkdir(exist_ok=True)
        self.active_path = root / 'runtime/p0f_state/fps.json'
        self.active_path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.normalize = normalizer()
        if not list(self.directory.glob('*.json')):
            for path in sorted((SOURCE / 'examples').glob('*.json')):
                self.add(json.loads(path.read_text()))
        if not self.active_path.exists():
            initial = json.loads((SOURCE / 'fps.json').read_text())
            ident = self.add(initial)
            if not self.compatibility(self.normalize(initial))['supported']:
                ident = next(item['id'] for item in self.catalog() if item['supported'])
            self.select(ident)

    @staticmethod
    def compatibility(value):
        supported = value['needs_ts']
        return dict(supported=supported, reason='' if supported else
            '当前预编译管线在 Linux 输入下移除 TCP 时间戳会出现校验和错误，暂不可启用此目标。')

    def select(self, ident):
        support = self.compatibility(self.normalize(self.get(ident)))
        if not support['supported']:
            raise ValueError(support['reason'])
        return super().select(ident)

    def validate(self, value):
        if len(json.dumps(value)) > 65536:
            raise ValueError('p0f 指纹文件超过 64 KB')
        self.normalize(value)
        return value

    def catalog(self):
        result = []
        candidates = self.candidate_metadata()
        for path in self.directory.glob('*.json'):
            value = self.normalize(json.loads(path.read_text()))
            result.append(dict(id=path.stem, name=value['os'], ttl=value['ttl'],
                               family=self.family(value['os']),
                               mss=value['mss'], window=value['wsize'], scale=value['scale'],
                               options=value['olayout'], option_bytes=value['option_bytes'],
                               **self.compatibility(value), **candidates.get(path.stem, {})))
        return sorted(result, key=lambda value: (value['name'], value.get('source_index', -1), value['id']))

    def selected(self):
        with self.lock:
            value = json.loads(self.active_path.read_text())
            return dict(id=hashlib.sha256(canonical(value).encode()).hexdigest(),
                        name=value['os'], **{key: self.normalize(value)[key]
                            for key in ('ttl', 'mss', 'wsize', 'scale', 'option_bytes')})


class P0fMonitor:
    def __init__(self, root, store, profiles):
        self.root, self.store, self.profiles = root, store, profiles
        self.sensor = {'online': False, 'capture': False, 'error': '等待 nic2 采集器连接'}
        self.enabled = True
        path = root / 'runtime/p0f-sensor.token'
        if not path.exists():
            fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w') as out:
                out.write(secrets.token_urlsafe(32))
        self.token = path.read_text().strip()
        with store.lock, store.db:
            store.db.executescript('''
                CREATE TABLE IF NOT EXISTS p0f_events(
                  id TEXT PRIMARY KEY, time REAL, captured_at REAL, source TEXT, sport INTEGER,
                  target TEXT, dport INTEGER, side TEXT, os TEXT, params TEXT, raw_sig TEXT,
                  ttl INTEGER, mss INTEGER, window INTEGER, scale INTEGER, options TEXT,
                  mode TEXT, profile TEXT, matched INTEGER, epoch TEXT);
                CREATE INDEX IF NOT EXISTS p0f_time ON p0f_events(time);
                CREATE INDEX IF NOT EXISTS p0f_epoch ON p0f_events(epoch);
            ''')

    @staticmethod
    def context(runtime):
        data = runtime.get('telemetry', {})
        active = data.get('active') or {}
        valid = data.get('fresh') and data.get('ready') and not runtime.get('busy')
        mode = data.get('program', 'idle') if valid else 'transition' if runtime.get('busy') else 'idle'
        return dict(mode=mode, epoch='{}:{}'.format(data.get('boot', ''), active.get('sha', '')) if valid else '')

    def ingest(self, payload, runtime):
        if not isinstance(payload, dict) or not isinstance(payload.get('events'), list) or len(payload['events']) > 100:
            raise ValueError('采集数据格式无效')
        boot = payload.get('boot')
        if not isinstance(boot, str) or len(boot) != 32 or any(c not in '0123456789abcdef' for c in boot):
            raise ValueError('采集器标识无效')
        now = time.time()
        context = self.context(runtime)
        selected = self.profiles.selected()
        actual_profile = runtime.get('telemetry', {}).get('active') or {}
        expected = None
        if context['mode'] == 'p0f' and actual_profile.get('sha') == selected['id']:
            expected = self.profiles.normalize(self.profiles.get(selected['id']))
        rows = []
        for event in payload['events']:
            if not isinstance(event, dict):
                raise ValueError('指纹事件必须为对象')
            ident = event.get('id', '')
            if not isinstance(ident, str) or not ident.startswith(boot + ':') or len(ident) > 70:
                raise ValueError('事件标识无效')
            source, target = str(ipaddress.IPv4Address(event['source'])), str(ipaddress.IPv4Address(event['target']))
            if (source, target) != ('192.168.3.1', '192.168.3.2'):
                raise ValueError('事件不属于当前实验链路')
            for key in ('sport', 'dport'):
                if type(event.get(key)) is not int or not 1 <= event[key] <= 65535:
                    raise ValueError('TCP 端口无效')
            if event.get('side') not in ('SYN', 'SYN-ACK'):
                raise ValueError('事件类型无效')
            for key in ('raw_sig', 'os', 'params'):
                if not isinstance(event.get(key, ''), str) or len(event.get(key, '')) > 1024:
                    raise ValueError('指纹文本无效')
            captured = event.get('captured_at', 0)
            if not isinstance(captured, (int, float)) or not math.isfinite(captured):
                raise ValueError('采集时间无效')
            detail = fields(event['raw_sig'])
            same_epoch = bool(context['epoch'] and event.get('epoch') == context['epoch'])
            matched = signature_matches(event['raw_sig'], expected) if (expected and same_epoch and event['side'] == 'SYN') else None
            rows.append((ident, now, captured, source, event['sport'], target, event['dport'], event['side'],
                         event.get('os', '???'), event.get('params', ''), event['raw_sig'],
                         detail['ttl'], detail['mss'], detail['window'], detail['scale'], json.dumps(detail['options']),
                         context['mode'] if same_epoch else 'transition', selected['id'] if expected and same_epoch else '',
                         matched, context['epoch'] if same_epoch else ''))
        status = payload.get('status', {})
        if not isinstance(status, dict):
            raise ValueError('采集器状态无效')
        clean = {key: status.get(key) for key in ('pid', 'p0f_pid', 'capture', 'carrier', 'ipv4', 'kernel', 'error', 'dropped')}
        clean = json.loads(json.dumps(clean))
        if len(json.dumps(clean)) > 4096:
            raise ValueError('采集器状态过大')
        for key in ('pid', 'p0f_pid', 'dropped'):
            if clean[key] is not None and (type(clean[key]) is not int or clean[key] < 0):
                raise ValueError('采集器数值状态无效')
        for key in ('capture', 'carrier'):
            if clean[key] is not None and type(clean[key]) is not bool:
                raise ValueError('采集器链路状态无效')
        for key in ('kernel', 'error'):
            if clean[key] is not None and not isinstance(clean[key], str):
                raise ValueError('采集器文本状态无效')
        if clean['ipv4'] is not None and (not isinstance(clean['ipv4'], list) or
                any(not isinstance(value, str) for value in clean['ipv4'])):
            raise ValueError('采集器地址状态无效')
        with self.store.lock, self.store.db:
            self.sensor = dict(clean, boot=boot, time=now, online=True)
            self.store.db.executemany('INSERT OR IGNORE INTO p0f_events VALUES (' + ','.join('?' * 20) + ')', rows)
            self.store.db.execute('DELETE FROM p0f_events WHERE id NOT IN (SELECT id FROM p0f_events ORDER BY time DESC LIMIT 50000)')
        return dict(enabled=self.enabled, context=context)

    def snapshot(self, runtime, export=False):
        context = self.context(runtime)
        with self.store.lock:
            db = self.store.db
            sensor = dict(self.sensor, online=time.time() - self.sensor.get('time', 0) < 8, enabled=self.enabled)
            counts = dict(db.execute('SELECT side,COUNT(*) FROM p0f_events GROUP BY side'))
            events = [dict(row) for row in db.execute('SELECT * FROM p0f_events ORDER BY time DESC,rowid DESC LIMIT ?',
                (50000 if export else 300,))]
            for event in events:
                event['options'] = json.loads(event['options'])
            evaluated, matched = db.execute('SELECT COUNT(matched),COALESCE(SUM(matched),0) FROM p0f_events WHERE epoch=? AND profile=?',
                (context['epoch'], self.profiles.selected()['id'])).fetchone()
            recent_os = [dict(row) for row in db.execute('SELECT os,COUNT(*) AS count FROM p0f_events WHERE side=? GROUP BY os ORDER BY count DESC LIMIT 8', ('SYN',))]
            chart = dict(db.execute('SELECT CAST(time/60 AS INTEGER)*60,COUNT(*) FROM p0f_events WHERE time>? GROUP BY 1', (time.time()-1800,)))
            return dict(now=time.time(), sensor=sensor, counts=counts, events=events, os_distribution=recent_os, chart=chart,
                        evaluated=evaluated, matched=matched, context=context,
                        active_sources=db.execute('SELECT COUNT(DISTINCT source) FROM p0f_events WHERE time>?', (time.time()-30,)).fetchone()[0])
