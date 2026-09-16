import hashlib
import json
import os
import subprocess
import threading
from pathlib import Path


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'))


def atomic_json(path, value):
    temp = path.with_suffix('.tmp')
    with open(temp, 'w', encoding='utf-8') as out:
        json.dump(value, out, ensure_ascii=False, indent=2)
        out.flush()
        os.fsync(out.fileno())
    os.replace(temp, path)


class Profiles:
    kind = 'nmap'

    def __init__(self, root):
        self.root = root
        self.directory = root / 'profiles'
        self.directory.mkdir(exist_ok=True)
        self.active_path = root / 'runtime/controller_state/fps.json'
        self.lock = threading.RLock()

    def validate(self, value):
        raw = json.dumps(value)
        if len(raw) > 1024 * 1024:
            raise ValueError('指纹文件超过 1 MB')
        proc = subprocess.run(['/usr/bin/python3', str(self.root / 'tools/profile_bridge.py')],
            input=raw, text=True, capture_output=True, timeout=10)
        try:
            result = json.loads(proc.stdout)
        except ValueError:
            raise ValueError('指纹校验程序异常：' + proc.stderr[-500:])
        if not result['ok']:
            raise ValueError(result['error'])
        return result['value']

    def add(self, value):
        with self.lock:
            value = self.validate(value)
            ident = hashlib.sha256(canonical(value).encode()).hexdigest()
            atomic_json(self.directory / (ident + '.json'), value)
            return ident

    def catalog(self):
        result = []
        candidates = self.candidate_metadata()
        for path in self.directory.glob('*.json'):
            value = json.loads(path.read_text())
            result.append({'id': path.stem, 'name': value['OS'],
                'family': self.family(value['OS']),
                'ttl': value.get('T1', {}).get('TG'), 'window': value.get('WIN', {}).get('W1'),
                'isn': len(value.get('ISN', {})), 'class': value.get('_class', ''),
                **candidates.get(path.stem, {})})
        return sorted(result, key=lambda p: (p['name'], p.get('source_index', -1), p['id']))

    @staticmethod
    def family(name):
        lower = name.lower()
        for keyword, family in [('windows', 'Windows'), ('freebsd', 'FreeBSD'),
                                ('mac', 'Mac'), ('linux', 'Linux')]:
            if keyword in lower:
                return family
        return 'Other'

    def candidate_metadata(self):
        path = self.root / 'validation/catalog/candidates.json'
        if not path.is_file():
            return {}
        candidates = json.loads(path.read_text())
        return {item['id']: dict(candidate=True, source_index=item['source_index'],
                                variant='库条目 #{}'.format(item['source_index'] + 1))
                for item in candidates
                if item.get('tool') == self.kind and item.get('schema_valid') is True}

    def get(self, ident):
        if len(ident) != 64 or any(c not in '0123456789abcdef' for c in ident):
            raise ValueError('无效的指纹 ID')
        path = self.directory / (ident + '.json')
        if not path.is_file():
            raise ValueError('找不到该指纹')
        return json.loads(path.read_text())

    def select(self, ident):
        with self.lock:
            value = self.validate(self.get(ident))
            atomic_json(self.active_path, value)
            return value

    def selected(self):
        with self.lock:
            value = json.loads(self.active_path.read_text())
            return {'id': hashlib.sha256(canonical(value).encode()).hexdigest(), 'name': value['OS']}
