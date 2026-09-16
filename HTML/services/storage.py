import json
import sqlite3
import threading
import time
from collections import Counter


class Store:
    def __init__(self, path):
        self.lock = threading.RLock()
        self.db = sqlite3.connect(str(path), check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript('''
          PRAGMA journal_mode=WAL;
          CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY, time REAL, source TEXT,
            target TEXT, category TEXT, dport INTEGER, mode TEXT, session TEXT);
          CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY, source TEXT, target TEXT,
            first REAL, last REAL, probes INTEGER, confidence TEXT);
          CREATE TABLE IF NOT EXISTS counters(boot TEXT, category TEXT, value INTEGER,
            PRIMARY KEY(boot,category));
          CREATE TABLE IF NOT EXISTS samples(minute INTEGER, category TEXT, value INTEGER,
            PRIMARY KEY(minute,category));
          CREATE TABLE IF NOT EXISTS audit(time REAL, action TEXT, detail TEXT);
        ''')
        self.db.commit()

    def audit(self, action, detail):
        with self.lock, self.db:
            self.db.execute('INSERT INTO audit VALUES (?,?,?)', (time.time(), action, str(detail)))

    def ingest(self, state):
        with self.lock, self.db:
            for event in state.get('events', []):
                if self.db.execute('SELECT 1 FROM events WHERE id=?', (event['id'],)).fetchone():
                    continue
                previous = self.db.execute('SELECT * FROM sessions WHERE source=? AND target=? '
                    'ORDER BY last DESC LIMIT 1', (event['source'], event['target'])).fetchone()
                if previous and 0 <= event['time'] - previous['last'] <= 30:
                    sid = previous['id']
                    self.db.execute('UPDATE sessions SET last=?,probes=probes+1 WHERE id=?',
                                    (event['time'], sid))
                else:
                    sid = event['id']
                    self.db.execute('INSERT INTO sessions VALUES (?,?,?,?,?,?,?)',
                        (sid, event['source'], event['target'], event['time'], event['time'], 1, 'suspected'))
                self.db.execute('INSERT INTO events VALUES (?,?,?,?,?,?,?,?)',
                    (event['id'], event['time'], event['source'], event['target'],
                     event['category'], event['dport'], event['mode'], sid))
                kinds = [r[0] for r in self.db.execute('SELECT DISTINCT category FROM events WHERE session=?', (sid,))]
                if 'ECN' in kinds or len(kinds) >= 3:
                    self.db.execute('UPDATE sessions SET confidence=? WHERE id=?', ('high', sid))
            for name, value in state.get('counts', {}).items():
                old = self.db.execute('SELECT value FROM counters WHERE boot=? AND category=?',
                                      (state['boot'], name)).fetchone()
                old = old[0] if old else 0
                # A restart gets a new boot ID; never interpret a reset as a huge wrap delta.
                delta = max(0, value - old)
                self.db.execute('INSERT OR REPLACE INTO counters VALUES (?,?,?)',
                                (state['boot'], name, max(old, value)))
                minute = int(state['time'] // 60) * 60
                self.db.execute('INSERT OR IGNORE INTO samples VALUES (?,?,0)', (minute, name))
                self.db.execute('UPDATE samples SET value=value+? WHERE minute=? AND category=?',
                                (delta, minute, name))
            self.db.execute('DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY time DESC LIMIT 50000)')
            self.db.execute('DELETE FROM samples WHERE minute<?', (time.time() - 30 * 86400,))

    def snapshot(self):
        with self.lock:
            counts = dict(self.db.execute('SELECT category,SUM(value) FROM counters GROUP BY category'))
            sessions = [dict(r) for r in self.db.execute('SELECT * FROM sessions ORDER BY last DESC LIMIT 100')]
            events = [dict(r) for r in self.db.execute('SELECT * FROM events ORDER BY time DESC LIMIT 200')]
            total = self.db.execute('SELECT COUNT(*) FROM sessions').fetchone()[0]
            high = self.db.execute("SELECT COUNT(*) FROM sessions WHERE confidence='high'").fetchone()[0]
            chart = dict(self.db.execute('SELECT minute,SUM(value) FROM samples WHERE minute>? GROUP BY minute',
                                        (time.time() - 1800,)))
            audit = [dict(r) for r in self.db.execute('SELECT * FROM audit ORDER BY time DESC LIMIT 60')]
            return {'counts': counts, 'total': sum(counts.values()), 'scan_sessions': total,
                    'high_confidence': high, 'active_sources': len({s['source'] for s in sessions if time.time()-s['last'] < 30}),
                    'sessions': sessions, 'events': events, 'chart': chart, 'audit': audit}
