#!/usr/bin/env python3
import fcntl
import hmac
import json
import os
import secrets
import sys
import threading
import time
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'vendor'))
from flask import Flask, abort, jsonify, render_template, request, session
from services.profiles import Profiles
from services.runtime import Runtime
from services.storage import Store
from services.p0f import P0fProfiles, P0fMonitor
from release_config import SETTINGS


def create_app(root=ROOT, testing=False):
    app = Flask(__name__)
    runtime_dir = root / 'runtime'
    runtime_dir.mkdir(exist_ok=True)
    secret_path = runtime_dir / 'admin.token'
    if not secret_path.exists():
        fd = os.open(str(secret_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as out:
            out.write(secrets.token_urlsafe(18))
    secret = secret_path.read_text().strip()
    app.secret_key = secret
    app.config.update(MAX_CONTENT_LENGTH=1024 * 1024, SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Strict', PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
        TRUSTED_HOSTS=SETTINGS.get('trusted_hosts', ['127.0.0.1', 'localhost']), TESTING=testing)
    store = Store(runtime_dir / 'monitor.sqlite3')
    profiles = Profiles(root)
    runtime = Runtime(root, store)
    p0f_profiles = P0fProfiles(root)
    p0f = P0fMonitor(root, store, p0f_profiles)
    app.extensions.update(store=store, profiles=profiles, runtime=runtime, p0f=p0f, p0f_profiles=p0f_profiles)
    failures = {}
    auth_lock = threading.Lock()

    @app.context_processor
    def deployment_context():
        return {'deployment': {'switch_label': SETTINGS.get('switch_label', 'Tofino1'),
                               'asset_label': SETTINGS.get('asset_label', 'Linux 2.6'),
                               'verified_kernel': SETTINGS.get('verified_kernel', '未核验')}}

    @app.before_request
    def protect():
        if request.path.startswith('/api/') and request.method == 'POST':
            if not request.is_json or not isinstance(request.get_json(silent=True), dict):
                raise ValueError('请求必须为 JSON 对象')
        if request.path == '/api/p0f/ingest':
            if request.remote_addr not in SETTINGS.get('sensor_allowed_ips', ['127.0.0.1']) or not hmac.compare_digest(request.headers.get('X-Sensor-Token', ''), p0f.token):
                abort(403)
            return
        if not request.path.startswith('/api/') or request.path == '/api/login':
            return
        if not session.get('authorized'):
            abort(401)
        if request.method != 'GET':
            if not hmac.compare_digest(request.headers.get('X-CSRF-Token', ''), session.get('csrf', '-')):
                abort(403)
            origin = request.headers.get('Origin')
            if origin and origin != request.host_url.rstrip('/'):
                abort(403)

    @app.after_request
    def headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['Cache-Control'] = 'no-store'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        return response

    @app.errorhandler(ValueError)
    def invalid(error):
        return jsonify(error=str(error)), 400

    @app.errorhandler(401)
    @app.errorhandler(403)
    @app.errorhandler(413)
    @app.errorhandler(429)
    def http_error(error):
        return jsonify(error={401: '请先登录', 403: '请求校验失败，请刷新页面',
                              413: '文件超过 1 MB', 429: '尝试过于频繁，请稍后再试'}[error.code]), error.code

    @app.route('/')
    def index():
        return render_template('gateway.html')

    @app.route('/nmap')
    def nmap_page():
        return render_template('index.html')

    @app.route('/p0f')
    def p0f_page():
        return render_template('p0f.html')

    @app.post('/api/login')
    def login():
        ip = request.remote_addr
        with auth_lock:
            now = time.time()
            failures[ip] = [t for t in failures.get(ip, []) if now - t < 60]
            if len(failures[ip]) >= 8:
                abort(429)
            token = (request.get_json(silent=True) or {}).get('token', '')
            if not isinstance(token, str) or not hmac.compare_digest(token, secret):
                failures[ip].append(now)
                abort(401)
            failures.pop(ip, None)
        session.clear()
        session.update(authorized=True, csrf=secrets.token_urlsafe(24))
        session.permanent = True
        return jsonify(csrf=session['csrf'])

    @app.post('/api/logout')
    def logout():
        session.clear()
        return jsonify(ok=True)

    @app.get('/api/state')
    def state():
        return jsonify(runtime=runtime.snapshot(), statistics=store.snapshot(),
                       selected=profiles.selected(), csrf=session['csrf'],
                       asset={'label': SETTINGS.get('asset_label', 'Linux 2.6'), 'ip': '192.168.3.2',
                              'verified_kernel': SETTINGS.get('verified_kernel', '未核验'),
                              'verified_at': SETTINGS.get('verified_at', '')})

    @app.post('/api/operation/prepare')
    def prepare():
        value = request.get_json() or {}
        return jsonify(runtime.prepare(value.get('mode'), value.get('action')))

    @app.post('/api/operation/confirm')
    def confirm():
        value = request.get_json() or {}
        runtime.commit(value.get('token'))
        return jsonify(ok=True), 202

    @app.get('/api/profiles')
    def catalog():
        return jsonify(profiles=profiles.catalog())

    @app.post('/api/operation/cancel')
    def cancel_operation():
        runtime.cancel(request.get_json().get('token'))
        return jsonify(ok=True)

    @app.get('/api/profiles/<ident>')
    def profile(ident):
        return jsonify(profiles.get(ident))

    @app.post('/api/profiles/import')
    def import_profile():
        ident = profiles.add(request.get_json())
        store.audit('profile_import', profiles.get(ident)['OS'])
        return jsonify(id=ident)

    @app.post('/api/profiles/select')
    def select_profile():
        with runtime.lock:
            if runtime.state['busy']:
                raise ValueError('正在切换程序，请等待完成后更换指纹')
            value = profiles.select((request.get_json() or {}).get('id', ''))
            store.audit('profile_select', value['OS'])
            return jsonify(name=value['OS'], status='pending')

    @app.get('/api/logs/<name>')
    def logs(name):
        return jsonify(text=runtime.log(name))

    @app.get('/api/export')
    def export():
        result = jsonify(exported_at=time.time(), **store.snapshot())
        result.headers['Content-Disposition'] = 'attachment; filename="osdisguise-monitor.json"'
        return result

    @app.post('/api/p0f/ingest')
    def ingest_p0f():
        try:
            return jsonify(p0f.ingest(request.get_json(), runtime.snapshot()))
        except (KeyError, TypeError, IndexError) as exc:
            raise ValueError('采集字段缺失或无效') from exc

    @app.get('/api/p0f/state')
    def p0f_state():
        snapshot = runtime.snapshot()
        return jsonify(runtime=snapshot, statistics=p0f.snapshot(snapshot), selected=p0f_profiles.selected(), csrf=session['csrf'])

    @app.get('/api/p0f/profiles')
    def p0f_catalog():
        return jsonify(profiles=p0f_profiles.catalog())

    @app.get('/api/p0f/profiles/<ident>')
    def p0f_profile(ident):
        return jsonify(p0f_profiles.get(ident))

    @app.post('/api/p0f/profiles/import')
    def p0f_import():
        ident = p0f_profiles.add(request.get_json())
        store.audit('p0f_profile_import', p0f_profiles.get(ident)['os'])
        return jsonify(id=ident)

    @app.post('/api/p0f/profiles/select')
    def p0f_select():
        with runtime.lock:
            if runtime.state['busy']:
                raise ValueError('程序切换期间不能更换指纹')
            selected = p0f_profiles.select(request.get_json().get('id', ''))
            store.audit('p0f_profile_select', selected['os'])
            return jsonify(name=selected['os'], status='pending')

    @app.post('/api/p0f/sensor')
    def p0f_sensor():
        enabled = request.get_json().get('enabled')
        if type(enabled) is not bool:
            raise ValueError('enabled 必须为布尔值')
        p0f.enabled = enabled
        store.audit('p0f_sensor', 'resume' if enabled else 'pause')
        return jsonify(ok=True)

    @app.get('/api/p0f/export')
    def p0f_export():
        result = jsonify(exported_at=time.time(), **p0f.snapshot(runtime.snapshot(), export=True))
        result.headers['Content-Disposition'] = 'attachment; filename="p0f-observations.json"'
        return result

    return app


if __name__ == '__main__':
    if not (ROOT / 'runtime/controller_state/fps.json').exists():
        raise SystemExit('Run scripts/configure.py before starting the dashboard.')
    lock = open(ROOT / 'runtime/dashboard.lock', 'w')
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise SystemExit('Dashboard is already running')
    os.chmod(ROOT / 'runtime', 0o700)
    app = create_app()
    app.run(host=SETTINGS.get('web_host', '127.0.0.1'), port=SETTINGS.get('web_port', 5080),
            debug=False, threaded=True, use_reloader=False)
