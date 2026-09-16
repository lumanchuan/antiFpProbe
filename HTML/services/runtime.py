import hashlib
import json
import os
import secrets
import signal
import socket
import subprocess
import threading
import time
from pathlib import Path

from release_config import PROJECT, SDE, SDE_INSTALL, SDE_PYTHON, switch_config
MODES = ('scan_monitor', 'antiFpProbe', 'p0f')
REQUIRED_PORTS = (52, 60)


def pending_ports(telemetry):
    ready = {p['port'] for p in telemetry.get('ports', [])
             if p.get('enabled') and p.get('up')}
    return [port for port in REQUIRED_PORTS if port not in ready]


def python_entrypoint(argv):
    index = 1
    while index < len(argv):
        arg = argv[index]
        if arg in ('-c', '-m'):
            return ''
        if arg in ('-W', '-X', '--check-hash-based-pycs'):
            index += 2
        elif arg == '--':
            index += 1
            break
        elif arg.startswith('-'):
            index += 1
        else:
            break
    return argv[index] if index < len(argv) else ''


def processes(proc_root=Path('/proc')):
    result = []
    for folder in proc_root.glob('[0-9]*'):
        try:
            argv = folder.joinpath('cmdline').read_bytes().decode(errors='replace').strip('\0').split('\0')
            stat = folder.joinpath('stat').read_text().rsplit(')', 1)[1].split()
            if not argv or stat[0] == 'Z':
                continue
            binary = Path(argv[0]).name
            plane = None
            if binary == 'bf_switchd':
                plane = 'data'
            elif 'python' in binary:
                # run_ptf_tests.py has a "--ptf bf-ptf" argument but is only a
                # waiting launcher. Signal the actual Python entrypoint instead.
                entrypoint = python_entrypoint(argv)
                if Path(entrypoint).name == 'bf-ptf' or entrypoint.endswith('/scan_monitor/controller.py'):
                    plane = 'control'
            if not plane:
                continue
            command = ' '.join(argv)
            mode = ('p0f' if '/p0f_control' in command or '/test_p0f' in command
                    else next((m for m in MODES if m in command), None))
            if plane == 'data':
                for i, arg in enumerate(argv):
                    if arg == '--conf-file' and i + 1 < len(argv):
                        mode = Path(argv[i + 1]).stem
                        if mode == 'antiFpProbe_p0f':
                            mode = 'p0f'
            result.append({'pid': int(folder.name), 'start': stat[19], 'plane': plane,
                           'program': mode or 'unknown', 'name': binary, 'command': command})
        except (OSError, IndexError, ValueError):
            continue
    return sorted(result, key=lambda p: (p['plane'], p['pid']))


def identity(items):
    return {(p['pid'], p['start'], p['command']) for p in items}


class Runtime:
    def __init__(self, root, store):
        self.root, self.store = root, store
        self.lock = threading.RLock()
        self.challenges = {}
        self.state = {'busy': False, 'stage': 'idle', 'message': '等待启动', 'error': None}
        self.children = []
        self.stop_event = threading.Event()
        threading.Thread(target=self.collect, daemon=True).start()

    def telemetry(self):
        try:
            value = json.loads((self.root / 'runtime/telemetry.json').read_text())
            value['fresh'] = time.time() - value['time'] < 8 and any(
                p['pid'] == value['pid'] and p['plane'] == 'control' for p in processes())
            value['fresh'] = value['fresh'] and any(p['plane'] == 'data' and p['program'] == value.get('program') for p in processes())
            return value
        except (OSError, ValueError, KeyError):
            return {'fresh': False, 'ready': False, 'counts': {}, 'ports': []}

    def collect(self):
        while not self.stop_event.wait(1):
            try:
                telemetry = self.telemetry()
                if telemetry['fresh'] and telemetry.get('program') != 'p0f':
                    self.store.ingest(telemetry)
                with self.lock:
                    self.children = [p for p in self.children if p.poll() is None]
            except Exception as error:
                self.store.audit('collector_error', str(error))
                self.stop_event.wait(5)

    def snapshot(self):
        with self.lock:
            telemetry = self.telemetry()
            missing = pending_ports(telemetry)
            return dict(self.state, processes=processes(), telemetry=telemetry,
                        pending_ports=missing,
                        link_ready=bool(telemetry['fresh'] and telemetry.get('ready') and not missing))

    def prepare(self, mode, action):
        if mode not in MODES or action not in ('start', 'stop'):
            raise ValueError('无效的模式或操作')
        with self.lock:
            if self.state['busy']:
                raise ValueError('已有启动或停止任务，请等待完成')
            current = processes()
            token = secrets.token_urlsafe(24)
            self.challenges = {token: {'mode': mode, 'action': action, 'processes': current, 'expires': time.time() + 90}}
            return {'token': token, 'processes': current, 'confirmation_required': True,
                    'mode': mode, 'action': action}

    def commit(self, token):
        with self.lock:
            challenge = self.challenges.pop(token, None)
            if not challenge or time.time() > challenge['expires']:
                raise ValueError('确认已过期，请重新检查进程')
            if self.state['busy']:
                raise ValueError('后台正在执行操作')
            if identity(processes()) != identity(challenge['processes']):
                raise ValueError('运行进程已发生变化，未停止任何进程。请重新确认')
            self.state = {'busy': True, 'stage': 'stopping' if challenge['processes'] else 'data',
                          'message': '正在准备操作', 'error': None, 'mode': challenge['mode']}
            threading.Thread(target=self.execute, args=(challenge,), daemon=True).start()

    def cancel(self, token):
        with self.lock:
            self.challenges.pop(token, None)

    def preflight(self, mode):
        path = switch_config(mode)
        if not path.is_file():
            raise RuntimeError('缺少预编译配置，未停止当前程序：' + str(path))
        config = json.loads(path.read_text())
        program = config['p4_devices'][0]['p4_programs'][0]
        pipe = program['p4_pipelines'][0]
        for asset in (program['bfrt-config'], pipe['config'], pipe['context']):
            if not Path(asset).is_file():
                raise RuntimeError('缺少编译产物，未停止当前程序：' + asset)
            if path.parent.resolve() not in Path(asset).resolve().parents:
                raise RuntimeError('构建路径不属于当前目录，请先执行 build.py --config-only，未停止当前程序')

    def update(self, stage, message):
        with self.lock:
            self.state.update(stage=stage, message=message)
        self.store.audit(stage, message)

    def stop_confirmed(self, confirmed):
        # Check PID identity again immediately before every signal; do not signal process groups.
        for process in sorted(confirmed, key=lambda p: p['plane'] != 'control'):
            expected = identity([process])
            current = [p for p in processes() if p['pid'] == process['pid']]
            if not current:
                continue
            if identity(current) != expected:
                raise RuntimeError('PID 已被复用，停止操作已取消')
            self.update('stopping', '正在退出 {}，PID {}'.format(process['program'], process['pid']))
            os.kill(process['pid'], signal.SIGINT if process['plane'] == 'control' else signal.SIGQUIT)
            for _ in range(60):
                if not any(p['pid'] == process['pid'] and p['start'] == process['start'] for p in processes()):
                    break
                time.sleep(0.25)
            else:
                raise RuntimeError('PID {} 未退出，未强制杀死；请检查日志后重试'.format(process['pid']))

    def launch(self, command, name):
        environment = dict(os.environ)
        environment.pop('PYTHONHOME', None)
        environment.pop('PYTHONPATH', None)
        environment.update(SDE=str(SDE), SDE_INSTALL=str(SDE_INSTALL),
            PATH='/usr/bin:/bin:' + str(SDE_INSTALL / 'bin'), PYTHONUNBUFFERED='1', TERM='dumb')
        path = self.root / ('runtime/' + name + '.log')
        if path.exists() and path.stat().st_size > 8 * 1024 * 1024:
            os.replace(path, path.with_suffix('.previous.log'))
        with open(path, 'ab', buffering=0) as log:
            log.write(('\n=== START {} ===\n'.format(time.strftime('%Y-%m-%d %H:%M:%S'))).encode())
            proc = subprocess.Popen(command, cwd=str(SDE), env=environment,
                stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        self.children.append(proc)
        return proc

    def device_ready(self, mode):
        if not any(p['plane'] == 'data' and p['program'] == mode for p in processes()):
            return False
        try:
            with socket.create_connection(('127.0.0.1', 7777), timeout=1) as conn:
                conn.sendall(b'0')
                if conn.recv(1) != b'1':
                    return False
            check = subprocess.run([SDE_PYTHON, str(self.root / 'tools/ready.py'), 'antiFpProbe' if mode == 'p0f' else mode],
                capture_output=True, timeout=8)
            return check.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return False

    def wait_for_links(self, mode, started, proc, timeout=90):
        deadline = time.monotonic() + timeout
        stable_since = first_sample = None
        last_message = None
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise RuntimeError('等待链路时控制面已退出；数据面保留运行，请检查控制面日志')
            data = self.telemetry()
            current = (data['fresh'] and data.get('ready') and data.get('program') == mode
                       and data.get('time', 0) > started)
            missing = pending_ports(data)
            if current and not missing:
                if stable_since is None:
                    stable_since, first_sample = time.monotonic(), data['time']
                # Require another hardware sample after the link has settled.
                if time.monotonic() - stable_since >= 2 and data['time'] > first_sample:
                    return
                message = 'DEV 52 / 60 已连接，正在确认链路稳定'
            else:
                stable_since = first_sample = None
                message = ('控制面已就绪，等待 100G 链路：DEV ' + ' / '.join(map(str, missing))
                           if current else '等待控制面上报最新链路状态')
            if message != last_message:
                self.update('links', message)
                last_message = message
            time.sleep(1)
        raise RuntimeError('链路在 {} 秒内未就绪：{}。程序保留运行，请检查网卡、线缆和 FEC/协商状态'.format(
            timeout, last_message or '未收到有效端口状态'))

    def execute(self, challenge):
        mode = challenge['mode']
        try:
            if challenge['action'] == 'start':
                self.preflight(mode)
            self.stop_confirmed(challenge['processes'])
            if processes():
                raise RuntimeError('检测到新的交换机进程，已取消后续启动')
            if challenge['action'] == 'stop':
                self.update('idle', '数据面与控制面已停止，监测暂停')
                return
            self.update('data', '正在启动数据面：' + mode)
            command = [str(SDE / 'run_switchd.sh')]
            command += ['-c', str(switch_config(mode))]
            command += ['--server-listen-local-only', '--', '--background']
            proc = self.launch(command, 'data')
            deadline = time.monotonic() + 180
            while time.monotonic() < deadline:
                if self.device_ready(mode):
                    break
                if proc.poll() is not None:
                    raise RuntimeError('数据面进程提前退出；控制面未启动，请检查数据面日志')
                time.sleep(2)
            else:
                raise RuntimeError('数据面 180 秒内未就绪；控制面未启动，保留现场供检查')
            self.update('control', '设备初始化与 BFRT 已就绪，正在启动控制面')
            if mode == 'scan_monitor':
                command = [SDE_PYTHON, str(PROJECT / 'monitor/scan_monitor/controller.py')]
            else:
                command = [str(SDE / 'run_p4_tests.sh'), '-p', 'antiFpProbe', '-t',
                           str(self.root / ('p0f_control' if mode == 'p0f' else 'control_plane')), '--target', 'tofino']
            started = time.time()
            proc = self.launch(command, 'control')
            deadline = time.monotonic() + 90
            while time.monotonic() < deadline:
                data = self.telemetry()
                if data['fresh'] and data.get('ready') and data.get('program') == mode and data.get('time', 0) > started:
                    self.wait_for_links(mode, started, proc)
                    self.update('running', ('监测转发已运行' if mode == 'scan_monitor' else 'p0f 指纹已下发' if mode == 'p0f' else 'Nmap 抗测绘规则已下发')
                                + '；DEV 52 / 60 链路已就绪')
                    return
                if proc.poll() is not None:
                    raise RuntimeError('控制面提前退出；数据面保留运行，请检查控制面日志')
                time.sleep(1)
            raise RuntimeError('未收到控制面就绪状态；请检查日志和端口状态')
        except Exception as error:
            with self.lock:
                self.state.update(stage='error', error=str(error), message=str(error))
            self.store.audit('operation_failed', str(error))
        finally:
            with self.lock:
                self.state['busy'] = False

    def log(self, name):
        if name not in ('data', 'control'):
            raise ValueError('无效的日志类型')
        path = self.root / ('runtime/' + name + '.log')
        if not path.exists():
            return ''
        with open(path, 'rb') as stream:
            stream.seek(max(0, path.stat().st_size - 24000))
            return stream.read().decode(errors='replace').replace('\x1b', '')
