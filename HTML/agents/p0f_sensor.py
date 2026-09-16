"""Memory-only nic2 collector. No network settings, files or existing processes are changed."""
import argparse
import collections
import json
import os
import signal
import socket
import subprocess
import threading
import time
import urllib.request
import uuid

# Decoder is supplied by tools/sensor_bundle.py before this source is executed.


def run_sensor(background=False):
    lock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        lock.bind('\0osdisguise-p0f-sensor-nic2')
    except OSError:
        raise SystemExit('OSDisguise p0f sensor is already running; no process was stopped.')
    if background:
        pid = os.fork()
        if pid:
            print('OSDisguise p0f sensor PID {}'.format(pid), flush=True)
            return
        os.setsid()
        with open('/dev/null', 'rb+', buffering=0) as null:
            for fd in (0, 1, 2):
                os.dup2(null.fileno(), fd)
    running = threading.Event()
    running.set()
    signal.signal(signal.SIGTERM, lambda *_: running.clear())
    signal.signal(signal.SIGINT, lambda *_: running.clear())
    boot = uuid.uuid4().hex
    queue = collections.deque()
    guard = threading.Lock()
    context = {'epoch': ''}
    counter = [0]
    dropped = [0]
    child = None
    error = ''
    enabled = True
    last_success = time.monotonic()

    def read_output(process):
        decoder = Decoder()
        for line in process.stdout:
            event = decoder.feed(line.rstrip())
            if event and (event.get('source'), event.get('target')) != ('192.168.3.1', '192.168.3.2'):
                continue
            if event:
                try:
                    fields(event['raw_sig'])
                except (ValueError, TypeError, KeyError):
                    with guard:
                        dropped[0] += 1
                    continue
                with guard:
                    counter[0] += 1
                    event.update(id=boot + ':' + str(counter[0]), captured_at=time.time(), epoch=context.get('epoch', ''))
                    if len(queue) >= 512:
                        queue.popleft()
                        dropped[0] += 1
                    queue.append(event)

    def stop_capture(process):
        if process and process.poll() is None:
            process.send_signal(signal.SIGINT)
            try:
                process.wait(timeout=4)
            except subprocess.TimeoutExpired:
                # Only our own Popen child can reach this branch.
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()

    try:
        while running.is_set():
            if enabled and (child is None or child.poll() is not None):
                try:
                    child = subprocess.Popen(['/usr/bin/stdbuf', '-oL', '-eL', '/usr/sbin/p0f',
                        '-i', 'enp5s0f1', '-m', '256,512',
                        'ip and tcp and host 192.168.3.1 and host 192.168.3.2 and (tcp[13] & 2 != 0)'],
                        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                        universal_newlines=True, bufsize=1)
                    threading.Thread(target=read_output, args=(child,), daemon=True).start()
                    error = ''
                except OSError as exc:
                    error = str(exc)
            elif not enabled and child is not None:
                stop_capture(child)
                child = None
            try:
                with open('/sys/class/net/enp5s0f1/carrier') as stream:
                    carrier = stream.read().strip() == '1'
                address = json.loads(subprocess.check_output(['/sbin/ip', '-j', '-4', 'addr', 'show', 'dev', 'enp5s0f1'], timeout=2))
                ipv4 = ['{}/{}'.format(item['local'], item['prefixlen'])
                        for interface in address for item in interface.get('addr_info', [])
                        if item.get('family') == 'inet']
            except (OSError, ValueError, KeyError, subprocess.SubprocessError):
                carrier, ipv4 = False, []
            with guard:
                batch = list(queue)[:100]
            status = dict(pid=os.getpid(), p0f_pid=child.pid if child else None,
                          capture=bool(child and child.poll() is None), carrier=carrier,
                          ipv4=ipv4, kernel=os.uname().release, dropped=dropped[0],
                          error=error or ('p0f exited; check interface and installed binary' if child and child.poll() is not None else ''))
            request = urllib.request.Request(SENSOR_URL,
                data=json.dumps(dict(boot=boot, events=batch, status=status)).encode(),
                headers={'Content-Type': 'application/json', 'X-Sensor-Token': DEFAULT_TOKEN})
            try:
                with urllib.request.urlopen(request, timeout=4) as response:
                    reply = json.load(response)
                with guard:
                    acknowledged = {event['id'] for event in batch}
                    remaining = [event for event in queue if event['id'] not in acknowledged]
                    queue.clear()
                    queue.extend(remaining)
                    context.update(reply.get('context', {}))
                enabled = bool(reply.get('enabled', True))
                last_success = time.monotonic()
            except (OSError, ValueError):
                if time.monotonic() - last_success > 60:
                    enabled = False
                if time.monotonic() - last_success > 600:
                    break
            time.sleep(1)
    finally:
        stop_capture(child)
        lock.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--background', action='store_true')
    run_sensor(parser.parse_args().background)
