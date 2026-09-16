"""Shared helpers compatible with the SDE Python 3.5 runtime."""
import os


def pipeline_identity(program):
    for pid in os.listdir('/proc'):
        if not pid.isdigit():
            continue
        try:
            with open('/proc/' + pid + '/comm') as stream:
                if stream.read().strip() != 'bf_switchd':
                    continue
            with open('/proc/' + pid + '/stat') as stream:
                start = stream.read().rsplit(')', 1)[1].split()[19]
            with open('/proc/sys/kernel/random/boot_id') as stream:
                machine_boot = stream.read().strip()
            return '{}:{}:{}:{}'.format(program, machine_boot, pid, start)
        except (OSError, IndexError):
            continue
    raise RuntimeError('No bf_switchd process found')
