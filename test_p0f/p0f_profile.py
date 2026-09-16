"""Validate the existing p0f JSON schema before touching hardware tables."""
import copy
import re
import struct

LENGTHS = {'mss': 4, 'sok': 2, 'ts': 10, 'ws': 3, 'nop': 1, 'end': 1}


def integer(value, low, high, field):
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ValueError('{} must be an integer in [{}, {}]'.format(field, low, high))
    return value


def normalize(value):
    if not isinstance(value, dict) or not isinstance(value.get('os'), str) or not value['os'].strip():
        raise ValueError('fps.json must contain one fingerprint object with an os name')
    result = copy.deepcopy(value)
    raw_signature = value.get('raw', '')
    if not isinstance(raw_signature, str):
        raise ValueError('raw must be a p0f signature string')
    raw = raw_signature.split(':')
    if raw and raw[0] and (len(raw) < 8 or raw[0] not in ('*', '4') or raw[2] != '0' or raw[7] != '0'):
        raise ValueError('Only IPv4 SYN signatures without IP options or payload are supported')
    ttl = integer(value.get('ttl'), 1, 255, 'ttl')
    df = integer(value.get('df'), 0, 1, 'df')
    mss = integer(value.get('mss', 0), 0, 65535, 'mss')
    # The supplied database exporter encodes wildcard MSS as zero.
    if not mss:
        if len(raw) >= 8 and raw[3] not in ('*', ''):
            mss = integer(int(raw[3]), 1, 65535, 'raw MSS')
        else:
            mss = 1460
    wraw = str(value.get('wsize_raw', value.get('wsize', 0)))
    if re.match(r'^(mss|mtu)\*[1-9][0-9]*$', wraw):
        base, mult = wraw.split('*')
        window = (mss if base == 'mss' else mss + 40) * int(mult)
    elif wraw.isdigit():
        window = int(wraw)
    elif wraw == '*':
        window = value.get('wsize') or 65535
    else:
        raise ValueError('Unsupported window expression: ' + wraw)
    window = integer(window, 0, 65535, 'window')
    scale = integer(value.get('scale', 0), 0, 14, 'scale')
    layout = value.get('olayout')
    if not isinstance(layout, list):
        raise ValueError('olayout must be a list')
    options = []
    explicit_eol = False
    for index, option in enumerate(layout):
        if not isinstance(option, str):
            raise ValueError('option names must be strings')
        match = re.match(r'^eol\+([0-9]+)$', option)
        if match:
            if index != len(layout) - 1:
                raise ValueError('EOL must be the last option')
            options.extend(['end'] * (1 + integer(int(match.group(1)), 0, 39, 'EOL padding')))
            explicit_eol = True
        elif option in LENGTHS and option != 'end':
            options.append(option)
        else:
            raise ValueError('Unsupported TCP option: ' + option)
    length = sum(LENGTHS[x] for x in options)
    if explicit_eol and length % 4:
        raise ValueError('Explicit eol+N does not match a four-byte TCP header boundary')
    options.extend(['end'] * ((-length) % 4))
    length = sum(LENGTHS[x] for x in options)
    if len(options) > 10 or length > 40:
        raise ValueError('Fingerprint exceeds 10 option slots or 40 TCP option bytes')
    if any(options.count(option) > 1 for option in ('mss', 'sok', 'ts', 'ws')):
        raise ValueError('Repeated MSS, SACK, timestamp, or window-scale options are unsupported')
    if value.get('packet_size', 0) not in (0, 40 + length):
        raise ValueError('packet_size disagrees with the option layout')
    encoded = bytearray()
    for option in options:
        if option == 'ts' and len(encoded) % 2:
            raise ValueError('Timestamp at an odd byte offset is not supported')
        encoded.extend({'end': b'\x00', 'nop': b'\x01', 'sok': b'\x04\x02',
                        'mss': struct.pack('!BBH', 2, 4, mss), 'ws': struct.pack('!BBB', 3, 3, scale),
                        'ts': b'\x08\x0a' + b'\x00' * 8}[option])
    option_sum = sum((encoded[i] << 8) | encoded[i + 1] for i in range(0, len(encoded), 2))
    while option_sum >> 16:
        option_sum = (option_sum & 65535) + (option_sum >> 16)
    result.update(ttl=ttl, df=df, mss=mss, wsize=window, scale=scale,
                  olayout=options, option_bytes=length, needs_ts='ts' in options,
                  option_sum=option_sum, ecn=int(len(raw) >= 8 and 'ecn' in raw[6].split(',')))
    return result
