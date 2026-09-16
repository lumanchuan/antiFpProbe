"""p0f text decoding and explicit signature checks, without network side effects."""
import re

HEADER = re.compile(r'\.-\[ ([0-9.]+)/([0-9]+) -> ([0-9.]+)/([0-9]+) \((syn(?:\+ack)?)\) \]-')


class Decoder:
    def __init__(self):
        self.current = None

    def feed(self, line):
        header = HEADER.search(line)
        if header:
            source, sport, target, dport, kind = header.groups()
            self.current = dict(source=source, sport=int(sport), target=target,
                                dport=int(dport), side='SYN' if kind == 'syn' else 'SYN-ACK')
        elif line.startswith('.-['):
            self.current = None
        elif self.current is not None:
            if line.startswith('`----'):
                result, self.current = self.current, None
                return result if result.get('raw_sig') else None
            match = re.match(r'\|\s+(os|params|raw_sig)\s+=\s+(.*)', line.strip())
            if match:
                self.current[match.group(1)] = match.group(2).strip()
        return None


def window_value(text, mss):
    if text.isdigit():
        return int(text)
    match = re.fullmatch(r'(mss|mtu)\*([0-9]+)', text)
    if match:
        return (mss if match.group(1) == 'mss' else mss + 40) * int(match.group(2))
    return None


def fields(signature):
    parts = signature.split(':')
    if len(parts) != 8:
        raise ValueError('Invalid p0f signature')
    window, scale = parts[4].split(',')
    mss = int(parts[3]) if parts[3].isdigit() else 0
    return dict(version=parts[0], ttl=int(parts[1].split('+')[0].rstrip('-')),
                ip_options=parts[2], mss=mss, window=window_value(window, mss),
                scale=int(scale) if scale.isdigit() else None,
                options=parts[5].split(',') if parts[5] else [],
                quirks=parts[6].split(',') if parts[6] else [], payload=parts[7])


def signature_matches(signature, normalized):
    actual = fields(signature)
    raw = normalized.get('raw', '').split(':')
    if len(raw) < 8:
        return None
    options = normalized['olayout']
    if 'end' in options:
        first = options.index('end')
        options = options[:first] + ['eol+' + str(len(options) - first - 1)]
    return (actual['version'] == '4' and actual['ip_options'] == '0'
            and actual['ttl'] == normalized['ttl']
            and ('mss' not in options or actual['mss'] == normalized['mss'])
            and actual['window'] == normalized['wsize']
            and ('ws' not in options or actual['scale'] == normalized['scale'])
            and actual['options'] == options and actual['payload'] == '0'
            and sorted(actual['quirks']) == sorted(filter(None, raw[6].split(','))))
