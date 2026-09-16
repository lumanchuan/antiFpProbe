import logging
import time
import os
import signal
import traceback
import json
from pprint import pprint
import random
import struct
from copy import deepcopy
from ipaddress import IPv4Address

from bfruntime_client_base_tests import BfRuntimeTest
import bfrt_grpc.client as gc

logger = logging.getLogger('Test')
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler())

P1_6_IDS = tuple(range(8, 14))
ACK_OPS = {'S+': 1, 'S': 2, 'Z': 3, 'O': 4, 'O|S': 2, 'O|S+': 1}
SEQ_OPS = {'A': 1, 'Z': 2, 'O': 3, 'A|O': 1}
TCP_FLAGS = {'F': 1, 'S': 2, 'R': 4, 'P': 8, 'A': 16, 'U': 32, 'E': 64, 'C': 128}
OPTION_SIZES = {'eop': 1, 'nop': 1, 'mss': 4, 'ws': 3, 'sok': 2, 'ts': 10}
TEST_DIR = os.path.dirname(os.path.abspath(__file__))


def checked_uint(value, bits, field):
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < (1 << bits):
        raise ValueError('{} must be an unsigned {}-bit integer'.format(field, bits))
    return value


def option_config(options, field='O', slots=10):
    if not isinstance(options, list):
        raise ValueError('{} must be a list'.format(field))
    config = {'mss': 0, 'scale': 0, 'tsval': 232561103, 'tsecr': 0, 'olayout': []}
    seen = set()
    for option in options:
        if not isinstance(option, dict) or len(option) != 1:
            raise ValueError('{}: each option must contain exactly one key'.format(field))
        name, value = next(iter(option.items()))
        if not isinstance(name, str):
            raise ValueError('{}: option names must be strings'.format(field))
        name = name.lower()
        if name == 'mss':
            kind = 'mss'
            config['mss'] = checked_uint(value, 16, field + '.mss')
        elif name == 'w':
            kind = 'ws'
            config['scale'] = checked_uint(value, 8, field + '.w')
        elif name.startswith('nop'):
            # In this JSON format the value labels a NOP; it is not a repeat count.
            kind = 'nop'
        elif name.startswith(('eop', 'eol')):
            kind = 'eop'
        elif name == 'sack':
            kind = 'sok'
        elif name == 'ts':
            kind = 'ts'
        else:
            raise ValueError('{}: unsupported option {}'.format(field, name))
        if kind not in ('nop', 'eop') and kind in seen:
            raise ValueError('{}: duplicate {} cannot be represented by this pipeline'.format(field, name))
        seen.add(kind)
        config['olayout'].append(kind)
    length = sum(OPTION_SIZES[kind] for kind in config['olayout'])
    padding = (-length) % 4
    if length + padding > 40 or len(config['olayout']) + padding > slots:
        raise ValueError('{} exceeds TCP option length or the {} P4 option slots'.format(field, slots))
    return config


def tcp_option_sum(config):
    encoded = []
    for kind in config['olayout']:
        if kind == 'mss':
            encoded.append(struct.pack('!BBH', 2, 4, config['mss']))
        elif kind == 'ws':
            encoded.append(struct.pack('!BBB', 3, 3, config['scale']))
        elif kind == 'ts':
            encoded.append(struct.pack('!BBII', 8, 10, config['tsval'], config['tsecr']))
        else:
            encoded.append({'eop': b'\x00', 'nop': b'\x01', 'sok': b'\x04\x02'}[kind])
    raw = b''.join(encoded)
    raw += b'\x00' * ((-len(raw)) % 4)
    total = sum(struct.unpack('!{}H'.format(len(raw) // 2), raw)) if raw else 0
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return total


def icmp_reply_fields(ie, index):
    df = {'N': (0, 0), 'Y': (1, 1), 'S': (1, 0), 'O': (0, 1)}[ie['DFI']][index]
    cd = ie.get('CD', 'Z')
    if cd == 'S':
        code = (9, 0)[index]
    elif cd == 'Z':
        code = 0
    elif cd == 'O':
        code = (0, 1)[index]
    else:
        code = checked_uint(int(cd, 16) if isinstance(cd, str) else cd, 8, 'IE.CD')
    return df, code


def validate_fingerprint(fps):
    if not isinstance(fps, dict) or not any(k in fps for k in ('T1', 'ECN', 'IE')):
        raise ValueError('fingerprint must be an object containing T1, ECN or IE')
    result = deepcopy(fps)
    for name in ['ECN'] + ['T{}'.format(i) for i in range(1, 8)]:
        if name not in result:
            continue
        rule = result[name]
        if not isinstance(rule, dict) or rule.get('R', 'Y') not in ('Y', 'N'):
            raise ValueError('{}: invalid response rule'.format(name))
        if name == 'ECN' and rule.get('R', 'Y') == 'Y':
            cc = rule.get('CC', 'N')
            if cc not in ('N', 'Y', 'S', 'O'):
                raise ValueError('ECN.CC must be N, Y, S or O in this pipeline')
            rule.setdefault('F', {'N': 'AS', 'Y': 'ASE', 'S': 'ASEC', 'O': 'ASC'}[cc])
            rule.setdefault('A', 'S+')
        if rule.get('R', 'Y') == 'N':
            result[name] = {'R': 'N'}
            continue
        checked_uint(rule.get('TG'), 8, name + '.TG')
        if rule['TG'] == 0:
            raise ValueError(name + '.TG must be positive')
        if rule.get('DF', 'N') not in ('Y', 'N'):
            raise ValueError(name + '.DF must be Y or N')
        if 'A' in rule and rule['A'] not in ACK_OPS:
            raise ValueError(name + '.A is unsupported')
        if 'S' in rule and rule['S'] not in SEQ_OPS:
            raise ValueError(name + '.S is unsupported')
        if not isinstance(rule.get('F', ''), str) or set(rule.get('F', '')) - set(TCP_FLAGS):
            raise ValueError(name + '.F contains unsupported TCP flags')
        checked_uint(rule.get('W', 0), 16, name + '.W')
        option_config(rule.get('O', []), name + '.O')
    if 'T1' in result and result['T1'].get('R', 'Y') == 'Y':
        for key in ('ISN', 'WIN', 'OPS'):
            if not isinstance(result.get(key), dict):
                raise ValueError('T1 replies require the top-level {} object'.format(key))
        for i in range(1, 7):
            checked_uint(result['ISN'].get('s{}'.format(i)), 32, 'ISN.s{}'.format(i))
            checked_uint(result['WIN'].get('W{}'.format(i)), 16, 'WIN.W{}'.format(i))
            option_config(result['OPS'].get('O{}'.format(i)), 'OPS.O{}'.format(i))
    if 'IE' in result:
        ie = result['IE']
        if not isinstance(ie, dict) or ie.get('R', 'Y') not in ('Y', 'N'):
            raise ValueError('IE: invalid response rule')
        if ie.get('R', 'Y') == 'Y':
            checked_uint(ie.get('TG'), 8, 'IE.TG')
            if ie.get('DFI') not in ('Y', 'N', 'S', 'O'):
                raise ValueError('IE.DFI must be Y, N, S or O')
            icmp_reply_fields(ie, 0)
    return result


def upsert(table, target, keys, data):
    # Only ALREADY_EXISTS permits an entry_mod fallback; propagate other failures.
    for key, value in zip(keys, data):
        try:
            table.entry_add(target, [key], [value])
        except gc.BfruntimeReadWriteRpcException as error:
            errors = error.sub_errors_get()
            if not errors or any(item.canonical_code != 6 for _, item in errors):
                raise
            table.entry_mod(target, [key], [value])


"""
把你从规则里解析出来的TCP 选项描述（m_opt_dict[_key] 是一个“选项字典的列表”）
转换成一行可读字符串，用于写进发往 DPDK 的 JSON（config.json）里。
它会保持输入顺序，把每个选项翻译成诸如 
MSS(mss=1460);NOP;NOP;WS(scale=10);SOK;EOL;TS(123,0) 这样的串。
"""
def generate_opt_str(m_opt_dict, _key):
    opt_list = []
    tsval = -1
    tsecr = -1
    opt_dict_list = []

    if _key in m_opt_dict:
        opt_dict_list = m_opt_dict[_key]
    else:
        return None

    # print("raw opt_dict_list = {}".format(opt_dict_list))
    for opt_dict in opt_dict_list:
        for opt_name, opt_val in list(opt_dict.items()):
            if 'mss' in opt_name:
                opt_list.append("MSS(mss={})".format(opt_val))

            elif 'nop' in opt_name:
                opt_list.append("NOP")

            elif 'w' in opt_name:
                opt_list.append("WS(scale={})".format(opt_val))

            elif 'sack' in opt_name:
                opt_list.append("SOK")

            elif 'eol' in opt_name:
                opt_list.append("EOL")

            elif 'TSval' in opt_name:
                tsval = opt_val
                if tsval != -1 and tsecr != -1:
                    opt_list.append("TS({},{})".format(tsval, tsecr))
                    tsval = -1
                    tsecr = -1
            elif 'TSecr' in opt_name:
                tsecr = opt_val
                if tsval != -1 and tsecr != -1:
                    opt_list.append("TS({},{})".format(tsval, tsecr))
                    tsval = -1
                    tsecr = -1
            else:
                print("Unknown option:{}".format(opt_val))
        
    opt_str = ";".join(opt_list)
    return opt_str 

def append_rule(submit_list, m_str, _key):
    if m_str != None:
        submit_list.append("{}: {}".format(_key, m_str))

def input_with_timeout(prompt, timeout):
    def alarm_handler(signum, frame):
        raise TimeoutError
    signal.signal(signal.SIGALRM, alarm_handler)
    signal.alarm(timeout)
    try:
        return input(prompt)
    finally:
        signal.alarm(0)


class NMAP_Test(BfRuntimeTest):
    p4_name = "antiFpProbe"
    client_id = 0

    attacker_port = 60
    emulator_port = 52
    recirec_port = 196

    arp_ip_dict = {}
    tx_mac_dict = { 
        60 : "9c:69:b4:65:0f:5d",
        52 : "64:9d:99:ff:fd:63"
    }
    ipv4_port_fwd_rule_dict = {}
    refresh_table_tuple_list = []
    fp_ip_dict = {}
    # port dump
    port_speed_dict = {}
    port_statistic_dict = {}


    def setUp(self):
        BfRuntimeTest.setUp(self, self.client_id, self.p4_name)
        self.arp_ip_dict = {}
        self.ipv4_port_fwd_rule_dict = {}
        self.refresh_table_tuple_list = []
        self.fp_ip_dict = {}
        self.port_speed_dict = {}
        self.port_statistic_dict = {}
        self.active_fingerprint = None
        self.last_config_error = None
    
    def clear_table(self, table_name):
        bfrt_info = self.interface.bfrt_info_get(self.p4_name)
        table = bfrt_info.table_get(table_name)
        target = gc.Target(device_id=0, pipe_id=0xffff)
        table.entry_del(target) 
    
    def open_port(self, target):
        Speed_dict = {"100G":"BF_SPEED_100G", "10G":"BF_SPEED_10G"}
        Fec_dict = {"RS":"BF_FEC_TYP_RS", "NONE":"BF_FEC_TYP_NONE"}
        AN_dict = {0:"PM_AN_DEFAULT", 1:"PM_AN_FORCE_ENABLE", 2:"PM_AN_FORCE_DISABLE"}
        Loop_Back = {0:"BF_LPBK_NONE", 1:"BF_LPBK_MAC_NEAR"}
        port_lst = [
            {
                "port" : 52,
                "speed" : Speed_dict["100G"],
                "fec" : Fec_dict["RS"],
                "an" : AN_dict[0],
                "lpbk" : Loop_Back[0]

            },
            {
                "port" : 60,
                "speed" : Speed_dict["100G"],
                "fec" : Fec_dict["RS"],
                "an" : AN_dict[0],
                "lpbk" : Loop_Back[0]
            }
        ]
        existing = {key.to_dict()['$DEV_PORT']['value']
                    for _, key in self.port_table.entry_get(target, [], {'from_hw': False})}
        for index, item in enumerate(port_lst, 1):
            if item['port'] not in existing:
                self.port_table.entry_add(
                    target,
                    [self.port_table.make_key([gc.KeyTuple('$DEV_PORT', item["port"])])],
                    [
                        self.port_table.make_data(
                            [
                                gc.DataTuple('$SPEED', str_val=item["speed"]),
                                gc.DataTuple('$FEC', str_val=item["fec"]),
                                gc.DataTuple('$AUTO_NEGOTIATION',str_val=item["an"]),
                                gc.DataTuple('$LOOPBACK_MODE',str_val=item["lpbk"]),
                                gc.DataTuple('$PORT_ENABLE', bool_val=True)
                            ]
                        )
                    ]
                )
            self.port_statistic_dict[item["port"]] = {
                "port":item["port"], "tx_pkts":0, "tx_MB":0, "rx_pkts":0, "rx_MB":0
            }
            self.port_speed_dict[item["port"]] = {
                'tx':0, 'tx_MB':0, 'rx':0, 'rx_MB':0
            }
            time.sleep(2)

    def load_arp_rules(self, handle_arp_table, rule_path, target):
        with open(rule_path, 'r') as fin:
            lines = fin.readlines()
            for line in lines:
                items = line.replace("\n", "").split(' ')
                _ip   = items[0]
                _mac  = items[1]
                self.insert_arp_rule(handle_arp_table, _ip, _mac, target)
    
    def insert_arp_rule(self, handle_arp_table, target_ip, target_mac, target):
        if target_ip not in self.arp_ip_dict:
            handle_arp_table.entry_add(
                target,
                [
                    handle_arp_table.make_key(
                        [
                            gc.KeyTuple('hdr.arp.$valid',1), 
                            gc.KeyTuple('hdr.arp.opcode',1),
                            gc.KeyTuple('hdr.arp.target_ipv4', gc.ipv4_to_bytes(target_ip))
                        ]
                    )
                ],
                [
                    handle_arp_table.make_data(
                        [
                            gc.DataTuple('arp_proxy_mac', gc.mac_to_bytes(target_mac))
                        ],
                        'SwitchIngress.handle_arp_request'
                    )
                ]
            )
            # print("arp rule: ip = {}, mac = {}".format(target_ip, target_mac))
            self.arp_ip_dict[target_ip] = target_mac
        else:
            print("duplicated arp rule: {}->{}".format(target_ip, target_mac))

    def load_ipv4_fwd_rules_from_file(self, fwd_table, file_path, target):
        with open(file_path, 'r') as fin:
            lines = fin.readlines()
            for line in lines:
                items = line.replace('\n', '').split(' ')
                ip = items[0].split('/')[0]
                plen = int(items[0].split('/')[1])
                port = int(items[1])
                self.add_ipv4_fwd_rule(fwd_table, ip, plen, port, target) 

    def add_ipv4_fwd_rule(self, fwd_table, _ip, _plen, _out_port, target): 
        if _out_port not in self.tx_mac_dict:
            print("Unregistered Port = {}".format(_out_port))
        
        _mac  = self.tx_mac_dict[_out_port] 
        # avoid duplicated rule
        pkey = "{}/{}".format(_ip, _plen)
        if pkey in self.ipv4_port_fwd_rule_dict:
            del self.ipv4_port_fwd_rule_dict[pkey]
        # add normal forward
        try:
            fwd_table.entry_add(
                target,
                [
                    fwd_table.make_key(
                        [
                            gc.KeyTuple('ig_md.dst_ipv4', gc.ipv4_to_bytes(_ip), prefix_len = _plen)
                        ]
                    )
                ],
                [
                    fwd_table.make_data(
                        [
                            gc.DataTuple('port', _out_port),
                            gc.DataTuple('dst_mac', gc.mac_to_bytes(_mac))
                        ], 
                        "SwitchIngress.action_port_fwd"
                    )
                ]
            )
        except:
            fwd_table.entry_mod(
                target,
                [   
                    fwd_table.make_key(
                        [
                            gc.KeyTuple('ig_md.dst_ipv4', gc.ipv4_to_bytes(_ip), prefix_len = _plen)
                        ]
                    )
                ],
                [
                    fwd_table.make_data(
                        [
                            gc.DataTuple('port', _out_port),
                            gc.DataTuple('dst_mac', gc.mac_to_bytes(_mac))
                        ], 
                        "SwitchIngress.action_port_fwd"
                    )
                ]
            )
        # update local rule dict
        self.ipv4_port_fwd_rule_dict[pkey] = _out_port 

    def clear_refresh_tuple_for_ip(self, target):
        self.fp_ip_dict.clear()
        # The entry gate is installed last; remove it before changing reply rules.
        while self.refresh_table_tuple_list:
            _table, _key = self.refresh_table_tuple_list[-1]
            _table.entry_del(target, _key)
            self.refresh_table_tuple_list.pop()

    def track_existing_fingerprint(self, tables, host_ip, target):
        expected_ip = int(IPv4Address(host_ip))
        for table in tables:
            for _, key in table.entry_get(target, [], {'from_hw': False}):
                if key is None:
                    continue
                fields = key.to_dict()
                ip_field = fields.get('ig_md.dst_ipv4', fields.get('hdr.ipv4.dst_addr'))
                if not ip_field or ip_field.get('prefix_len', 32) != 32:
                    continue
                value = ip_field['value']
                if isinstance(value, (bytes, bytearray)):
                    value = int.from_bytes(value, 'big')
                elif isinstance(value, str):
                    value = int(IPv4Address(value))
                if value == expected_ip:
                    self.add_refresh_table_tuple([key], table)

    def refresh_fingerprint(self, path, tables, host_ip, target):
        try:
            with open(path, 'r') as source:
                fps = validate_fingerprint(json.load(source))
        except (OSError, ValueError, TypeError) as error:
            if self.active_fingerprint is None:
                raise
            if str(error) != self.last_config_error:
                logger.error('Invalid fingerprint; retaining active rules: %s', error)
                self.last_config_error = str(error)
            return False
        self.last_config_error = None
        if fps == self.active_fingerprint:
            return False

        def install(config):
            self.handle_fp_rules(tables[0], tables[1], tables[2], 0, host_ip,
                                 config.get('OS', 'unspecified'), config, target)
            self.add_filter_P1_6_table_rulers(tables[3], host_ip, target)
            self.add_confuse_enter_rule(tables[4], host_ip, target)

        previous = self.active_fingerprint
        self.clear_refresh_tuple_for_ip(target)
        try:
            install(fps)
        except Exception:
            logger.exception('Fingerprint update failed')
            self.clear_refresh_tuple_for_ip(target)
            if previous is None:
                raise
            install(previous)
            logger.error('Restored previous fingerprint rules')
            return False
        self.active_fingerprint = deepcopy(fps)
        logger.info('Applied fingerprint for %s: %s', host_ip, fps.get('OS', 'unspecified'))
        return True
    
    def add_opt_end_rule(self, finger_option_tables, table_id, ip, pkt_seq, target):
        key = [
            finger_option_tables.make_key(
                [
                    gc.KeyTuple('packet_seq', pkt_seq),
                    gc.KeyTuple('ig_md.dst_ipv4', gc.ipv4_to_bytes(ip))
                ]
            )
        ]
        data = [
            finger_option_tables.make_data(
                [], 
                'SwitchIngress.finger_Tcp_opt_end_{}'.format(table_id)
            )
        ]
        upsert(finger_option_tables, target, key, data)
        self.add_refresh_table_tuple(key, finger_option_tables)

    def add_opt_nop_rule(self, finger_option_tables, table_id, ip, pkt_seq, target):
        key = [
            finger_option_tables.make_key(
                [
                    gc.KeyTuple('packet_seq', pkt_seq),
                    gc.KeyTuple('ig_md.dst_ipv4', gc.ipv4_to_bytes(ip))
                ]
            )
        ]
        data = [
            finger_option_tables.make_data(
                [], 
                'SwitchIngress.finger_Tcp_opt_Nop_{}'.format(table_id)
            )
        ]
        upsert(finger_option_tables, target, key, data)
        self.add_refresh_table_tuple(key, finger_option_tables)

    def add_opt_mss_rule(self, finger_option_tables, table_id, ip, mss, pkt_seq, target):
        key = [
            finger_option_tables.make_key(
                [
                    gc.KeyTuple('packet_seq', pkt_seq),
                    gc.KeyTuple('ig_md.dst_ipv4', gc.ipv4_to_bytes(ip))
                ]
            )
        ]
        data = [
            finger_option_tables.make_data(
                [gc.DataTuple('mss', mss)], 
                'SwitchIngress.finger_Tcp_opt_MSS_{}'.format(table_id)
            )
        ]
        upsert(finger_option_tables, target, key, data)
        self.add_refresh_table_tuple(key, finger_option_tables)

    def add_opt_wsize_rule(self, finger_option_tables, table_id, ip, scale, pkt_seq, target):
        key = [
            finger_option_tables.make_key(
                [
                    gc.KeyTuple('packet_seq', pkt_seq),
                    gc.KeyTuple('ig_md.dst_ipv4', gc.ipv4_to_bytes(ip))
                ]
            )
        ]
        data = [
            finger_option_tables.make_data(
                [gc.DataTuple('scale', scale)], 
                'SwitchIngress.finger_Tcp_opt_Wsize_{}'.format(table_id)
            )
        ]
        upsert(finger_option_tables, target, key, data)
        self.add_refresh_table_tuple(key, finger_option_tables)

    def add_opt_sok_rule(self, finger_option_tables, table_id, ip, pkt_seq, target):
        key = [
            finger_option_tables.make_key(
                [
                    gc.KeyTuple('packet_seq', pkt_seq),
                    gc.KeyTuple('ig_md.dst_ipv4', gc.ipv4_to_bytes(ip))
                ]
            )
        ]
        data = [
            finger_option_tables.make_data(
                [], 
                'SwitchIngress.finger_Tcp_opt_SOK_{}'.format(table_id)
            )
        ]
        upsert(finger_option_tables, target, key, data)
        self.add_refresh_table_tuple(key, finger_option_tables)

    def add_opt_ts_rule(self, finger_option_tables, table_id, ip, pkt_seq, target, tsval, tsecr):
        key = [
            finger_option_tables.make_key(
                [
                    gc.KeyTuple('packet_seq', pkt_seq),
                    gc.KeyTuple('ig_md.dst_ipv4', gc.ipv4_to_bytes(ip))
                ]
            )
        ]
        data = [
            finger_option_tables.make_data(
                [gc.DataTuple('tsval', tsval), gc.DataTuple('tsecr', tsecr)],
                'SwitchIngress.finger_Tcp_opt_TS_{}'.format(table_id)
            )
        ]
        upsert(finger_option_tables, target, key, data)
        self.add_refresh_table_tuple(key, finger_option_tables)

    """
        负责 把选项拼装逻辑下发到 P4（每个槽的动作），
        并计算好数据面需要的数值（头长、长度差），
        交由后续的 handle_T1_7_table 一次性应用到报文。

        finger_opt_tables：一个列表，
        代表在 P4 中为“6 个槽位”创建的 6 张表（finger_ob_tcp_table_0 ... _5）。
        这些表以 (packet_seq, dst_ip) 为 key，
        用来为每个槽位选择具体的 option 动作（END/NOP/MSS/WS/SOK/TS 等）。
    """
    def add_fp_option_rule(self, finger_option_tables, rule_tuple, pkt_seq, target):
        rule_type          = rule_tuple[0]
        ip                 = rule_tuple[1]
        os                 = rule_tuple[2]
        opt_config_dict    = rule_tuple[3]
        layout = opt_config_dict.get('olayout', [])
        if any(kind not in OPTION_SIZES for kind in layout):
            raise ValueError('Unsupported TCP option layout')
        length = sum(OPTION_SIZES[kind] for kind in layout)
        if length + (-length) % 4 > 40 or len(layout) + (-length) % 4 > len(finger_option_tables):
            raise ValueError('TCP options exceed header length or available P4 slots')
        raw_data_offset    = 20
        new_data_offset    = 0
        new_ipv4_len_delta = 0
        new_ttl            = 0
        new_wsize          = 0

        if pkt_seq in self.fp_ip_dict[ip]:
            del self.fp_ip_dict[ip][pkt_seq]

        options = []
        if "olayout" in opt_config_dict:
            for index, option in enumerate(opt_config_dict["olayout"]):
                if option == 'eop': # 1B
                    self.add_opt_end_rule(finger_option_tables[index], index, ip, pkt_seq, target)
                    # print("\toption {:2d}: end, type=0".format(_id))
                    options.append("END")
                    raw_data_offset += 1

                elif option == 'nop': # 1B
                    self.add_opt_nop_rule(finger_option_tables[index], index, ip, pkt_seq, target)
                    # print("\toption {:2d}: nop, type=1".format(_id))
                    options.append("NOP")
                    raw_data_offset += 1

                elif option == 'mss': # 4B
                    self.add_opt_mss_rule(finger_option_tables[index], index, ip, opt_config_dict["mss"], pkt_seq, target)
                    # print("\toption {:2d}: mss, type=2, length=4, mss={}".format(_id, fps["mss"]))
                    options.append("MSS(mss={})".format(opt_config_dict["mss"]))
                    raw_data_offset += 4

                elif option == 'ws': # 3B
                    self.add_opt_wsize_rule(finger_option_tables[index], index, ip, opt_config_dict["scale"], pkt_seq, target)
                    # print("\toption {:2d}: wsize, type=3, length=3, scale={}".format(_id, fps["scale"]))
                    options.append("WS(scale={})".format(opt_config_dict["scale"]))
                    raw_data_offset += 3

                elif option == 'sok': # 2B
                    self.add_opt_sok_rule(finger_option_tables[index], index, ip, pkt_seq, target)
                    # print("\toption {:2d}: sok, type=4, length=2".format(_id))
                    options.append("SOK")
                    raw_data_offset += 2

                elif option == 'ts': # 10B
                    self.add_opt_ts_rule(finger_option_tables[index], index, ip, pkt_seq, target,
                                         opt_config_dict['tsval'], opt_config_dict['tsecr'])
                    # print("\toption {:2d}: timestamp, type=8, length=10, ts={}:{}".format(_id, fps['tsval'], fps['tsecr']))
                    options.append("TS(ts={})".format(opt_config_dict['tsval']))
                    raw_data_offset += 10

        
        table_id = len(options)
        while raw_data_offset % 4 != 0:
            self.add_opt_end_rule(finger_option_tables[table_id], table_id, ip, pkt_seq, target)
            raw_data_offset += 1
            table_id += 1

        new_ipv4_len_delta = raw_data_offset - 20
        new_data_offset = int(raw_data_offset / 4) 
        

        return new_data_offset, new_ipv4_len_delta, {"RawOptLen":new_data_offset, "Options":"-".join(options)} 

    """
        handle_T1_7_table   :   下发 T1 ~ T7/ECN 探针包对应的 header 修改规则
        finger_option_tables:   包含 6 张表,分别对应 TCP Options 的 6 个“槽位”。定义在某个槽位上插入哪个 TCP Option
        handle_icmp_table   :   定义如何应答 Nmap 的 ICMP Echo (IE) 探针。
        rule_type           :   由 FlaskAgent 收到请求时带过来的规则的类型,=0时进行改写
        hostIP              :   目标主机的 IP 地址
        host_type           :   表示目标主机的操作系统类型（如 "Linux", "Windows", "FreeBSD"）。
        fps                 :   fingerprint 规则集。
    """
    def handle_fp_rules(self, handle_T1_7_table, finger_option_tables, 
            handle_icmp_table, rule_type, hostIP, host_type, fps, target
        ):
        fps = validate_fingerprint(fps)
        self.fp_ip_dict[hostIP] = {"ruleType":rule_type, "OS": host_type}

       
        def generate_hdr_fp_data(raw_fps, _pkt_seq, win=None, ops_lst=None, isn=None):
            ack_opcode         = 0
            seq_opcode         = 0
            ipv4_ttl           = 0
            ipv4_serv_bits     = 0
            ipv4_flags         = 0
            tcp_wsize          = 0
            tcp_flags          = 0
            new_data_offset    = 0
            new_ipv4_len_delta = 0
            options_fp_data    = 0
            should_reply       = 1
            seq_from_isn       = 0
            opt_dict_list      = []
            opt_config_dict = {'mss':0, 'scale':0, 'ts':0, 'olayout':[]}
            should_reply_dict = {
                "Y" : 1,
                "N" : 0
            }  

            if 'A' in raw_fps:
                ack_opcode = ACK_OPS[raw_fps['A']]
            if 'DF' in raw_fps and raw_fps['DF'] == 'Y':
                ipv4_flags |= (1<<1)
            if 'S' in raw_fps:
                seq_opcode = SEQ_OPS[raw_fps['S']]
            if 'F' in raw_fps:
                tcp_flags = sum(TCP_FLAGS[flag] for flag in set(raw_fps['F']))
            if 'W' in raw_fps:
                tcp_wsize = raw_fps['W']
            if 'R' in raw_fps:
                should_reply = should_reply_dict[raw_fps['R']]
            # if 'T' in raw_fps:
            #     min_v = int(raw_fps['T'].split('-')[0])
            #     max_v = int(raw_fps['T'].split('-')[1])
            #     ipv4_ttl = min_v
            if 'TG' in raw_fps:
                ipv4_ttl = int(raw_fps['TG'])
            opt_config_dict = option_config(raw_fps.get('O', []))
            if _pkt_seq in P1_6_IDS and should_reply:
                tcp_wsize = win
                opt_config_dict = option_config(ops_lst)
                # ISN lives at the JSON root. Zero is a valid supplied ISN.
                seq_from_isn = checked_uint(isn, 32, 'ISN')
            elif seq_opcode == 3 and should_reply:
                # S=O must not silently turn into the S=Z case for T3/ECN.
                seq_from_isn = random.randint(1, 0xFFFFFFFF)

            # insert into option insertion table
            new_data_offset, new_ipv4_len_delta, options_fp_data = self.add_fp_option_rule(
                finger_option_tables, 
                (rule_type, hostIP, host_type, opt_config_dict), 
                _pkt_seq,
                target
            )
                
            # All option and flags parsed over
            key  = [
                handle_T1_7_table.make_key(
                    [
                        gc.KeyTuple('packet_seq', _pkt_seq),
                        gc.KeyTuple('hdr.ipv4.dst_addr', gc.ipv4_to_bytes(hostIP))
                    ]
                )
            ]
            data = [
                handle_T1_7_table.make_data(
                    [
                        gc.DataTuple('ipv4_ttl',             ipv4_ttl),
                        gc.DataTuple('ipv4_serv_bits',       ipv4_serv_bits),
                        gc.DataTuple('ipv4_flags',           ipv4_flags),
                        gc.DataTuple('wsize',                tcp_wsize),
                        gc.DataTuple('tcp_flag_bits',        tcp_flags),
                        gc.DataTuple('m_new_data_offset',    new_data_offset),
                        gc.DataTuple('m_new_ipv4_len_delta', new_ipv4_len_delta),
                        gc.DataTuple('m_ack_no_opcode',      ack_opcode),
                        gc.DataTuple('m_seq_no_opcode',      seq_opcode),
                        gc.DataTuple('should_reply',         should_reply),
                        gc.DataTuple('m_seq_from_isn',       seq_from_isn),
                        gc.DataTuple('m_tcp_option_sum',     tcp_option_sum(opt_config_dict)),
                    ], 
                    'SwitchIngress.hdr_fp_setup'
                )
            ]

            upsert(handle_T1_7_table, target, key, data)

            self.add_refresh_table_tuple(key, handle_T1_7_table)
            
            self.fp_ip_dict[hostIP]["Seq-{:d}".format(_pkt_seq)] = ";".join(
                [
                    "Reply={}".format(should_reply), 
                    "TTL={}".format(ipv4_ttl), 
                    "Sbits={}".format(ipv4_serv_bits), 
                    "IFlags={}".format(ipv4_flags), 
                    "IPd={}".format(new_ipv4_len_delta),
                    "W={}".format(tcp_wsize), 
                    "Tflags={}".format(tcp_flags), 
                    "Dof={}".format( new_data_offset), 
                    "ACKop={}".format(ack_opcode), 
                    "SEQop={}".format(seq_opcode),
                    "ISN={}".format(seq_from_isn),
                    "OPS={}".format( options_fp_data)
                ]
            )

        print(">>>   generate_hdr_fp_data")
        # insert ECN and T1~T7
        if 'ECN' in fps:
            generate_hdr_fp_data(fps['ECN'], 0x1)
        if 'T1' in fps:
            for index, packet_id in enumerate(P1_6_IDS, 1):
                if fps['T1'].get('R', 'Y') == 'N':
                    generate_hdr_fp_data(fps['T1'], packet_id)
                    continue
                generate_hdr_fp_data(
                    fps['T1'], packet_id,
                    fps.get('WIN', {}).get('W{}'.format(index)),
                    fps.get('OPS', {}).get('O{}'.format(index)),
                    fps.get('ISN', {}).get('s{}'.format(index)))
        if 'T2' in fps:
            generate_hdr_fp_data(fps['T2'], 0x2)
        if 'T3' in fps:
            generate_hdr_fp_data(fps['T3'], 0x3)
        if 'T4' in fps:
            generate_hdr_fp_data(fps['T4'], 0x4)
        if 'T5' in fps:
            generate_hdr_fp_data(fps['T5'], 0x5)
        if 'T6' in fps:
            generate_hdr_fp_data(fps['T6'], 0x6)
        if 'T7' in fps:
            generate_hdr_fp_data(fps['T7'], 0x7)
        # insert ICMP rules
        if 'IE' in fps:
            self.fp_ip_dict[hostIP]['IE'] = []
            ie_dict = fps['IE']
            for index, (tos, code, seq) in enumerate(((0, 9, 295), (4, 0, 296))):
                key = handle_icmp_table.make_key([
                    gc.KeyTuple('hdr.ipv4.diffserv[5:0]', tos),
                    gc.KeyTuple('hdr.icmp.code', code),
                    gc.KeyTuple('hdr.icmp_data.seq', seq),
                    gc.KeyTuple('ig_md.dst_ipv4', gc.ipv4_to_bytes(hostIP), prefix_len=32)])
                if ie_dict.get('R', 'Y') == 'N':
                    data = handle_icmp_table.make_data([], 'SwitchIngress.ignore_icmp_request')
                    description = 'Ignore'
                else:
                    df, reply_code = icmp_reply_fields(ie_dict, index)
                    data = handle_icmp_table.make_data([
                        gc.DataTuple('ttl', ie_dict['TG']), gc.DataTuple('df', df),
                        gc.DataTuple('code', reply_code)], 'SwitchIngress.generate_icmp_reply')
                    description = 'Reply(TTL={}, DF={}, code={})'.format(ie_dict['TG'], df, reply_code)
                upsert(handle_icmp_table, target, [key], [data])
                self.add_refresh_table_tuple([key], handle_icmp_table)
                self.fp_ip_dict[hostIP]['IE'].append('Probe {}: {}'.format(index + 1, description))

    def add_filter_P1_6_table_rulers(self, filter_P1_6_table, host_ip, target):
        # rules = [
        #     [10, 1460, 0xffffffff, 0, 1],  # P1
        #     [0,  1400, 0xffffffff, 0, 63], # P2
        #     [5,  640,  0xffffffff, 0, 4],  # P3
        #     [10, 0,    0xffffffff, 0, 4],  # P4
        #     [10, 536,  0xffffffff, 0, 16], # P5
        #     [0,  265,  0xffffffff, 0, 512] # P6
        # ]
        rules = [
            [10, 1460, 1, 1],  # P1
            [0,  1400, 1, 63], # P2
            [5,  640,  1, 4],  # P3
            [10, 0,    1, 4],  # P4
            [10, 536,  1, 16], # P5
            [0,  265,  1, 512] # P6
        ]
        keys = []
        datas = []
        for index, item in enumerate(rules):
            keys.append(
                filter_P1_6_table.make_key(
                    [
                        gc.KeyTuple('ig_md.scale', item[0]),
                        gc.KeyTuple('ig_md.mss', item[1]),
                        # gc.KeyTuple('ig_md.tsval', item[2]),
                        # gc.KeyTuple('ig_md.tsecr', item[3]),
                        gc.KeyTuple('ig_md.has_ts', item[2]),
                        gc.KeyTuple('hdr.tcp.window', item[3]),
                        gc.KeyTuple('ig_md.dst_ipv4', gc.ipv4_to_bytes(host_ip))
                    ]
                )
            )
            datas.append(
                filter_P1_6_table.make_data(
                    [
                            gc.DataTuple('seq', P1_6_IDS[index])
                    ],
                    'SwitchIngress.set_packet_seq'
                )
            )
        for key, data in zip(keys, datas):
            upsert(filter_P1_6_table, target, [key], [data])
            self.add_refresh_table_tuple([key], filter_P1_6_table)



    def add_confuse_enter_rule(self, enter_table, dst_ip, target):
        if dst_ip not in self.fp_ip_dict:
            return
        
        key = [
            enter_table.make_key(
                [
                    gc.KeyTuple('ig_md.dst_ipv4', gc.ipv4_to_bytes(dst_ip))
                ]
            )
        ]
        data = [enter_table.make_data([], 'SwitchIngress.mark_packet_to_enter_confuse')]

        upsert(enter_table, target, key, data)
        self.add_refresh_table_tuple(key, enter_table)
    
    def add_refresh_table_tuple(self, _key, _table):
        self.refresh_table_tuple_list.append((_table, _key))

    def setup_preprocess_ipv4_tcp_length_rules(self, p4_table, target):
        keys = []
        datas = []

        for i in range(6,16):
            _k = i
            _d = (i - 5) * 4
            keys.append( 
                p4_table.make_key(
                    [
                        gc.KeyTuple('hdr.tcp.data_offset', _k)
                    ]
                )
            )
            datas.append(
                p4_table.make_data(
                    [
                        gc.DataTuple('old_len_delta', _d)
                    ], 
                    'SwitchIngress.preprocess_ipv4_tcp_length'
                )
            )
        
        upsert(p4_table, target, keys, datas)
    
    def dump_fwd_rules(self):
        print("****Forward rules:****")
        for _prefix, _out_port in self.ipv4_port_fwd_rule_dict.items():
            print("{}\t---> {}, binded mac = {}".format(
                    _prefix, _out_port, self.tx_mac_dict[_out_port]
                )
            )
    
    def dump_ports_statistic(self, target):
        print("\n******Ports IO******")
        for port_key, port_item in self.port_statistic_dict.items():
            _port = port_item['port']
            get_data_list = None
            resp = self.port_stat_table.entry_get(
                target,
                [self.port_stat_table.make_key([gc.KeyTuple('$DEV_PORT', _port)])],
                {"from_hw": True},
                get_data_list
            )
            
            # dump to dict
            data_dict  = next(resp)[0].to_dict()
            
            """
            new_tx_MB / new_rx_MB → 当前累计 MB（硬件最新值）。
            last_tx_MB / last_rx_MB → 上一次累计 MB（软件保存的历史值）。
            new_tx_npkts / new_rx_npkts → 当前累计包数（硬件最新值）。
            last_tx_npkts / last_rx_npkts → 上一次累计包数。
            self.port_speed_dict[_port]['tx'] / ['rx'] → 新产生的包数（速率指标）。
            self.port_speed_dict[_port]['tx_MB'] / ['rx_MB'] → 新产生的 MB 数（速率指标）。
            port_item['tx_pkts'] / ['rx_pkts'] → 更新后的累计包数。
            port_item['tx_MB'] / ['rx_MB'] → 更新后的累计 MB。
            """
            # TX
            new_tx_MB     = (float)(data_dict['$OctetsTransmittedTotal']) / 1000000
            last_tx_MB    = port_item['tx_MB']
            new_tx_npkts  = data_dict['$FramesTransmittedAll']
            last_tx_npkts = port_item['tx_pkts']
            self.port_speed_dict[_port]['tx'] = new_tx_npkts - last_tx_npkts
            self.port_speed_dict[_port]['tx_MB'] = new_tx_MB - last_tx_MB
            port_item['tx_pkts'] = new_tx_npkts
            port_item['tx_MB']   = new_tx_MB

            # RX
            new_rx_MB     = (float)(data_dict['$OctetsReceived']) / 1000000
            last_rx_MB    = port_item['rx_MB']
            new_rx_npkts  = data_dict['$FramesReceivedAll']
            last_rx_npkts = port_item['rx_pkts']
            self.port_speed_dict[_port]['rx'] = new_rx_npkts - last_rx_npkts
            self.port_speed_dict[_port]['rx_MB'] = new_rx_MB - last_rx_MB
            port_item['rx_pkts'] = new_rx_npkts
            port_item['rx_MB']   = new_rx_MB

            print(
                "Port {:3}: rx_rate = {:6.3f} Mpps ({:6.3f} Mbps), rx_tot = {:8}, tx_rate = {:6.3f} Mpps ({:6.3f} Mbps), tx_tot = {:8}".format(
                    _port, 
                    self.port_speed_dict[_port]['rx']/1000000, 
                    self.port_speed_dict[_port]['rx_MB'] * 8,
                    new_rx_npkts,
                    self.port_speed_dict[_port]['tx']/1000000, 
                    self.port_speed_dict[_port]['tx_MB'] * 8,
                    new_tx_npkts
                )
            )
    
    def dump_reg(self, reg_table, index, reg_name, target):
        resp = reg_table.entry_get(
            target,
            [
                reg_table.make_key(
                    [gc.KeyTuple('$REGISTER_INDEX', index)]
                )
            ],
            {"from_hw":True},
            None
        )
        data,_ = next(resp)
        data_dict = data.to_dict()
        ret_data = data_dict['SwitchIngress.{}.f1'.format(reg_name)]
        print("{:<19}-{}: {}".format(reg_name, index, ret_data))

    def dump_fp_rules(self, detailed_fp):
        print("\n***FP rules***")
        for ip, _dict in self.fp_ip_dict.items():
            print("IP={}, OS={}".format(ip, _dict['OS']))
            if detailed_fp:
                print(json.dumps(_dict, indent=2))


    
    
    def runTest(self):
        bfrt_info = self.interface.bfrt_info_get(self.p4_name)
        target = gc.Target(device_id=0, pipe_id=0xffff)

        # clear table
        # self.clear_table("SwitchIngress.handle_arp_table")

        # Initializing all info tables
        self.port_table = bfrt_info.table_get("$PORT")
        self.port_stat_table = bfrt_info.table_get("$PORT_STAT")
        self.port_hdl_info_table = bfrt_info.table_get("$PORT_HDL_INFO")
        self.port_fp_idx_info_table = bfrt_info.table_get("$PORT_FP_IDX_INFO")
        self.port_str_info_table = bfrt_info.table_get("$PORT_STR_INFO")

        # tables
        # handle_arp_table = bfrt_info.table_get("SwitchIngress.handle_arp_table")
        ipv4_fwd_table = bfrt_info.table_get('SwitchIngress.ipv4_fwd_table')
        filter_packet_enter_confuse_table = bfrt_info.table_get('SwitchIngress.filter_packet_enter_confuse_table')
        preprocess_ipv4_tcp_length_table  = bfrt_info.table_get('SwitchIngress.preprocess_ipv4_tcp_length_table')
        filter_P1_6_table = bfrt_info.table_get('SwitchIngress.filter_P1_6_table')

        # Fp tables
        handle_T1_7_table    = bfrt_info.table_get("SwitchIngress.handle_T1_7_table")
        finger_option_tables = []
        finger_option_tables.append( bfrt_info.table_get('SwitchIngress.finger_ob_tcp_table_0'))
        finger_option_tables.append( bfrt_info.table_get('SwitchIngress.finger_ob_tcp_table_1'))
        finger_option_tables.append( bfrt_info.table_get('SwitchIngress.finger_ob_tcp_table_2'))
        finger_option_tables.append( bfrt_info.table_get('SwitchIngress.finger_ob_tcp_table_3'))
        finger_option_tables.append( bfrt_info.table_get('SwitchIngress.finger_ob_tcp_table_4'))
        finger_option_tables.append( bfrt_info.table_get('SwitchIngress.finger_ob_tcp_table_5'))
        finger_option_tables.append( bfrt_info.table_get('SwitchIngress.finger_ob_tcp_table_6'))
        finger_option_tables.append( bfrt_info.table_get('SwitchIngress.finger_ob_tcp_table_7'))
        finger_option_tables.append( bfrt_info.table_get('SwitchIngress.finger_ob_tcp_table_8'))
        finger_option_tables.append( bfrt_info.table_get('SwitchIngress.finger_ob_tcp_table_9'))
        handle_icmp_table = bfrt_info.table_get('SwitchIngress.handle_icmp_table')

        # reg tables
        bypass_pkts_reg_table = bfrt_info.table_get('SwitchIngress.bypass_pkts_reg')
        confuse_pkts_reg_table = bfrt_info.table_get('SwitchIngress.confuse_pkts_reg')
        icmp_pkts_reg_table = bfrt_info.table_get('SwitchIngress.icmp_pkts_reg')
        icmp_hit_reg_table = bfrt_info.table_get('SwitchIngress.icmp_hit_reg')
        udp_pkts_reg_table = bfrt_info.table_get('SwitchIngress.udp_pkts_reg')
        tcp_pkts_reg_table = bfrt_info.table_get('SwitchIngress.tcp_pkts_reg')
        resubmited_reg_table = bfrt_info.table_get('SwitchIngress.resubmited_reg')
        ecn_1_to_7_reg_table  = bfrt_info.table_get('SwitchIngress.ecn_1_to_7_reg')
        return_pkts_reg_table = bfrt_info.table_get('SwitchIngress.return_pkts_reg')

        # parsed_mss_reg_table = bfrt_info.table_get('SwitchIngress.parsed_mss_reg')
        # parsed_scale_reg_table = bfrt_info.table_get('SwitchIngress.parsed_scale_reg')
        # parsed_ts_reg_table = bfrt_info.table_get('SwitchIngress.parsed_ts_reg')
        # parsed_var_opt_reg_table = bfrt_info.table_get('SwitchIngress.parsed_var_opt_reg')
        # reg1_table = bfrt_info.table_get('SwitchIngress.reg1')

        fingerprint_path = os.path.join(TEST_DIR, 'fps.json')
        # Validate before any table or port changes on startup.
        with open(fingerprint_path, 'r') as source:
            validate_fingerprint(json.load(source))
        self.open_port(target)
        self.setup_preprocess_ipv4_tcp_length_rules(preprocess_ipv4_tcp_length_table, target)
        self.load_ipv4_fwd_rules_from_file(
            ipv4_fwd_table, os.path.join(TEST_DIR, '..', 'configs', 'ipv4_fwd_rules.txt'), target)

        host_ip = '192.168.3.2'
        refresh_tables = (handle_T1_7_table, finger_option_tables, handle_icmp_table,
                          filter_P1_6_table, filter_packet_enter_confuse_table)
        # Adopt only this host's old rules so a controller restart removes stale IDs.
        self.track_existing_fingerprint(
            [handle_T1_7_table] + finger_option_tables + [handle_icmp_table,
             filter_P1_6_table, filter_packet_enter_confuse_table], host_ip, target)

        detailed_fp = False

        while True:
            os.system("clear")
            self.refresh_fingerprint(fingerprint_path, refresh_tables, host_ip, target)
            print("正在进行Nmap指纹抗测绘")
            # self.dump_reg(reg1_table, 0, 'reg1', target)


            # self.dump_fwd_rules()
            # self.dump_ports_statistic(target)
            # print("\n*** Port ***")
            self.dump_reg(bypass_pkts_reg_table, 0, 'bypass_pkts_reg', target)
            self.dump_reg(confuse_pkts_reg_table, 0, 'confuse_pkts_reg', target)
            self.dump_reg(icmp_pkts_reg_table, 0, 'icmp_pkts_reg', target)
            self.dump_reg(icmp_hit_reg_table, 0, 'icmp_hit_reg', target)
            self.dump_reg(udp_pkts_reg_table, 0, 'udp_pkts_reg', target)
            self.dump_reg(tcp_pkts_reg_table, 0, 'tcp_pkts_reg', target)
            self.dump_reg(resubmited_reg_table, 0, 'resubmited_reg', target)
            for i in range(15):
                self.dump_reg(ecn_1_to_7_reg_table, i, 'ecn_1_to_7_reg', target)
            self.dump_reg(return_pkts_reg_table, 0, 'return_pkts_reg', target)

            # self.dump_reg(parsed_mss_reg_table, 0, 'parsed_mss_reg', target)
            # self.dump_reg(parsed_scale_reg_table, 0, 'parsed_scale_reg', target)
            # self.dump_reg(parsed_ts_reg_table, 0, 'parsed_ts_reg', target)
            # self.dump_reg(parsed_var_opt_reg_table, 0, 'parsed_var_opt_reg', target)




            # self.dump_fp_rules(detailed_fp)

            # timeout input
            # print("\n-----------------------------------------------------")
            # try:
            #     cmd = input_with_timeout('Command (d: detailed FP dump; s: simple FP dump):', 1)
            #     if cmd == 'd':
            #         detailed_fp = True
            #     elif cmd == 's':
            #         detailed_fp = False
            # except TimeoutError:
            #     print('Time out!')
            # else:
            #     pass
            time.sleep(2)
