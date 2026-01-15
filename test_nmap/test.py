import logging
import time
import os
import signal
import traceback
import json
from pprint import pprint
import random

from bfruntime_client_base_tests import BfRuntimeTest
import bfrt_grpc.client as gc

logger = logging.getLogger('Test')
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler())


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
                for i in range(opt_val):
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

    attacker_port = 176
    emulator_port = 184
    recirec_port = 68

    arp_ip_dict = {}
    tx_mac_dict = { 
        184 : "64:9d:99:ff:fd:63",
        176 : "9c:69:b4:65:0f:5d"
    }
    ipv4_port_fwd_rule_dict = {}
    refresh_table_tuple_list = []
    fp_ip_dict = {}
    # port dump
    port_speed_dict = {}
    port_statistic_dict = {}


    def setUp(self):
        BfRuntimeTest.setUp(self, self.client_id, self.p4_name)
    
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
                "port" : 176,
                "speed" : Speed_dict["100G"],
                "fec" : Fec_dict["RS"],
                "an" : AN_dict[0],
                "lpbk" : Loop_Back[0]

            },
            {
                "port" : 184,
                "speed" : Speed_dict["100G"],
                "fec" : Fec_dict["RS"],
                "an" : AN_dict[0],
                "lpbk" : Loop_Back[0]
            }
        ]
        for index, item in enumerate(port_lst, 1):
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
        for _table, _key in self.refresh_table_tuple_list:
            _table.entry_del(target, _key)
        self.refresh_table_tuple_list.clear()
    
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
        self.add_refresh_table_tuple(key, finger_option_tables)
        try:
            finger_option_tables.entry_add(target, key, data)
        except:
            finger_option_tables.entry_mod(target, key, data)

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
        self.add_refresh_table_tuple(key, finger_option_tables)
        try:
            finger_option_tables.entry_add(target, key, data)
        except:
            finger_option_tables.entry_mod(target, key, data)

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
        self.add_refresh_table_tuple(key, finger_option_tables)
        try:
            finger_option_tables.entry_add(target, key, data)
        except:
            finger_option_tables.entry_mod(target, key, data)

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
        self.add_refresh_table_tuple(key, finger_option_tables)
        try:
            finger_option_tables.entry_add(target, key, data)
        except:
            finger_option_tables.entry_mod(target, key, data)

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
        self.add_refresh_table_tuple(key, finger_option_tables)
        try:
            finger_option_tables.entry_add(target, key, data)
        except:
            finger_option_tables.entry_mod(target, key, data)

    def add_opt_ts_rule(self, finger_option_tables, table_id, ip, pkt_seq, target):
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
                'SwitchIngress.finger_Tcp_opt_TS_{}'.format(table_id)
            )
        ]
        self.add_refresh_table_tuple(key, finger_option_tables)
        try:
            finger_option_tables.entry_add(target, key, data)
        except:
            finger_option_tables.entry_mod(target, key, data)

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
                    self.add_opt_ts_rule(finger_option_tables[index], index, ip, pkt_seq, target)
                    # print("\toption {:2d}: timestamp, type=8, length=10, ts={}:{}".format(_id, fps['tsval'], fps['tsecr']))
                    options.append("TS(ts={})".format(opt_config_dict['tsval']))
                    raw_data_offset += 10

        
        table_id = len(options)
        while (raw_data_offset % 4 != 0 and table_id <= 9):
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
            ack_op_dict = {
                "S+": 1,   # ack_eq_seq_plus_one
                "S": 2,    # ack eq seq
                "Z": 3,    # ack set zero
                "O": 4,    # ack set other
                "O|S": 2,
                "O|S+": 1,
            }       
            seq_op_dict = {
                "A": 1, # seq_eq_ack
                "Z": 2, # seq set zero
                "O": 3,  # seq set other
                "A|O": 1
            }
            should_reply_dict = {
                "Y" : 1,
                "N" : 0
            }  

            if 'A' in raw_fps:
                ack_opcode = ack_op_dict[raw_fps['A']]
            if 'DF' in raw_fps and raw_fps['DF'] == 'Y':
                ipv4_flags |= (1<<1)
            if 'S' in raw_fps:
                seq_opcode = seq_op_dict[raw_fps['S']]
            if 'F' in raw_fps:
                if 'A' in raw_fps['F']: # ACK
                    tcp_flags |= (1 << 4)
                if 'R' in raw_fps['F']: # RST
                    tcp_flags |= (1 << 2)
                if 'S' in raw_fps['F']: # SYN
                    tcp_flags |= (1 << 1)
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
            if 'O' in raw_fps: # options
                opt_dict_list = raw_fps['O']
                opt_config_dict = {'mss':0, 'scale':0, 'tsval':0, 'tsecr':0, 'olayout':[]}
                # ts_dup = False
                print("raw options list:{}".format(opt_dict_list))
                for opt_dict in opt_dict_list:
                    for _opt_name, _opt_val in opt_dict.items():
                        _opt_name = _opt_name.lower()
                        if 'mss' == _opt_name:
                            opt_config_dict['olayout'].append('mss')
                            opt_config_dict['mss'] = _opt_val
                        elif 'nop' in _opt_name:
                            opt_config_dict['olayout'].append('nop')
                        elif 'eop' in _opt_name:
                            opt_config_dict['olayout'].append('eol+1')
                        elif 'w' == _opt_name:
                            opt_config_dict['olayout'].append('ws')
                            opt_config_dict['scale'] = _opt_val
                        elif 'sack' == _opt_name:
                            opt_config_dict['olayout'].append('sok')
                        elif 'ts' == _opt_name:
                            opt_config_dict['tsval'] = 4294967295
                            opt_config_dict['tsecr'] = 0
                            opt_config_dict['olayout'].append('ts')
            if _pkt_seq > 7:
                tcp_wsize = win
                opt_config_dict = {'mss':0, 'scale':0, 'tsval':0, 'tsecr':0, 'olayout':[]}
                # ts_dup = False
                if 'ISN' in raw_fps:
                    seq_from_isn = isn if isn != 0 else random.randint(1, 0xFFFFFFFF)
                print("P1-P6 options list:{}".format(ops_lst))
                for opt_dict in ops_lst:
                    for _opt_name, _opt_val in opt_dict.items():
                        _opt_name = _opt_name.lower()
                        if 'mss' == _opt_name:
                            opt_config_dict['olayout'].append('mss')
                            opt_config_dict['mss'] = _opt_val
                        elif 'nop' in _opt_name:
                            opt_config_dict['olayout'].append('nop')
                        elif 'eop' in _opt_name:
                            opt_config_dict['olayout'].append('eol+1')
                        elif 'w' == _opt_name:
                            opt_config_dict['olayout'].append('ws')
                            opt_config_dict['scale'] = _opt_val
                        elif 'sack' == _opt_name:
                            opt_config_dict['olayout'].append('sok')
                        elif 'ts' == _opt_name:
                            opt_config_dict['tsval'] = 4294967295
                            opt_config_dict['tsecr'] = 0
                            opt_config_dict['olayout'].append('ts')


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
                    ], 
                    'SwitchIngress.hdr_fp_setup'
                )
            ]

            handle_T1_7_table.entry_add(target, key, data)

            self.add_refresh_table_tuple(key, handle_T1_7_table)
            
            self.fp_ip_dict[hostIP]["Seq-{:x}".format(_pkt_seq)] = ";".join(
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
                    "OPS={}".format( options_fp_data)
                ]
            )

        print(">>>   generate_hdr_fp_data")
        # insert ECN and T1~T7
        if 'ECN' in fps:
            # TCP flags
            if "F" not in fps['ECN'] or fps['ECN']['F'] != 'AS':
                fps['ECN']['F'] = 'AS'
            if "A" not in fps['ECN']:
                fps['ECN']['A'] = 'S+'
            generate_hdr_fp_data(fps['ECN'], 0x1)
        if 'T1' in fps:
            generate_hdr_fp_data(fps['T1'], 0x8, fps.get("WIN", {}).get("W1", 512), fps.get("OPS").get("O1", {}),fps["ISN"]["s1"])
            generate_hdr_fp_data(fps['T1'], 0x9, fps.get("WIN", {}).get("W2", 512), fps.get("OPS").get("O2", {}),fps["ISN"]["s2"])
            generate_hdr_fp_data(fps['T1'], 0x10, fps.get("WIN", {}).get("W3", 512), fps.get("OPS").get("O3", {}),fps["ISN"]["s3"])
            generate_hdr_fp_data(fps['T1'], 0x11, fps.get("WIN", {}).get("W4", 512), fps.get("OPS").get("O4", {}),fps["ISN"]["s4"])
            generate_hdr_fp_data(fps['T1'], 0x12, fps.get("WIN", {}).get("W5", 512), fps.get("OPS").get("O5", {}),fps["ISN"]["s5"])
            generate_hdr_fp_data(fps['T1'], 0x13, fps.get("WIN", {}).get("W6", 512), fps.get("OPS").get("O6", {}),fps["ISN"]["s6"])
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
            if 'R' not in ie_dict or ie_dict['R'] == 'Y':
                # ttl_min = int(ie_dict['T'].split('-')[0])
                # ttl_max = int(ie_dict['T'].split('-')[1])
                ttl = ie_dict['TG']
                # icmp_ttl = random.randint(ttl_min, ttl_max)
                icmp_ttl = ttl
                keys = []
                datas = []
                # 1th reply
                keys.append(
                    handle_icmp_table.make_key(
                        [
                            gc.KeyTuple('hdr.ipv4.diffserv[5:0]', 0),
                            gc.KeyTuple('hdr.icmp.code', 9),
                            gc.KeyTuple('hdr.icmp_data.seq', 295),
                            gc.KeyTuple('ig_md.dst_ipv4', gc.ipv4_to_bytes(hostIP), prefix_len=32)
                        ]
                    )
                )
                if ie_dict['DFI'] == 'Y':
                    datas.append(
                        handle_icmp_table.make_data(
                            [gc.DataTuple('ttl', icmp_ttl)], 
                            'SwitchIngress.generate_icmp_reply'
                        )
                    )
                    self.fp_ip_dict[hostIP]['IE'].append(
                        "1th echo reply: TOS=0,icmp_code=9,icmp_seq=295,IP={},action=Reply(TTL={})".format(hostIP, icmp_ttl)
                    )
                else:
                    datas.append(
                        handle_icmp_table.make_data(
                            [], 
                            'SwitchIngress.ignore_icmp_request'
                        )
                    )
                    self.fp_ip_dict[hostIP]['IE'].append(
                        "1th echo reply: TOS=0,icmp_code=9,icmp_seq=295,IP={},action=Ignore".format(hostIP)
                    )
                # 2th reply
                keys.append(
                    handle_icmp_table.make_key(
                        [
                            gc.KeyTuple('hdr.ipv4.diffserv[5:0]', 4),
                            gc.KeyTuple('hdr.icmp.code', 0),
                            gc.KeyTuple('hdr.icmp_data.seq', 296),
                            gc.KeyTuple('ig_md.dst_ipv4', gc.ipv4_to_bytes(hostIP), prefix_len=32)
                        ]
                    )
                )
                datas.append(
                    handle_icmp_table.make_data(
                        [gc.DataTuple('ttl', icmp_ttl)], 
                        'SwitchIngress.generate_icmp_reply'
                    )
                )
                self.fp_ip_dict[hostIP]['IE'].append("2th echo reply: TOS=4,icmp_code=0,icmp_seq=296,IP={},action=Reply(TTL={})".format(hostIP, icmp_ttl))
                handle_icmp_table.entry_add(target, keys, datas)
                self.add_refresh_table_tuple(keys, handle_icmp_table)

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
                        gc.DataTuple('seq', index+8)
                    ],
                    'SwitchIngress.set_packet_seq'
                )
            )
        filter_P1_6_table.entry_add(target,keys,datas)
        self.add_refresh_table_tuple(keys, filter_P1_6_table)



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

        enter_table.entry_add(target, key, data)
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
        
        p4_table.entry_add( target, keys, datas)
    
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
        handle_arp_table = bfrt_info.table_get("SwitchIngress.handle_arp_table")
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
        # confuse_pkts_reg_table = bfrt_info.table_get('SwitchIngress.confuse_pkts_reg')
        # bypass_pkts_reg_table = bfrt_info.table_get('SwitchIngress.bypass_pkts_reg')
        # resubmit_reg_table = bfrt_info.table_get('SwitchIngress.resubmit_reg')
        # resubmited_reg_table = bfrt_info.table_get('SwitchIngress.resubmited_reg')
        # ecn_1_to_7_reg_table  = bfrt_info.table_get('SwitchIngress.ecn_1_to_7_reg')
        # icmp_pkts_reg_table = bfrt_info.table_get('SwitchIngress.icmp_pkts_reg')
        # icmp_hit_reg_table = bfrt_info.table_get('SwitchIngress.icmp_hit_reg')
        # udp_pkts_reg_table = bfrt_info.table_get('SwitchIngress.udp_pkts_reg')
        # tcp_pkts_reg_table = bfrt_info.table_get('SwitchIngress.tcp_pkts_reg')
        # return_pkts_reg_table = bfrt_info.table_get('SwitchIngress.return_pkts_reg')
        # parsed_mss_reg_table = bfrt_info.table_get('SwitchIngress.parsed_mss_reg')
        # parsed_scale_reg_table = bfrt_info.table_get('SwitchIngress.parsed_scale_reg')
        # parsed_ts_reg_table = bfrt_info.table_get('SwitchIngress.parsed_ts_reg')
        # parsed_var_opt_reg_table = bfrt_info.table_get('SwitchIngress.parsed_var_opt_reg')

        # reg1_table = bfrt_info.table_get('SwitchIngress.reg1')

        self.open_port(target)
        self.load_arp_rules(handle_arp_table, "GXC/antiFpProbe/configs/arp_rules.txt", target)
        self.setup_preprocess_ipv4_tcp_length_rules(preprocess_ipv4_tcp_length_table, target)
        self.load_ipv4_fwd_rules_from_file(ipv4_fwd_table, "GXC/antiFpProbe/configs/ipv4_fwd_rules.txt", target)


        # def index_to_ip(i):
        #     x = i - 1  # 0-based
        #     b = (x >> 16) & 255
        #     c = (x >> 8)  & 255
        #     d = x & 255
        #     return "%d.%d.%d.%d" % (10, b, c, d)
        
        # print("正在进行Nmap指纹抗测绘")
        # for i in range(100):
        #     rule_type = 0
        #     host_ip = index_to_ip(i+1)
        #     host_type = "linux 5.4"
        #     with open("GXC/antiFpProbe/test_nmap/fps.json", 'r') as file:
        #         fps = json.load(file)
        #     self.handle_fp_rules(
        #         handle_T1_7_table, 
        #         finger_option_tables, 
        #         handle_icmp_table,
        #         rule_type, 
        #         host_ip,
        #         host_type, 
        #         fps, 
        #         target
        #     )
        #     self.add_filter_P1_6_table_rulers(filter_P1_6_table, host_ip, target)
        #     self.add_confuse_enter_rule(filter_packet_enter_confuse_table, host_ip, target)


        detailed_fp = False

        while True:
            os.system("clear")
            rule_type = 0
            host_ip = "192.168.3.2"
            host_type = "linux 5.4"
            with open("GXC/antiFpProbe/test_nmap/fps.json", 'r') as file:
                fps = json.load(file)

            self.clear_refresh_tuple_for_ip(target)
            self.handle_fp_rules(
                handle_T1_7_table, 
                finger_option_tables, 
                handle_icmp_table,
                rule_type, 
                host_ip,
                host_type, 
                fps, 
                target
            )
            self.add_filter_P1_6_table_rulers(filter_P1_6_table, host_ip, target)
            self.add_confuse_enter_rule(filter_packet_enter_confuse_table, host_ip, target)
            print("正在进行Nmap指纹抗测绘")
            # self.dump_reg(reg1_table, 0, 'reg1', target)
            time.sleep(1)

            # self.dump_fwd_rules()
            # self.dump_ports_statistic(target)
            # print("\n*** Port ***")
            # self.dump_reg(confuse_pkts_reg_table, 0, 'confuse_pkts_reg', target)
            # self.dump_reg(bypass_pkts_reg_table, 0, 'bypass_pkts_reg', target)
            # self.dump_reg(parsed_mss_reg_table, 0, 'parsed_mss_reg', target)
            # self.dump_reg(parsed_scale_reg_table, 0, 'parsed_scale_reg', target)
            # self.dump_reg(parsed_ts_reg_table, 0, 'parsed_ts_reg', target)
            # self.dump_reg(parsed_var_opt_reg_table, 0, 'parsed_var_opt_reg', target)
            # self.dump_reg(resubmit_reg_table, 0, 'resubmit_reg', target)
            # self.dump_reg(resubmited_reg_table, 0, 'resubmited_reg', target)
            # self.dump_reg(icmp_pkts_reg_table, 0, 'icmp_pkts_reg', target) 
            # self.dump_reg(icmp_hit_reg_table, 0, 'icmp_hit_reg', target) 
            # self.dump_reg(udp_pkts_reg_table, 0, 'udp_pkts_reg', target) 
            # self.dump_reg(tcp_pkts_reg_table, 0, 'tcp_pkts_reg', target) 
            # self.dump_reg(return_pkts_reg_table, 0, 'return_pkts_reg', target)
            # for i in range(15):
            #     self.dump_reg(ecn_1_to_7_reg_table, i, 'ecn_1_to_7_reg', target)
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
        