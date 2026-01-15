import logging
import random
import time
import os
import signal
import sys
import multiprocessing
import traceback
import json

from bfruntime_client_base_tests import BfRuntimeTest
import bfrt_grpc.client as gc

logger = logging.getLogger('Test')
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler())


class TimeoutError(Exception):
    pass

def input_with_timeout(prompt, timeout):
    def alarm_handler(signum, frame):
        raise TimeoutError

    signal.signal(signal.SIGALRM, alarm_handler)
    signal.alarm(timeout)

    try:
        return input(prompt)
    finally:
        signal.alarm(0)

class P0F_Test(BfRuntimeTest):
    p4_name = "antiFpProbe"
    arp_ip_dict = {}
    tx_mac_dict = { 
        184 : "64:9d:99:ff:fd:63",
        176 : "9c:69:b4:65:0f:5d"
    }
    refresh_table_tuple_list = []
    ipv4_port_fwd_rule_dict = {}
    fp_ip_dict = {}
    port_speed_dict = {}
    port_statistic_dict = {}
    fp_prefix_len = 24



    def setUp(self):
        client_id = 0
        BfRuntimeTest.setUp(self, client_id, self.p4_name)
    
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
            time.sleep(2)

    def setup_preprocess_ipv4_tcp_length_rules(self, p4_table, target):
        keys = []
        datas = []

        for i in range(6,16):
            _k = i << 4
            _d = (i - 5) * 4
            # print("Data_offset:{}->{}".format(_k, _d))
            keys.append( 
                p4_table.make_key(
                    [
                        gc.KeyTuple('hdr.option.$valid', True),
                        gc.KeyTuple('hdr.tcp.data_offset', _k)
                    ]
                )
            )
            datas.append(
                p4_table.make_data(
                    [gc.DataTuple('len_delta', _d)], 
                    'SwitchIngress.preprocess_ipv4_tcp_length'
                )
            )
        p4_table.entry_add( target, keys, datas)

    
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
    
    def add_opt_end_rule(self, fp_opt_table, table_id, ip, target):
        key = [
            fp_opt_table.make_key(
                [
                    gc.KeyTuple('hdr.ipv4.src_addr', gc.ipv4_to_bytes(ip))
                ]
            )
        ]
        data = [
            fp_opt_table.make_data(
                [], 
                'SwitchIngress.finger_Tcp_opt_end_{}'.format(table_id)
            )
        ]
        self.add_refresh_table_tuple(key, fp_opt_table)
        try:
            fp_opt_table.entry_add(target, key, data)
        except:
            fp_opt_table.entry_mod(target, key, data)

    def add_opt_nop_rule(self, fp_opt_table, table_id, ip, target):
        key = [
            fp_opt_table.make_key(
                [gc.KeyTuple('hdr.ipv4.src_addr', gc.ipv4_to_bytes(ip))]
            )
        ]
        data = [
            fp_opt_table.make_data(
                [],
                'SwitchIngress.finger_Tcp_opt_Nop_{}'.format(table_id)
            )
        ]
        self.add_refresh_table_tuple(key, fp_opt_table)
        try:
            fp_opt_table.entry_add(target, key, data)
        except:
            fp_opt_table.entry_mod(target, key, data)

    def add_opt_mss_rule(self, fp_opt_table, table_id, ip, mss, target):
        key = [
            fp_opt_table.make_key(
                [gc.KeyTuple('hdr.ipv4.src_addr', gc.ipv4_to_bytes(ip))]
            )
        ]
        data = [
            fp_opt_table.make_data(
                [gc.DataTuple('mss', mss)],
                'SwitchIngress.finger_Tcp_opt_MSS_{}'.format(table_id)
            )
        ]
        self.add_refresh_table_tuple(key, fp_opt_table)
        try:
            fp_opt_table.entry_add(target, key, data)
        except:
            fp_opt_table.entry_mod(target, key, data)


    def add_opt_wsize_rule(self, fp_opt_table, table_id, ip, scale, target):
        key = [
            fp_opt_table.make_key(
                [gc.KeyTuple('hdr.ipv4.src_addr', gc.ipv4_to_bytes(ip))]
            )
        ]
        data = [
            fp_opt_table.make_data(
                [gc.DataTuple('scale', scale)],
                'SwitchIngress.finger_Tcp_opt_Wsize_{}'.format(table_id)
            )
        ]
        self.add_refresh_table_tuple(key, fp_opt_table)
        try:
            fp_opt_table.entry_add(target, key, data)
        except:
            fp_opt_table.entry_mod(target, key, data)


    def add_opt_sok_rule(self, fp_opt_table, table_id, ip, target):
        key = [
            fp_opt_table.make_key(
                [gc.KeyTuple('hdr.ipv4.src_addr', gc.ipv4_to_bytes(ip))]
            )
        ]
        data = [
            fp_opt_table.make_data(
                [],
                'SwitchIngress.finger_Tcp_opt_SOK_{}'.format(table_id)
            )
        ]
        self.add_refresh_table_tuple(key, fp_opt_table)
        try:
            fp_opt_table.entry_add(target, key, data)
        except:
            fp_opt_table.entry_mod(target, key, data)


    def add_opt_ts_rule(self, fp_opt_table, table_id, ip, target):
        key = [
            fp_opt_table.make_key(
                [gc.KeyTuple('hdr.ipv4.src_addr', gc.ipv4_to_bytes(ip))]
            )
        ]
        data = [
            fp_opt_table.make_data(
                [],
                'SwitchIngress.finger_Tcp_opt_TS_{}'.format(table_id)
            )
        ]
        self.add_refresh_table_tuple(key, fp_opt_table)
        try:
            fp_opt_table.entry_add(target, key, data)
        except:
            fp_opt_table.entry_mod(target, key, data)

    
    def add_fp_rule(self, fp_ob_table, fp_opt_tables, rule_tuple, target):
        rule_type          = rule_tuple[0]
        ip                 = rule_tuple[1]
        os                 = rule_tuple[2]
        fps                = rule_tuple[3]
        raw_data_offset    = 20
        new_data_offset    = 0
        new_ipv4_len_delta = 0
        new_ttl            = 0
        new_wsize          = 0
        new_df             = 0
        is_dup = False

        if ip in self.fp_ip_dict:
            del self.fp_ip_dict[ip]
            is_dup = True

        options = []
        # finger option tables
        for _id, option in enumerate(fps["olayout"]):
            if option == 'eol+1': # 1B
                self.add_opt_end_rule(fp_opt_tables[_id], _id, ip, target)
                options.append("END")
                raw_data_offset += 1

            elif option == 'nop': # 1B
                self.add_opt_nop_rule(fp_opt_tables[_id], _id, ip, target)
                options.append("NOP")
                raw_data_offset += 1

            elif option == 'mss': # 4B
                self.add_opt_mss_rule(fp_opt_tables[_id], _id, ip, fps["mss"], target)
                options.append("MSS(mss={})".format(fps["mss"]))
                raw_data_offset += 4

            elif option == 'ws': # 3B
                self.add_opt_wsize_rule(fp_opt_tables[_id], _id, ip, fps["scale"], target)
                options.append("WS(scale={})".format(fps["scale"]))
                raw_data_offset += 3

            elif option == 'sok': # 2B
                self.add_opt_sok_rule(fp_opt_tables[_id], _id, ip, target)
                options.append("SOK")
                raw_data_offset += 2

            elif option == 'ts': # 10B
                self.add_opt_ts_rule(fp_opt_tables[_id], _id, ip, target)
                options.append("TS({},{})".format(232561103,0))
                raw_data_offset += 10

        table_id = len(options)
        while (raw_data_offset % 4 != 0 and table_id <= 9):
            self.add_opt_end_rule(fp_opt_tables[table_id], table_id, ip, target)
            raw_data_offset += 1
            table_id += 1

        new_ipv4_len_delta = raw_data_offset - 20
        new_data_offset = int(raw_data_offset / 4) << 4


        # print("raw_data_offset = {}".format(raw_data_offset))
        # print("new_ipv4_len_delta = {}".format(new_ipv4_len_delta))
        # print("new_data_offset = {}".format(new_data_offset))

        self.fp_ip_dict[ip] = {"ruleType":rule_type, "OS":os, "RawOptLen":new_data_offset, "Options":"-".join(options)}
        
        # finger op table
        if 'ttl' in fps and fps['ttl'] != None:
            new_ttl = fps['ttl']
        
        if 'wsize' in fps and fps['wsize'] != None:
            new_wsize = fps['wsize']
        
        if 'df' in fps and fps['df'] != None:
            new_df = fps['df']


        key = [
            fp_ob_table.make_key([gc.KeyTuple('hdr.ipv4.src_addr', gc.ipv4_to_bytes(ip))])
        ]
        data = [
            fp_ob_table.make_data(
                [
                    gc.DataTuple('ttl',                  new_ttl),
                    gc.DataTuple('wsize',                new_wsize),
                    gc.DataTuple('df',                   new_df),
                    gc.DataTuple('m_new_data_offset',    new_data_offset),
                    gc.DataTuple('m_new_ipv4_len_delta', new_ipv4_len_delta)
                ],
                'SwitchIngress.finger_action_wsize'
            )
        ]
        try:
            if not is_dup:
                fp_ob_table.entry_add(target, key, data)
                self.add_refresh_table_tuple(key, fp_ob_table)
            else:
                fp_ob_table.entry_mod(target, key, data)
        except:
            print("Fail to insert ttl = {}, wsize = {}, new_data_offset = {}, new_ipv4_len_delta = {}".format(new_ttl, new_wsize,new_data_offset,new_ipv4_len_delta))
            import traceback
            traceback.print_exc()

    def dump_fwd_rules(self):
        print("****Forward rules:****")
        for _prefix, _out_port in self.ipv4_port_fwd_rule_dict.items():
            print("{}\t---> {}, binded mac = {}".format(_prefix, _out_port, self.tx_mac_dict[_out_port]))
        print("**********END************\n")
    
    def dump_arp_rules(self):
        print("\n*********ARP rules************")
        for _ip, _mac in self.arp_ip_dict.items():
            print("{}:{}".format(_ip, _mac))

    def dump_ports_statistic(self, target):
        for port_key, port_item in self.port_statistic_dict.items():
            _port = port_item['port']
            get_data_list = None
            resp = self.port_stat_table.entry_get(
                target,
                [self.port_stat_table.make_key([gc.KeyTuple('$DEV_PORT', _port)])],
                {"from_hw": True},
                get_data_list)
            
            # dump to dict
            data_dict  = next(resp)[0].to_dict()
            
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

            print("Port {:3}: rx = {:10.3f} Mpps ({:10.3f} Mbps), tx = {:10.3f} Mpps ({:10.3f} Mbps)".format(
                            _port, 
                            self.port_speed_dict[_port]['rx']/1000000, 
                            self.port_speed_dict[_port]['rx_MB'] * 8,
                            self.port_speed_dict[_port]['tx']/1000000, 
                            self.port_speed_dict[_port]['tx_MB'] * 8))

    def dump_fp_rules(self):
        for ip, _dict in self.fp_ip_dict.items():
            print("IP:{}, RuleType:{}, OS:{}, RawOptLen:{}, options:{}".format(ip, _dict['ruleType'], _dict['OS'], _dict['RawOptLen'], _dict['Options']))

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
    
    def clear_refresh_tuple_for_ip(self, target):
        self.fp_ip_dict.clear()
        for _table, _key in self.refresh_table_tuple_list:
            _table.entry_del(target, _key)
        self.refresh_table_tuple_list.clear()

    def add_refresh_table_tuple(self, _key, _table):
        self.refresh_table_tuple_list.append((_table, _key))
    
    def runTest(self):
        bfrt_info = self.interface.bfrt_info_get(self.p4_name)
        target = gc.Target(device_id=0, pipe_id=0xffff)

        self.port_table = bfrt_info.table_get("$PORT")

        handle_arp_table = bfrt_info.table_get("SwitchIngress.handle_arp_table")
        preprocess_ipv4_tcp_length_table  = bfrt_info.table_get('SwitchIngress.preprocess_ipv4_tcp_length_table')
        ipv4_fwd_table = bfrt_info.table_get('SwitchIngress.ipv4_fwd_table')

        finger_ob_table = bfrt_info.table_get('SwitchIngress.finger_ob_table')
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

        self.open_port(target)
        self.load_arp_rules(handle_arp_table, "GXC/antiFpProbe/configs/arp_rules.txt", target)
        self.setup_preprocess_ipv4_tcp_length_rules(preprocess_ipv4_tcp_length_table, target)
        self.load_ipv4_fwd_rules_from_file(ipv4_fwd_table, "GXC/antiFpProbe/configs/ipv4_fwd_rules.txt", target)


        print("正在进行p0f指纹对抗实验")
        # rule_type = 0
        # host_ip = "192.168.3.1"
        # host_type = "2.4-2.6"
        # with open("GXC/antiFpProbe/test_p0f/fps.json", 'r') as file:
        #     fps = json.load(file)
        # rule_tuple = (rule_type, host_ip, host_type, fps)
        # self.add_fp_rule(finger_ob_table, finger_option_tables, rule_tuple, target)
        
        
        while True:
            rule_type = 0
            host_ip = "192.168.3.1"
            host_type = "2.4-2.6"
            with open("GXC/antiFpProbe/test_p0f/fps.json", 'r') as file:
                fps = json.load(file)
            rule_tuple = (rule_type, host_ip, host_type, fps)
            self.clear_refresh_tuple_for_ip(target)
            self.add_fp_rule(finger_ob_table, finger_option_tables, rule_tuple, target)
            # self.dump_reg(reg1_table, 0, 'reg1', target)
            time.sleep(1)
            # os.system("clear")
            
            # os.system("clear")
            # self.dump_fwd_rules()
            # self.dump_arp_rules()
            # self.dump_ports_statistic(target)
            # self.dump_fp_rules()



