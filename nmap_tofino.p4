/* -*- P4_16 -*- */
#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else 
#include <tna.p4>
#endif
#define ENB_NMAP 1

#include "common/headers.p4"
#include "common/util.p4"

#define BLOOM_FILTER_ENTRIES 4096   // 布隆过滤器
#define MASK_SHIFT 12
/* 8b */
struct tcp_option_end_t {
    bit<8> kind;
}

/* 8b 填充*/
struct tcp_option_nop_t {
    bit<8> kind;
}

/* 32b 最大报文长度*/
struct tcp_option_mss_t {
    bit<8> kind;
    bit<8> length;
    bit<16> mss;
}

/* 24b 用于 TCP 窗口大小的缩放因子*/
struct tcp_option_ws_t {
    bit<8> kind;
    bit<8> length;
    bit<8> scale;
}

/* 16b 表示支持选择性确认（Selective ACK）*/
struct tcp_option_sack_permitted_t {
    bit<8> kind;
    bit<8> length;
}

/* 80b 包含时间戳值和回显时间戳，用于 RTT 测量和 PAWS*/
struct tcp_option_ts_t {
    bit<8> kind;
    bit<8> length;
    bit<32> tsval;
    bit<32> tsecr;
}


/****************************************************************
        SwitchIngressParser
****************************************************************/
parser SwitchIngressParser(
        packet_in pkt,
        out headers_t hdr,
        out metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    TofinoIngressParser() tofino_parser;
    Checksum() icmp_checksum;

    state start {
        /*如果解析到这些opt就将值变成对应的kind */
        ig_md.mss = 0;      // 最大保温场地
        ig_md.scale = 0;    // 缩放因子
        ig_md.tsval = 0;    // 时间戳
        ig_md.tsecr = 0;    // 时间戳回显
        ig_md.has_ts = 1w0;

        /*默认没有解析到这些 */
        // ig_md.parsed_mss = false;
        // ig_md.parsed_scale = false;
        // ig_md.parsed_ts = false;
        // ig_md.parsed_var_option = false;

        ig_md.update_ipv4_checksum = false;
        ig_md.update_tcp_checksum = false;
        ig_md.update_udp_checksum = false;
        ig_md.update_icmp_checksum = false;
        ig_md.update_icmp_ipv4_checksum = false;
        ig_md.icmp_checksum_temp = 16w0;

        tofino_parser.apply(pkt, ig_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_ARP: parse_arp;
            default: accept;
        }
    }

    state parse_arp {
        pkt.extract(hdr.arp);
        ig_md.dst_ipv4 = hdr.arp.target_ipv4;
        transition accept;
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        ig_md.dst_ipv4 = hdr.ipv4.dst_addr;
        icmp_checksum.subtract(hdr.ipv4.ttl);
        icmp_checksum.subtract(hdr.ipv4.diffserv);
        icmp_checksum.subtract(hdr.ipv4.src_addr);
        icmp_checksum.subtract(hdr.ipv4.dst_addr);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_RECIRC_TCP : parse_recirc_tcp; // 回环报文
            IP_PROTOCOLS_TCP  : parse_tcp;              // tcp报文
            IP_PROTOCOLS_UDP  : parse_udp;              // udp报文
            IP_PROTOCOLS_ICMP : parse_icmp;             // icmp报文
            default           : accept;
        }
    }

    state parse_icmp {
        pkt.extract(hdr.icmp);
        icmp_checksum.subtract(hdr.icmp.hdr_checksum);
        icmp_checksum.subtract(hdr.icmp.icmp_type);
        icmp_checksum.subtract(hdr.icmp.code);
        // 把当前 icmp_checksum 的中间结果存到元数据 ig_md.icmp_checksum_temp
        ig_md.icmp_checksum_temp = icmp_checksum.get();
        transition select(hdr.icmp.icmp_type) {
            8w8: parse_icmp_data; // ping请求
            default: accept; 
        }
    }

    state parse_icmp_data {
        pkt.extract(hdr.icmp_data);
        transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition accept;
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition select(hdr.tcp.data_offset) {
            {4w12}: copy_fixed_tcp_option_28B;
            {4w11}: copy_fixed_tcp_option_24B;
            {4w10}: copy_fixed_tcp_option_20B;
            {4w9} : copy_fixed_tcp_option_16B;
            {4w8} : copy_fixed_tcp_option_12B;
            {4w7} : copy_fixed_tcp_option_8B;
            {4w6} : copy_fixed_tcp_option_4B;
            default: accept;
        }
    }

    #define STATE_COPY_OPTION(X)\
    state copy_fixed_tcp_option_##X##B { \
        pkt.extract(hdr.option_##X##B); \
        hdr.dummy_option_##X##B.setValid(); \
        hdr.dummy_option_##X##B = hdr.option_##X##B; \
        transition accept;      \
    }
    
    STATE_COPY_OPTION(28)
    STATE_COPY_OPTION(24)
    STATE_COPY_OPTION(20)
    STATE_COPY_OPTION(16)
    STATE_COPY_OPTION(12)
    STATE_COPY_OPTION(8)
    STATE_COPY_OPTION(4)

    state parse_recirc_tcp {
        pkt.extract(hdr.tcp);
        transition select(hdr.tcp.data_offset) {
            {4w12}: parse_fixed_tcp_option_28B;
            {4w11}: parse_fixed_tcp_option_24B;
            {4w10}: parse_fixed_tcp_option_20B;
            {4w9} : parse_fixed_tcp_option_16B;
            {4w8} : parse_fixed_tcp_option_12B;
            {4w7} : parse_fixed_tcp_option_8B;
            {4w6} : parse_fixed_tcp_option_4B;
            default: accept;
        }
    }

 
    #define STATE_PARSE_OPTION(X) \
    state parse_fixed_tcp_option_##X##B { \
        pkt.extract(hdr.option_##X##B); \
        transition parse_dummy_option; \
    }

    
    STATE_PARSE_OPTION(28)
    STATE_PARSE_OPTION(24)
    STATE_PARSE_OPTION(20)
    STATE_PARSE_OPTION(16)
    STATE_PARSE_OPTION(12)
    STATE_PARSE_OPTION(8)
    STATE_PARSE_OPTION(4)

    state parse_dummy_option{
        ig_md.parsed_var_option = true; 
        transition check_next_option;
    }

    state check_next_option {
        // 只看不吃，查看下一个opt的kind
        bit<8> option_kind = pkt.lookahead<bit<8>>();

        transition select(option_kind) {
            8w0xff:  parse_option_deol;     
            8w0:     parse_option_eol;      
            8w1:     parse_option_nop;      
            8w2:     parse_option_mss;      
            8w3:     parse_option_ws;       
            8w4:     parse_option_sack_permitted;   
            8w8:     parse_option_ts;       
            default: accept;
        }
    }

    // DEOL（自定义 0xff 终止符）。
    // 这是这套管线自己插入的“强结束”标记（在 ingress 里回环前写入），用于回环后解析时立刻停表。             
    state parse_option_deol {
        pkt.advance(1*8);
        transition accept;
    }

    // 标准“选项结束”。此实现里只是前进 1 字节后继续检查（允许后面有 padding/NOP）
    state parse_option_eol {
        pkt.advance(1*8);
        transition check_next_option;
    }

    // 前进 1 字节，继续检查（常用于对齐/填充）
    state parse_option_nop {
        pkt.advance(1*8);
        transition check_next_option;
    }

    // SACK 允许，前进 2 字节（这里不存额外元数据），继续检查。
    state parse_option_sack_permitted {
        pkt.advance(2*8);
        transition check_next_option;
    }

    // 读取结构 tcp_option_mss_t，再前进 4 字节；
    // 把 mss.mss 写到 ig_md.mss，并置 ig_md.parsed_mss=true
    state parse_option_mss {
        tcp_option_mss_t mss = pkt.lookahead<tcp_option_mss_t>();        
        pkt.advance(4*8);
        ig_md.mss = mss.mss;
        ig_md.parsed_mss = true;
        transition check_next_option;
    }

    // 窗口缩放，读取 tcp_option_ws_t，前进 3 字节；
    // 把 scale 写到 ig_md.scale，并置 parsed_scale=true。
    state parse_option_ws {
        tcp_option_ws_t ws = pkt.lookahead<tcp_option_ws_t>();        
        pkt.advance(3*8);
        ig_md.scale = ws.scale;
        ig_md.parsed_scale = true;
        transition check_next_option;
    }

    // 时间戳，读取 tcp_option_ts_t，前进 10 字节；
    // 把 tsval/tsecr 写到 ig_md.tsval/tsecr，并置 parsed_ts=true。
    state parse_option_ts {
        tcp_option_ts_t ts = pkt.lookahead<tcp_option_ts_t>();
        pkt.advance(10*8);
        ig_md.has_ts = 1w1;
        ig_md.tsval = ts.tsval;
        ig_md.tsecr = ts.tsecr;
        ig_md.parsed_ts = true;
        transition check_next_option;
    }
}



/****************************************************************
                    SwitchIngressParser
****************************************************************/
control SwitchIngressDeparser(
        packet_out pkt,
        inout headers_t hdr,
        in metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    
    Checksum() ipv4_checksum;
    Checksum() icmp_ipv4_checksum;

    apply {
        if(ig_md.update_ipv4_checksum) {
            hdr.ipv4.hdr_checksum = ipv4_checksum.update(
                {
                    hdr.ipv4.version,
                    hdr.ipv4.ihl,
                    hdr.ipv4.diffserv,
                    hdr.ipv4.total_len,
                    hdr.ipv4.identification,
                    hdr.ipv4.res_bit,
                    hdr.ipv4.df_bit,
                    hdr.ipv4.mf_bit,
                    hdr.ipv4.frag_offset,
                    hdr.ipv4.ttl,
                    hdr.ipv4.protocol,
                    hdr.ipv4.src_addr,
                    hdr.ipv4.dst_addr
                }
            );
        }

        if(ig_md.update_icmp_ipv4_checksum) {
            hdr.icmp_ipv4.hdr_checksum = icmp_ipv4_checksum.update(
                {
                    hdr.icmp_ipv4.version,
                    hdr.icmp_ipv4.ihl,
                    hdr.icmp_ipv4.diffserv,
                    hdr.icmp_ipv4.total_len,
                    hdr.icmp_ipv4.identification,
                    hdr.icmp_ipv4.res_bit,
                    hdr.icmp_ipv4.df_bit,
                    hdr.icmp_ipv4.mf_bit,
                    hdr.icmp_ipv4.frag_offset,
                    hdr.icmp_ipv4.ttl,
                    hdr.icmp_ipv4.protocol,
                    hdr.icmp_ipv4.src_addr,
                    hdr.icmp_ipv4.dst_addr
                }
            );
        }

        pkt.emit(hdr);
    }
}



/****************************************************************
                    SwitchIngress
****************************************************************/
control SwitchIngress(
    inout headers_t hdr,
    inout metadata_t ig_md,
    in ingress_intrinsic_metadata_t  ig_intr_md,
    in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {
    
    PortId_t recirc_port = 68; 
    PortId_t send_port = 176;
    PortId_t receive_port = 184;

    bool is_from_recirec_port = false;

    bool direct_forward   = false;
    bool do_swap_ethernet = false;
    bool do_swap_ipv4     = false;
    bool do_swap_tcp      = false;
    bool do_swap_udp      = false;
    bool do_handle_icmp_unreachable = false;
    bit<1> do_reply       = 1;

    // Register<bit<32>, bit<32>>(1, 32w0) bypass_pkts_reg;        // bypass_pkts_reg：进入 旁路路径 的包数量。
    // RegisterAction<bit<32>, bit<32>, void>(bypass_pkts_reg) bypass_pkts_add = {
    //     void apply(inout bit<32> item) {
    //         item = item + 1;
    //     }
    // };
    // Register<bit<32>, bit<32>>(1, 32w0) confuse_pkts_reg;       // confuse_pkts_reg：进入 混淆路径 的包数量。
    // RegisterAction<bit<32>, bit<32>, void>(confuse_pkts_reg) confuse_pkts_add = {
    //     void apply(inout bit<32> item) {
    //         item = item + 1;
    //     }
    // };
    // Register<bit<32>, bit<32>>(1, 32w0) resubmited_reg;     // 真正来自回环口的包数量。
    // RegisterAction<bit<32>, bit<32>, void>(resubmited_reg) resubmited_add = {
    //     void apply(inout bit<32> item) {
    //         item = item + 1;
    //     }
    // };
    // Register<bit<32>, bit<32>>(1, 32w0) parsed_mss_reg;
    // RegisterAction<bit<32>, bit<32>, void>(parsed_mss_reg) parsed_mss_add = {
    //     void apply(inout bit<32> item) {
    //         item = item + 1;
    //     }
    // };
    // Register<bit<32>, bit<32>>(1, 32w0) parsed_scale_reg;
    // RegisterAction<bit<32>, bit<32>, void>(parsed_scale_reg) parsed_scale_add = {
    //     void apply(inout bit<32> item) {
    //         item = item + 1;
    //     }
    // };
    // Register<bit<32>, bit<32>>(1, 32w0) parsed_ts_reg;
    // RegisterAction<bit<32>, bit<32>, void>(parsed_ts_reg) parsed_ts_add = {
    //     void apply(inout bit<32> item) {
    //         item = item + 1;
    //     }
    // };
    // Register<bit<32>, bit<32>>(1, 32w0) parsed_var_opt_reg;     // 遇到过 可变长度选项 的次数
    // RegisterAction<bit<32>, bit<32>, void>(parsed_var_opt_reg) parsed_var_opt_add = {
    //     void apply(inout bit<32> item) {
    //         item = item + 1;
    //     }
    // };
    // Register<bit<32>, bit<32>>(1, 32w0) tcp_pkts_reg;
    // RegisterAction<bit<32>, bit<32>, void>(tcp_pkts_reg) tcp_pkts_add = {
    //     void apply(inout bit<32> item) {
    //         item = item + 1;
    //     }
    // };
    // Register<bit<32>, bit<32>>(1, 32w0) resubmit_reg;   // 记录包被标记回环/重提交的次数（单元素寄存器，初值 0）
    // RegisterAction<bit<32>, bit<32>, void>(resubmit_reg) resubmit_add = {
    //     void apply(inout bit<32> item) {
    //         item = item + 1;
    //     }
    // };
    // Register<bit<32>, bit<32>>(15, 32w0) ecn_1_to_7_reg;    // 统计对应的探针包
    // RegisterAction<bit<32>, bit<32>, void>(ecn_1_to_7_reg) ecn_1_to_7_add = {
    //     void apply(inout bit<32> item) {
    //         item = item + 1;
    //     }
    // };
    // Register<bit<32>, bit<32>>(1, 32w0) icmp_pkts_reg;     
    // RegisterAction<bit<32>, bit<32>, void>(icmp_pkts_reg) icmp_pkts_add = {
    //     void apply(inout bit<32> item) {
    //         item = item + 1;
    //     }
    // };
    // Register<bit<32>, bit<32>>(1, 32w0) icmp_hit_reg;       // 统计 ICMP 匹配到应答规则的次数。
    // RegisterAction<bit<32>, bit<32>, void>(icmp_hit_reg) icmp_hit_add = {
    //     void apply(inout bit<32> item) {
    //         item = item + 1;
    //     }
    // };
    // Register<bit<32>, bit<32>>(1, 32w0) udp_pkts_reg;
    // RegisterAction<bit<32>, bit<32>, void>(udp_pkts_reg) udp_pkts_add = {
    //     void apply(inout bit<32> item) {
    //         item = item + 1;
    //     }
    // };
    // Register<bit<32>, bit<32>>(1, 32w0) return_pkts_reg;
    // RegisterAction<bit<32>, bit<32>, void>(return_pkts_reg) return_pkts_add = {
    //     void apply(inout bit<32> item) {
    //         item = item + 1;
    //     }
    // };
    




    

    action swap_sender_and_target(){
        mac_addr_t temp_mac_addr   = hdr.arp.sender_mac;
        ipv4_addr_t temp_ipv4_addr = hdr.arp.sender_ipv4;

        hdr.arp.sender_mac         = hdr.arp.target_mac;
        hdr.arp.sender_ipv4        = hdr.arp.target_ipv4;

        hdr.arp.target_mac         = temp_mac_addr;
        hdr.arp.target_ipv4        = temp_ipv4_addr;
    }

    /**
        在交换机上拦截 ARP 请求，并伪造一个 ARP 回复（由指定的代理 MAC 地址应答），
        然后直接回给请求方。
    **/
    action handle_arp_request(mac_addr_t arp_proxy_mac) {
        // Send to ARP proxy
        hdr.arp.target_mac = arp_proxy_mac;
        hdr.ethernet.dst_addr = arp_proxy_mac;

        hdr.arp.opcode = 2;

        swap_sender_and_target();
        do_swap_ethernet = true;
        
        /* transmit from ingress port */
        direct_forward  = true;
        ig_intr_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
    }

    table handle_arp_table {
        key = {
            hdr.arp.isValid() : exact; 
            hdr.arp.opcode : exact;    
            hdr.arp.target_ipv4 : exact; 
        }
        actions = {
            handle_arp_request;
        }
        size = 1024;
    }   


    action drop() {
        ig_intr_dprsr_md.drop_ctl = 0x1;
    }

    action action_port_fwd(PortId_t port, mac_addr_t dst_mac) {
        ig_intr_tm_md.ucast_egress_port = port;
        hdr.ethernet.dst_addr = dst_mac;
    }

    table ipv4_fwd_table {
        key = {
            ig_md.dst_ipv4: lpm;
        }
        actions = {
            drop;
            action_port_fwd;
        }
        size = 256;
        default_action = drop;
    }
   


    bit<16> packet_seq         = 16w0;  // 保存“当前报文属于哪个探测序列（T1~T7）”。初始化为 0，后面根据 TCP flag/window 等条件会设置为 1、2、3…
    bit<16> old_ipv4_len_delta = 16w0;
    bit<16> new_ipv4_len_delta = 16w0;  // 在处理 TCP option 时，需要 删掉旧选项 / 添加新选项，所以 IP 头里的 total_len 要调整，这两个变量就是差值缓存。
    bit<4> new_data_offset     = 4w0;
    bit<8> new_ttl             = 8w0;
    bit<16> new_wsize          = 16w0;  // TCP 窗口大小（hdr.tcp.window）的新值。在 T1~T7 规则里，经常会伪造/修改窗口大小来“指纹化”操作系统。
    bit<4>  ack_no_opcode      = 4w0;
    bit<4>  seq_no_opcode      = 4w0;   // 决定如何修改 TCP ACK/SEQ 序号。
    bit<32> new_seq_from_isn   = 32w0;
   
    action hdr_fp_setup(
        bit<8>  ipv4_ttl,          bit<8>  ipv4_serv_bits,  bit<3> ipv4_flags,
        bit<16> wsize,             bit<8>  tcp_flag_bits,
        bit<4>  m_new_data_offset, bit<16> m_new_ipv4_len_delta,
        bit<4>  m_ack_no_opcode,   bit<4>  m_seq_no_opcode, bit<1> should_reply,
        bit<32> m_seq_from_isn) {

        /* IPv4 */
        new_ttl                    = ipv4_ttl;
        new_ipv4_len_delta         = m_new_ipv4_len_delta;
        hdr.ipv4.diffserv          = ipv4_serv_bits;
        hdr.ipv4.df_bit            = ipv4_flags[1:1];
        ig_md.update_ipv4_checksum = true;

        /* TCP */
        new_wsize                 = wsize;
        new_data_offset           = m_new_data_offset;
        hdr.tcp.cwr               = tcp_flag_bits[7:7];
        hdr.tcp.ece               = tcp_flag_bits[6:6];
        hdr.tcp.urg               = tcp_flag_bits[5:5];
        hdr.tcp.ack               = tcp_flag_bits[4:4];
        hdr.tcp.psh               = tcp_flag_bits[3:3];
        hdr.tcp.rst               = tcp_flag_bits[2:2];
        hdr.tcp.syn               = tcp_flag_bits[1:1];
        hdr.tcp.fin               = tcp_flag_bits[0:0];
        ig_md.update_tcp_checksum = true;
        
        /* number opcode */
        ack_no_opcode = m_ack_no_opcode;
        seq_no_opcode = m_seq_no_opcode;

        do_reply = should_reply;
        new_seq_from_isn = m_seq_from_isn;
    }

    table handle_T1_7_table{
        key = {
            packet_seq : exact;         // 探测序列类型（T1/T2/…/T7/ECN）由前面逻辑判定
            hdr.ipv4.dst_addr: exact;     
        }
        actions = {
            hdr_fp_setup;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }



    action mark_packet_to_enter_confuse() { 
    }

    action mark_packet_to_bypass_confuse() {
        direct_forward = true;
    }

    // 根据目的 IP 地址决定某个包是否进入“confuse（混淆处理逻辑）”，还是直接绕过（bypass）。
    table filter_packet_enter_confuse_table {
        key = {
            ig_md.dst_ipv4 : exact;

        }
        actions = {
            mark_packet_to_enter_confuse;
            @defaultonly mark_packet_to_bypass_confuse;
        }
        size = 1024; //size = 4962;
        const default_action = mark_packet_to_bypass_confuse;
    } 


    /*
        这套宏 + 6 张槽位表的机制，就是一个可编排的 TCP 选项“拼装器”
        用 packet_seq（T1~T7/ECN）和目的前缀作为键，为每个槽位选择一个选项动作，
        流水线依序 apply 后，就得到你想要的 TCP Option 列表，配合其他字段改写，达到对外“操作系统或网络栈行为”的目的。
    */
    #define ACTION_FP_TCP_OPT_END(X) \
    action finger_Tcp_opt_end_##X##() { \
        hdr.end_##X##.setValid(); \
        hdr.end_##X##.kind = 00; \
    }

    #define ACTION_FP_TCP_OPT_NOP(X) \
    action finger_Tcp_opt_Nop_##X##() { \
        hdr.nop_##X##.setValid(); \
        hdr.nop_##X##.kind = 01; \
    }

    #define ACTION_FP_TCP_OPT_MSS(X)  \
    action finger_Tcp_opt_MSS_##X##(bit<16> mss) { \
        hdr.ss_##X##.setValid(); \
        hdr.ss_##X##.kind = 02; \
        hdr.ss_##X##.length = 04; \
        hdr.ss_##X##.mss = mss; \
    }

    #define ACTION_FP_TCP_OPT_WSIZE(X) \
    action finger_Tcp_opt_Wsize_##X##(bit<8> scale) { \
        hdr.s_##X##.setValid(); \
        hdr.s_##X##.kind = 03; \
        hdr.s_##X##.length = 03; \
        hdr.s_##X##.scale = scale; \
    }

    #define ACTION_FP_TCP_OPT_SOK(X) \
    action finger_Tcp_opt_SOK_##X##() { \
        hdr.sp_##X##.setValid(); \
        hdr.sp_##X##.kind = 04; \
        hdr.sp_##X##.length = 02; \
    }

    #define ACTION_FP_TCP_OPT_TS(X) \
    action finger_Tcp_opt_TS_##X##() { \
        hdr.ts_##X##.setValid(); \
        hdr.ts_##X##.kind  = 0x08; \
        hdr.ts_##X##.length = 0x0a; \
        hdr.ts_##X##.tsval = 232561103; \
        hdr.ts_##X##.tsecr = 0; \
    }

    #define ACTION_FP_TCP_OPT_DEL(X) \
    action finger_Tcp_opt_DEL_##X##() { \
        hdr.s_##X##.setValid(); \
        hdr.s_##X##.setInvalid(); \
    }	

    #define DEF_TABLE_FP_OB_TCP(X) \
    ACTION_FP_TCP_OPT_END(X) \
    ACTION_FP_TCP_OPT_NOP(X) \
    ACTION_FP_TCP_OPT_MSS(X) \
    ACTION_FP_TCP_OPT_SOK(X) \
    ACTION_FP_TCP_OPT_TS(X) \
    ACTION_FP_TCP_OPT_WSIZE(X) \
    table finger_ob_tcp_table_##X## { \
        key = { \
            packet_seq : exact; \
            ig_md.dst_ipv4: exact; \
        } \
        actions = { \
            finger_Tcp_opt_end_##X##; \
            finger_Tcp_opt_Nop_##X##; \
            finger_Tcp_opt_MSS_##X##; \
            finger_Tcp_opt_SOK_##X##; \
            finger_Tcp_opt_TS_##X##; \
            finger_Tcp_opt_Wsize_##X##; \
            NoAction; \
        } \
        size = 1024; \   
        default_action = NoAction(); \
    }
    //size = 64506;

    #define APP_TABLE_FP_OB_TCP(X) finger_ob_tcp_table_##X##.apply();

    DEF_TABLE_FP_OB_TCP(0)
    DEF_TABLE_FP_OB_TCP(1)
    DEF_TABLE_FP_OB_TCP(2)
    DEF_TABLE_FP_OB_TCP(3)
    DEF_TABLE_FP_OB_TCP(4)
    DEF_TABLE_FP_OB_TCP(5)
    DEF_TABLE_FP_OB_TCP(6)
    DEF_TABLE_FP_OB_TCP(7)
    DEF_TABLE_FP_OB_TCP(8)
    DEF_TABLE_FP_OB_TCP(9)

    action set_packet_seq(bit<16> seq ) {
        packet_seq = seq;
    }
    table filter_P1_6_table{
        key = {
            ig_md.scale    : exact;
            ig_md.mss      : exact;
            // ig_md.tsval    : exact;
            // ig_md.tsecr    : exact;
            ig_md.has_ts   : exact;
            hdr.tcp.window : exact;
            ig_md.dst_ipv4 : exact;
        }
        actions = {
            set_packet_seq;
            @defaultonly NoAction;
        }
        size = 1024;
        const default_action = NoAction;
    }

    /*
        命中规则就原地生成 Echo Reply 回给对端，或直接丢弃。
    */
    action generate_icmp_reply(bit<8> ttl) {
        do_swap_ethernet = true;
        do_swap_ipv4     = true;

        hdr.ipv4.diffserv = 0;
        hdr.ipv4.ttl = ttl;
        hdr.icmp.code = 0;
        hdr.icmp.icmp_type = 0;

        hdr.icmp.hdr_checksum = 0;

        ig_md.update_ipv4_checksum = true;
        ig_md.update_icmp_checksum = true;

        ig_intr_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
    }
    action ignore_icmp_request() {
        ig_intr_dprsr_md.drop_ctl = 0x1;
    }
    table handle_icmp_table {
        key = {
            hdr.ipv4.diffserv[5:0]: exact; 
            hdr.icmp.code: exact; 
            hdr.icmp_data.seq: exact; 
            ig_md.dst_ipv4: lpm;
        }
        actions = {
            generate_icmp_reply;
            ignore_icmp_request;
            @defaultonly NoAction;
        }
        size = 128;
        default_action = NoAction();
    }


    action mark_to_recirc() {
        hdr.deol.setValid();
        hdr.deol.kind = 8w0xff;
        ig_intr_tm_md.ucast_egress_port = recirc_port;
        hdr.ipv4.protocol = IP_PROTOCOLS_RECIRC_TCP;
        // resubmit_add.execute(0);
    }
    table recirc_determining_table {
        key = {
            hdr.tcp.data_offset : exact;
        }
        actions = {
            mark_to_recirc;
            @defaultonly NoAction;
        }
        size = 11;
        const default_action = NoAction;
        // 并且 TCP data_offset 在 6~15 之间 → 调用 mark_to_recirc，把报文送去重循环。
        const entries = {
            {4w6}  : mark_to_recirc;
            {4w7}  : mark_to_recirc;
            {4w8}  : mark_to_recirc;
            {4w9}  : mark_to_recirc;
            {4w10} : mark_to_recirc;
            {4w11} : mark_to_recirc;
            {4w12} : mark_to_recirc;
            {4w13} : mark_to_recirc;
            {4w14} : mark_to_recirc;
            {4w15} : mark_to_recirc;
        }
    }


    action preprocess_ipv4_tcp_length(bit<16> old_len_delta) {
        old_ipv4_len_delta = old_len_delta;
    }
    table preprocess_ipv4_tcp_length_table {
        key = {
            hdr.tcp.data_offset  : exact;
        }
        actions = {
            preprocess_ipv4_tcp_length;
            @defaultonly NoAction;
        }
        const default_action = NoAction;
        size = 256;
    }

    /*
        “TCP 序列号改写模块”。
        它把前面 hdr_fp_setup 填好的 操作码 seq_no_opcode 转换成实际的 新序列号 new_seq_no，供后续逻辑写入 hdr.tcp.seq_no。
    */
    // Random<bit<32>>() rand_seq;
    bit<32> new_seq_no = 0;
    action seq_eq_ack() {new_seq_no = hdr.tcp.ack_no;}
    action seq_set_zero() {new_seq_no = 0;}
    action seq_set_other() {
        new_seq_no =  new_seq_from_isn;
        // new_seq_no = rand_seq.get();
    }
    table process_seq_no {
        key = {
            seq_no_opcode: exact;
        }
        actions = {
            @defaultonly NoAction;
            seq_eq_ack;
            seq_set_zero;
            seq_set_other;
        }
        size = 32;
        const default_action = NoAction;
        const entries = {
            {4w1} : seq_eq_ack;
            {4w2} : seq_set_zero;
            {4w3} : seq_set_other;
        }
    }

    /*
        针对 TCP 确认号（ack number） 的改写逻辑。
    */
    bit<32> new_ack_no = 0;
    action ack_eq_seq_plus_one() {new_ack_no = hdr.tcp.seq_no + 1;}
    action ack_eq_seq() {new_ack_no = hdr.tcp.seq_no;}
    action ack_set_zero() {new_ack_no = 0;}
    action ack_set_other() {new_ack_no = hdr.tcp.seq_no + 9;}
    table process_ack_no {
        key = {
            ack_no_opcode: exact;
        }
        actions = {
            @defaultonly NoAction;
            ack_eq_seq_plus_one;
            ack_eq_seq;
            ack_set_zero;
            ack_set_other;
        }
        size = 32;
        const default_action = NoAction;
        const entries = {
            {4w1} : ack_eq_seq_plus_one;
            {4w2} : ack_eq_seq;
            {4w3} : ack_set_zero;
            {4w4} : ack_set_other;
        }
    }

    action drop_all_old_option() {
        hdr.option_24B.setInvalid();
        hdr.option_20B.setInvalid();
        hdr.option_16B.setInvalid();
        hdr.option_12B.setInvalid();
        hdr.option_8B.setInvalid();
        hdr.option_4B.setInvalid();
    }

    action swap_ethernet() {
        mac_addr_t temp_mac_addr = hdr.ethernet.src_addr;
        hdr.ethernet.src_addr    = hdr.ethernet.dst_addr;
        hdr.ethernet.dst_addr    = temp_mac_addr;
    }   
    table swap_ethernet_table {
        key = {
            do_swap_ethernet:exact;
        }
        actions = {
            swap_ethernet;
            @defaultonly NoAction;
        }
        size = 1;
        const default_action = NoAction;
        const entries = {
            {true} : swap_ethernet;
        }
    }

    action swap_ipv4() {
        ipv4_addr_t temp_ipv4_addr = hdr.ipv4.src_addr;
        hdr.ipv4.src_addr          = hdr.ipv4.dst_addr;
        hdr.ipv4.dst_addr          = temp_ipv4_addr;
    }   
    table swap_ipv4_table {
        key = {
            do_swap_ipv4:exact;
        }
        actions = {
            swap_ipv4;
            @defaultonly NoAction;
        }
        size = 1;
        const default_action = NoAction;
        const entries = {
            {true} : swap_ipv4;
        }
    }

    action swap_udp() {
        bit<16> temp_port = hdr.udp.src_port;
        hdr.udp.src_port  = hdr.udp.dst_port;
        hdr.udp.dst_port  = temp_port;
    }   
    table swap_udp_table {
        key = {
            do_swap_udp:exact;
        }
        actions = {
            swap_udp;
            @defaultonly NoAction;
        }
        size = 1;
        const default_action = NoAction;
        const entries = {
            {true} : swap_udp;
        }
    }

    action swap_tcp() {
        bit<16> temp_port = hdr.tcp.src_port;
        hdr.tcp.src_port  = hdr.tcp.dst_port;
        hdr.tcp.dst_port  = temp_port;
    }   
    table swap_tcp_table {
        key = {
            do_swap_tcp:exact;
        }
        actions = {
            swap_tcp;
            @defaultonly NoAction;
        }
        size = 1;
        const default_action = NoAction;
        const entries = {
            {true} : swap_tcp;
        }
    }




    apply{
        // 从发送端口发来的数据包
        if(ig_intr_md.ingress_port == send_port){
            // 如果不是arp请求，判断是否是目的IP,设置出端口
            if(!handle_arp_table.apply().hit) {
                ipv4_fwd_table.apply();
                filter_packet_enter_confuse_table.apply();
            }
            if(!direct_forward){
                // confuse_pkts_add.execute(0);

                if(hdr.tcp.isValid()){
                    // tcp_pkts_add.execute(0);
                    recirc_determining_table.apply();
                }
                // 处理 ICMP Echo Request（即 ping 请求报文）
                else if(hdr.icmp.isValid() && hdr.icmp.icmp_type == 8 &&  hdr.icmp_data.isValid()){
                    // icmp_pkts_add.execute(0); 
                    if(handle_icmp_table.apply().hit) {
                        // icmp_hit_add.execute(0);
                    }
                }
                // 处理“特定 UDP 探针 → 伪造 ICMP 不可达回应”的逻辑
                else if(hdr.udp.isValid() && hdr.ipv4.identification == 0x1042){
                    // udp_pkts_add.execute(0);
                    do_swap_ethernet = true;
                    do_swap_ipv4 = true;
                    do_handle_icmp_unreachable = true;

                    hdr.icmp_ipv4.setValid();
                    hdr.icmp_ipv4 = hdr.ipv4;

                    hdr.icmp.setValid();
                    hdr.icmp.icmp_type = 3;
                    hdr.icmp.code = 3;
                    hdr.icmp.hdr_checksum = 0;

                    hdr.icmp_data.setValid();
                    hdr.icmp_data.id = 0;
                    hdr.icmp_data.seq = 0;

                    ig_intr_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
                }
                // 处理 ICMP Unreachable（目的不可达报文） 时，对 IPv4/ICMP 头部进行修改的动作
                if( do_handle_icmp_unreachable) {
                    hdr.icmp_ipv4.ttl = hdr.icmp_ipv4.ttl - 1;
                    hdr.ipv4.ttl = 127;
                    hdr.ipv4.total_len = hdr.ipv4.total_len + 28;
                    hdr.ipv4.identification = 0xabab;
                    hdr.ipv4.protocol = IP_PROTOCOLS_ICMP;
                    ig_md.update_icmp_ipv4_checksum = true;
                    ig_md.update_ipv4_checksum = true;
                    ig_md.update_icmp_checksum = true;
                }

            }
            else{
                // bypass_pkts_add.execute(0);
            }
        }
        // 从循环端口来的数据包
        else if(ig_intr_md.ingress_port == recirc_port){
            is_from_recirec_port = true;
            hdr.ipv4.protocol = IP_PROTOCOLS_TCP;

            if(hdr.tcp.isValid()){
                // resubmited_add.execute(0);
                // if(ig_md.parsed_mss) parsed_mss_add.execute(0);
                // if(ig_md.parsed_scale) parsed_scale_add.execute(0);
                // if(ig_md.parsed_ts) parsed_ts_add.execute(0);
                // if(ig_md.parsed_var_option) parsed_var_opt_add.execute(0);
                // T1
                if(filter_P1_6_table.apply().hit){
                    do_swap_ipv4     = true;
                    do_swap_tcp      = true;
                    do_swap_ethernet = true;
                    ig_md.update_tcp_checksum = true;
                }
                // ecn : SYN + CWR + ECE，保留位(res)置 1，URG 指针=0xF7F5，ACK=0，window=3
                else if (hdr.tcp.cwr == 1 && hdr.tcp.ece == 1 && hdr.tcp.syn == 1 && 
                    hdr.tcp.urgent_ptr == 16w0xf7f5 && hdr.tcp.window == 3)
                {
                    packet_seq = 1;
                    hdr.tcp.urgent_ptr = 0;
                    do_swap_ipv4     = true;
                    do_swap_tcp      = true;
                    do_swap_ethernet = true;
                    ig_md.update_tcp_checksum = true;
                }
                // T2：NULL（无任何TCP标志），DF=1，window=128，发往开放端口
                else if (hdr.tcp.res==0 && hdr.tcp.cwr == 0 && hdr.tcp.ece == 0 && 
                    hdr.tcp.urg == 0 && hdr.tcp.ack == 0 && hdr.tcp.psh == 0 && 
                    hdr.tcp.rst == 0 && hdr.tcp.syn == 0 && hdr.tcp.fin == 0 && 
                    hdr.tcp.window == 128 ) //&& hdr.ipv4.df_bit == 1
                {
                    packet_seq = 2;
                    do_swap_ipv4     = true;
                    do_swap_tcp      = true;
                    do_swap_ethernet = true;
                    ig_md.update_tcp_checksum = true;
                }
                // T3：SYN|FIN|URG|PSH，DF 未置位，ACK=0，window=256，发往开放端口
                else if (hdr.tcp.urg == 1 && hdr.tcp.psh == 1 && hdr.tcp.syn == 1 && 
                    hdr.tcp.fin == 1 && hdr.tcp.window == 256)
                {
                    packet_seq = 3;
                    do_swap_ipv4     = true;
                    do_swap_tcp      = true;
                    do_swap_ethernet = true;
                    ig_md.update_tcp_checksum = true;
                }
                // T4：ACK（仅 ACK 置位），DF=1，window=1024，发往开放端口
                else if (hdr.tcp.ack==1 && hdr.tcp.syn==0 && hdr.tcp.rst==0 
                    && hdr.tcp.window == 1024)
                {
                    packet_seq = 4;
                    do_swap_ipv4     = true;
                    do_swap_tcp      = true;
                    do_swap_ethernet = true;
                    ig_md.update_tcp_checksum = true;
                }
                // T5：SYN，DF 未置位（DF=0），window=31337，发往关闭端口
                else if (hdr.tcp.syn == 1  && hdr.tcp.window == 31337)
                {
                    packet_seq = 5;
                    do_swap_ipv4     = true;
                    do_swap_tcp      = true;
                    do_swap_ethernet = true;
                    ig_md.update_tcp_checksum = true;
                }
                // T6：ACK，DF=1，window=32768，发往关闭端口
                else if (hdr.tcp.syn == 0 && hdr.tcp.ack == 1 && hdr.tcp.window == 32768
                    && hdr.ipv4.df_bit == 1)
                {
                    packet_seq = 6;
                    do_swap_ipv4     = true;
                    do_swap_tcp      = true;
                    do_swap_ethernet = true;
                    ig_md.update_tcp_checksum = true;
                }
                // T7：FIN|PSH|URG，DF 未置位（DF=0），ACK=0、SYN=0、RST=0，window=65535，发往关闭端口
                else if (hdr.tcp.fin == 1 && hdr.tcp.psh == 1 && hdr.tcp.urg == 1
                    && hdr.tcp.window == 65535 && hdr.ipv4.df_bit == 0)
                {
                    packet_seq = 7;
                    do_swap_ipv4     = true;
                    do_swap_tcp      = true;
                    do_swap_ethernet = true;
                    ig_md.update_tcp_checksum = true;
                }

                // ecn_1_to_7_add.execute((bit<32>) packet_seq);

                if(packet_seq == 0){
                    ig_intr_tm_md.ucast_egress_port = receive_port;
                }else{
                    preprocess_ipv4_tcp_length_table.apply();
                    ig_intr_tm_md.ucast_egress_port = send_port;
                }

                if(handle_T1_7_table.apply().hit) {    
                    if(do_reply == 1w0){
                        ig_intr_dprsr_md.drop_ctl = 0x1;
                    }               
                    process_ack_no.apply(); 
                    process_seq_no.apply(); 
                    hdr.tcp.ack_no = new_ack_no;
                    hdr.tcp.seq_no = new_seq_no;
                    hdr.ipv4.ttl = new_ttl;

                    drop_all_old_option();
                    hdr.tcp.data_offset = new_data_offset;
                    hdr.ipv4.total_len = hdr.ipv4.total_len - old_ipv4_len_delta;
                    hdr.ipv4.total_len = hdr.ipv4.total_len + new_ipv4_len_delta;

                    APP_TABLE_FP_OB_TCP(0)
                    APP_TABLE_FP_OB_TCP(1)
                    APP_TABLE_FP_OB_TCP(2)
                    APP_TABLE_FP_OB_TCP(3)
                    APP_TABLE_FP_OB_TCP(4)
                    APP_TABLE_FP_OB_TCP(5)
                    APP_TABLE_FP_OB_TCP(6)
                    APP_TABLE_FP_OB_TCP(7)
                    APP_TABLE_FP_OB_TCP(8)
                    APP_TABLE_FP_OB_TCP(9)

                    hdr.tcp.window = new_wsize;
                }

            }

        }
        // 从目的端口发来的数据包
        else if(ig_intr_md.ingress_port == receive_port){
            ig_intr_tm_md.ucast_egress_port = send_port;
            // return_pkts_add.execute(0);
        }

        if( hdr.ethernet.isValid() ) swap_ethernet_table.apply();
        if( hdr.ipv4.isValid()     ) swap_ipv4_table.apply();
        if( hdr.udp.isValid()      ) swap_udp_table.apply();
        if( hdr.tcp.isValid()      ) swap_tcp_table.apply();

        ig_intr_tm_md.bypass_egress = 1w1;
    }
}



Pipeline(
    SwitchIngressParser(),
    SwitchIngress(),
    SwitchIngressDeparser(),
    EmptyEgressParser(),
    EmptyEgress(),
    EmptyEgressDeparser()
) pipe;

Switch(pipe) main;







