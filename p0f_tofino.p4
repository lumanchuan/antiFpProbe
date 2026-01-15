/* -*- P4_16 -*- */
#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else 
#include <tna.p4>
#endif

#include "common/headers.p4"
#include "common/util.p4"

// #include "tcp_option_parser_w_hdr_union.p4"
// #include "tcp_option_parser_wo_hdr_union.p4"

// TCP control field values
const bit<6> SYN_FLAG = 1 << 1;
const bit<6> PSH_FLAG = 1 << 3;
const bit<6> URG_FLAG = 1 << 5;

parser SwitchIngressParser(
        packet_in pkt,
        out headers_t hdr,
        out metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    TofinoIngressParser() tofino_parser;

    state start {
        tofino_parser.apply(pkt, ig_intr_md);

        ig_md.update_ipv4_checksum = false;
        ig_md.update_tcp_checksum  = false;
        ig_md.update_udp_checksum  = false;
        
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_ARP: parse_arp;
            ETHERTYPE_IPV4: parse_ipv4;
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
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_TCP: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition select(hdr.tcp.data_offset[7:4]) {
            4w5: accept;
            default: parse_varbit_tcp_option;
        }
    }
    
    state parse_varbit_tcp_option{
        pkt.extract(hdr.option, (((bit<32>)hdr.tcp.data_offset[7:4] * 4) - 20) * 8);
        
        transition accept;
    }

    /*
        Maybe other size of original option
          Step 1: add parse_XXB_option state defination
          Step 2: insert it into selection in state parse_tcp_option
          Step 3: add corresponding header in header.h
    */
}

control SwitchIngressDeparser(
        packet_out pkt,
        inout headers_t hdr,
        in metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {

    Checksum() ipv4_checksum;

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

        pkt.emit(hdr);
    }
}

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

    mac_addr_t new_dst_mac_addr = 48w0;
    bool direct_forward = false;
    bit<16> old_ipv4_len_delta = 16w0;
    bit<16> new_ipv4_len_delta = 16w0;
    bit<8> new_data_offset = 8w0;
    bit<8> new_ttl = 8w0;
    bit<16> new_wsize = 16w0;
    bit<1> new_df = 1w0;
    


    action swap_sender_and_target(){
        mac_addr_t temp_mac_addr  = hdr.arp.sender_mac;
        ipv4_addr_t temp_ipv4_addr = hdr.arp.sender_ipv4;

        hdr.arp.sender_mac = hdr.arp.target_mac;
        hdr.arp.sender_ipv4  = hdr.arp.target_ipv4;

        hdr.arp.target_mac = temp_mac_addr;
        hdr.arp.target_ipv4  = temp_ipv4_addr;
    }
    action swap_ethernet() {
        mac_addr_t temp_mac_addr = hdr.ethernet.src_addr;
        hdr.ethernet.src_addr = hdr.ethernet.dst_addr;
        hdr.ethernet.dst_addr = temp_mac_addr;
    }   
    action handle_arp_request(mac_addr_t arp_proxy_mac) {
        // Send to ARP proxy
        hdr.arp.target_mac = arp_proxy_mac;
        hdr.ethernet.dst_addr = arp_proxy_mac;

        hdr.arp.opcode = 2;

        swap_sender_and_target();
        swap_ethernet();
        
        /* transmit from ingress port */
        direct_forward  = true;
        ig_intr_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
    }
    // ARP table
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
        new_dst_mac_addr = dst_mac;
    }
    table ipv4_fwd_table {
        key = {
            ig_md.dst_ipv4  : lpm;
        }
        actions = {
            drop;
            action_port_fwd;
        }
        size = 256;
        default_action = drop;
    }


    action set_new_dst_mac() {
        hdr.ethernet.dst_addr = new_dst_mac_addr;
    }
    action ignore_new_dst_mac() {}
    table setup_dst_mac_table {
        key = {
            new_dst_mac_addr: exact;
        }
        actions = {
            @defaultonly set_new_dst_mac;
            ignore_new_dst_mac;
        }
        size = 1;
        const default_action = set_new_dst_mac;
        const entries = {
            {48w0}:ignore_new_dst_mac;
        }
    }



    action finger_action_wsize(
        bit<8> ttl, bit<16> wsize, bit<8> m_new_data_offset, 
        bit<16> m_new_ipv4_len_delta, bit<1> df) {
        new_ttl = ttl;
        new_wsize = wsize;
        new_data_offset = m_new_data_offset;
        new_ipv4_len_delta = m_new_ipv4_len_delta;
        new_df = df;
    }
    table finger_ob_table {
        key = {
            hdr.ipv4.src_addr: exact;
        }
        actions = {
            finger_action_wsize;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }


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

    #define DEF_TABLE_FP_OB_TCP(X) \
    ACTION_FP_TCP_OPT_END(X) \
    ACTION_FP_TCP_OPT_NOP(X) \
    ACTION_FP_TCP_OPT_MSS(X) \
    ACTION_FP_TCP_OPT_SOK(X) \
    ACTION_FP_TCP_OPT_TS(X) \
    ACTION_FP_TCP_OPT_WSIZE(X) \
    table finger_ob_tcp_table_##X## { \
        key = { \
            hdr.ipv4.src_addr: exact; \
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



    action preprocess_ipv4_tcp_length(bit<16> len_delta) {
        old_ipv4_len_delta = len_delta;
    }
    table preprocess_ipv4_tcp_length_table {
        key = {
            hdr.option.isValid() : exact;
            hdr.tcp.data_offset  : exact;
        }
        actions = {
            preprocess_ipv4_tcp_length;
            @defaultonly NoAction;
        }
        const default_action = NoAction;
        size = 256;
    }




    
    apply {
        if(ig_intr_md.ingress_port == send_port){
            if(!handle_arp_table.apply().hit) {
                ipv4_fwd_table.apply();
                setup_dst_mac_table.apply();
            }

            if ( direct_forward == false && hdr.tcp.isValid() &&
                (hdr.tcp.flags[5:0] == SYN_FLAG
                || hdr.tcp.flags[5:0] == (SYN_FLAG | PSH_FLAG)
                || hdr.tcp.flags[5:0] == (SYN_FLAG | URG_FLAG)
                || hdr.tcp.flags[5:0] == (SYN_FLAG | PSH_FLAG | URG_FLAG))) {
            
            // if ( hdr.tcp.isValid() &&
            //     (hdr.tcp.flags[5:0] == SYN_FLAG
            //     || hdr.tcp.flags[5:0] == (SYN_FLAG | PSH_FLAG)
            //     || hdr.tcp.flags[5:0] == (SYN_FLAG | URG_FLAG)
            //     || hdr.tcp.flags[5:0] == (SYN_FLAG | PSH_FLAG | URG_FLAG))) {
                

                if(finger_ob_table.apply().hit) {
                    if(new_ttl > 0) hdr.ipv4.ttl = new_ttl;
                    if(new_wsize > 0) hdr.tcp.window = new_wsize;
                    if(new_df > 0) hdr.ipv4.df_bit = new_df;


                    /* Drop original option */
                    if(preprocess_ipv4_tcp_length_table.apply().hit) {
                        hdr.option.setInvalid();
                        hdr.tcp.data_offset = new_data_offset;
                        hdr.ipv4.total_len = hdr.ipv4.total_len - old_ipv4_len_delta;
                        hdr.ipv4.total_len = hdr.ipv4.total_len + new_ipv4_len_delta;
                    }
                
                    /* finger_ob_tcp_table_##X##.apply(); */
                    APP_TABLE_FP_OB_TCP(0);
                    APP_TABLE_FP_OB_TCP(1);
                    APP_TABLE_FP_OB_TCP(2);
                    APP_TABLE_FP_OB_TCP(3);
                    APP_TABLE_FP_OB_TCP(4);
                    APP_TABLE_FP_OB_TCP(5);
                    APP_TABLE_FP_OB_TCP(6);
                    APP_TABLE_FP_OB_TCP(7);
                    APP_TABLE_FP_OB_TCP(8);
                    APP_TABLE_FP_OB_TCP(9);

                    ig_md.update_ipv4_checksum = true;
                    ig_md.update_tcp_checksum  = true;
                }
            }

        }
        else if(ig_intr_md.ingress_port == receive_port){
            ig_intr_tm_md.ucast_egress_port = send_port;
        }

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
