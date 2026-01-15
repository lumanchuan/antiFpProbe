
#ifndef _HEADERS_
#define _HEADERS_

typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<128> ipv6_addr_t;
typedef bit<12> vlan_id_t;

typedef bit<16> ether_type_t;
const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;
const ether_type_t ETHERTYPE_ARP = 16w0x0806;
const ether_type_t ETHERTYPE_IPV6 = 16w0x86dd;
const ether_type_t ETHERTYPE_VLAN = 16w0x8100;

typedef bit<8> ip_protocol_t;
const ip_protocol_t IP_PROTOCOLS_ICMP = 1;
const ip_protocol_t IP_PROTOCOLS_TCP = 6;
const ip_protocol_t IP_PROTOCOLS_UDP = 17;
const ip_protocol_t IP_PROTOCOLS_RECIRC_TCP = 8w0xff;

header ethernet_h {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16> ether_type;
}

header vlan_tag_h {
    bit<3> pcp;
    bit<1> cfi;
    vlan_id_t vid;
    bit<16> ether_type;
}

header mpls_h {
    bit<20> label;
    bit<3> exp;
    bit<1> bos;
    bit<8> ttl;
}

header ipv4_h {
    bit<4> version;
    bit<4> ihl;

    #if ENB_XPROBE
    bit<3> precedence_bits;
    bit<5> tos_bits;
    #else
    bit<8> diffserv;
    #endif

    bit<16> total_len;
    bit<16> identification;

    #if ENB_XPROBE || ENB_NMAP
    bit<1> res_bit;
    bit<1> df_bit;
    bit<1> mf_bit;
    #else
    bit<1> res_bit;
    bit<1> df_bit;
    bit<1> mf_bit;
    #endif

    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
}

header ipv6_h {
    bit<4> version;
    bit<8> traffic_class;
    bit<20> flow_label;
    bit<16> payload_len;
    bit<8> next_hdr;
    bit<8> hop_limit;
    ipv6_addr_t src_addr;
    ipv6_addr_t dst_addr;
}

header tcp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;

    #if ENB_NMAP || ENB_XPROBE
    bit<4>  data_offset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;

    #elif ENB_P0F
    bit<8> data_offset;
    bit<8> flags;
    
    #endif

    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> hdr_length;
    bit<16> checksum;
}

header icmp_h {
    bit<8> icmp_type;
    bit<8> code;
    bit<16> hdr_checksum;
}

header icmp_data_h {
    bit<16> id;
    bit<16> seq;
}

// Address Resolution Protocol -- RFC 6747
header arp_h {
    bit<16> hw_type;
    bit<16> proto_type;
    bit<8> hw_addr_len;
    bit<8> proto_addr_len;
    bit<16> opcode;
    mac_addr_t sender_mac;
    ipv4_addr_t sender_ipv4;
    mac_addr_t target_mac;
    ipv4_addr_t target_ipv4;
}

// Segment Routing Extension (SRH) -- IETFv7
header ipv6_srh_h {
    bit<8> next_hdr;
    bit<8> hdr_ext_len;
    bit<8> routing_type;
    bit<8> seg_left;
    bit<8> last_entry;
    bit<8> flags;
    bit<16> tag;
}

// VXLAN -- RFC 7348
header vxlan_h {
    bit<8> flags;
    bit<24> reserved;
    bit<24> vni;
    bit<8> reserved2;
}

// Generic Routing Encapsulation (GRE) -- RFC 1701
header gre_h {
    bit<1> C;
    bit<1> R;
    bit<1> K;
    bit<1> S;
    bit<1> s;
    bit<3> recurse;
    bit<5> flags;
    bit<3> version;
    bit<16> proto;
}

struct ipv4_option_h {
    varbit<320> val;
}

struct header_t {
    ethernet_h ethernet;
    vlan_tag_h vlan_tag;
    ipv4_h ipv4;
    ipv6_h ipv6;
    tcp_h tcp;
    udp_h udp;

    // Add more headers here.
}

struct empty_header_t {}

struct empty_metadata_t {}

/* customized header and meta */
typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

/* 8b */
header tcp_option_end_h {
    bit<8> kind;
}

/* 8b */
header tcp_option_nop_h {
    bit<8> kind;
}

/* 32b */
header tcp_option_ss_h {
    bit<8> kind;
    bit<8> length;
    bit<16> mss;
}

/* 24b */
header tcp_option_s_h {
    bit<8> kind;
    bit<8> length;
    bit<8> scale;
}

/* 16b */
header tcp_option_sack_permitted_h {
    bit<8> kind;
    bit<8> length;
}

/* 80b */
header tcp_option_ts_h {
    bit<8> kind;
    bit<8> length;
    bit<32> tsval;
    bit<32> tsecr;
}

/* 80b */
header option_sack_h_1 {
    bit<8> kind;
    bit<8> length;
    bit<64> sack;
}

/* 144b */
header option_sack_h_2 {
    bit<8> kind;
    bit<8> length;
    bit<128> sack;
}

/* 208b */
header option_sack_h_3 {
    bit<8> kind;
    bit<8> length;
    bit<192> sack;
}

/* 272b */
header option_sack_h_4 {
    bit<8> kind;
    bit<8> length;
    bit<256> sack;
}

#define DEF_FIELD_OPTION(X) \
    tcp_option_end_h            end_##X##; \
    tcp_option_nop_h            nop_##X##; \
    tcp_option_ss_h             ss_##X##; \
    tcp_option_s_h              s_##X##; \
    tcp_option_sack_permitted_h sp_##X##; \
    tcp_option_ts_h             ts_##X##; \

/* mirror */
typedef bit<8>  pkt_type_t;
const pkt_type_t PKT_TYPE_NORMAL = 1;
const pkt_type_t PKT_TYPE_MIRROR = 2;

#if __TARGET_TOFINO__ == 1
typedef bit<3> mirror_type_t;
#else
typedef bit<4> mirror_type_t;
#endif

const mirror_type_t MIRROR_TYPE_I2E = 1;
const mirror_type_t MIRROR_TYPE_E2E = 2;
const MirrorId_t ing_ses = 1;
const MirrorId_t egr_ses = 2;

@flexible
header mirror_bridged_metadata_h {
    pkt_type_t pkt_type;
    bool do_egr_mirroring;  //  Enable egress mirroring
    MirrorId_t egr_mir_ses;   // Egress mirror session ID
}

header mirror_h{
    pkt_type_t pkt_type;
}

header option_h {
    varbit<320> content;
}

header option_40B_h {
    bit<320> content;
}

header option_36B_h {
    bit<288> content;
}

header option_32B_h {
    bit<256> content;
}

header option_28B_h {
    bit<224> content;
}

header option_24B_h {
    bit<192> content;
}

header option_20B_h {
    bit<160> content;
}

header option_16B_h {
    bit<128> content;
}

header option_12B_h {
    bit<96> content;
}

header option_8B_h {
    bit<64> content;
}

header option_4B_h {
    bit<32> content;
}

header option_dummy_end_h {
    bit<8> kind;
}

#define DF_OPTION_PREFIX(X,LEN) option_##LEN##B_h X##option_##LEN##B

#define DF_OPTION(LEN) option_##LEN##B_h option_##LEN##B

struct headers_t {
    mirror_bridged_metadata_h bridged_md;

    ethernet_h  ethernet;
    arp_h       arp;
    ipv4_h      ipv4;
    icmp_h      icmp;
    icmp_data_h icmp_data;
    ipv4_h      icmp_ipv4;
    udp_h       udp;
    tcp_h       tcp;

    #if ENB_XPROBE
    option_h option;
    DF_OPTION(40);
    DF_OPTION(36);
    DF_OPTION(32);
    DF_OPTION(28);
    DF_OPTION(24);
    DF_OPTION(20);
    DF_OPTION(16);
    DF_OPTION(12);
    DF_OPTION(8);
    DF_OPTION(4);
    #endif
    
    #if ENB_NMAP
    // DF_OPTION_PREFIX(,40);
    // DF_OPTION_PREFIX(,36);
    // DF_OPTION_PREFIX(,32);
    // option_28B_h option_28B
    DF_OPTION_PREFIX(,28);
    DF_OPTION_PREFIX(,24);
    DF_OPTION_PREFIX(,20);
    DF_OPTION_PREFIX(,16);
    DF_OPTION_PREFIX(,12);
    DF_OPTION_PREFIX(,8);
    DF_OPTION_PREFIX(,4);

    // DF_OPTION_PREFIX(dummy_,40);
    // DF_OPTION_PREFIX(dummy_,36);
    // DF_OPTION_PREFIX(dummy_,32);
    // option_28B_h dummy_option_28B
    DF_OPTION_PREFIX(dummy_,28);
    DF_OPTION_PREFIX(dummy_,24);
    DF_OPTION_PREFIX(dummy_,20);
    DF_OPTION_PREFIX(dummy_,16);
    DF_OPTION_PREFIX(dummy_,12);
    DF_OPTION_PREFIX(dummy_,8);
    DF_OPTION_PREFIX(dummy_,4);

    tcp_option_end_h deol;

    /* inserted option */
    // 
    DEF_FIELD_OPTION(0)
    DEF_FIELD_OPTION(1)
    DEF_FIELD_OPTION(2)
    DEF_FIELD_OPTION(3)
    DEF_FIELD_OPTION(4)
    DEF_FIELD_OPTION(5)
    DEF_FIELD_OPTION(6)
    DEF_FIELD_OPTION(7)
    DEF_FIELD_OPTION(8)
    DEF_FIELD_OPTION(9)
    #endif

    #if ENB_P0F
    option_h option;

    /* inserted option */
    DEF_FIELD_OPTION(0)
    DEF_FIELD_OPTION(1)
    DEF_FIELD_OPTION(2)
    DEF_FIELD_OPTION(3)
    DEF_FIELD_OPTION(4)
    DEF_FIELD_OPTION(5)
    DEF_FIELD_OPTION(6)
    DEF_FIELD_OPTION(7)
    DEF_FIELD_OPTION(8)
    DEF_FIELD_OPTION(9)
    #endif
}

struct metadata_t {
    #if ENB_TOPO
    bit<16> tcp_checksum_temp;
    bit<16> udp_checksum_temp;
    #endif    
    
    #if ENB_NMAP
    bit<1> has_ts;
    bit<16> mss;
    bit<8> scale; 
    bit<32> tsval;
    bit<32> tsecr;

    bool parsed_mss;
    bool parsed_scale;
    bool parsed_ts;
    bool parsed_var_option;

    bit<16> icmp_checksum_temp;
    #endif

    bit<1> do_ing_mirroring;  // Enable ingress mirroring
    bit<1> do_egr_mirroring;  // Enable egress mirroring
    MirrorId_t ing_mir_ses;   // Ingress mirror session ID
    MirrorId_t egr_mir_ses;   // Egress mirror session ID
    pkt_type_t pkt_type;
    ipv4_addr_t dst_ipv4;

    bool update_ipv4_checksum;
    bool update_tcp_checksum;
    bool update_udp_checksum;
    bool update_icmp_checksum;
    bool update_icmp_ipv4_checksum;
}

#endif
