#include <core.p4>
#include <tna.p4>
struct empty_header_t {}
struct empty_metadata_t {}
#include "../../common/util.p4"

header ethernet_t { bit<48> dst; bit<48> src; bit<16> type; }
header ipv4_t {
    bit<4> version; bit<4> ihl; bit<8> tos; bit<16> length;
    bit<16> id; bit<3> flags; bit<13> offset; bit<8> ttl;
    bit<8> protocol; bit<16> checksum; bit<32> src; bit<32> dst;
}
header tcp_t {
    bit<16> sport; bit<16> dport; bit<32> seq; bit<32> ack;
    bit<4> offset; bit<4> reserved; bit<8> flags; bit<16> window;
    bit<16> checksum; bit<16> urgent;
}
header udp_t { bit<16> sport; bit<16> dport; bit<16> length; bit<16> checksum; }
header icmp_t { bit<8> type; bit<8> code; bit<16> checksum; bit<16> id; bit<16> seq; }
struct headers_t { ethernet_t ethernet; ipv4_t ipv4; tcp_t tcp; udp_t udp; icmp_t icmp; }
struct metadata_t { bit<1> monitor; bit<8> category; bit<16> sport; bit<16> dport; bit<32> sequence; }
struct probe_digest_t {
    bit<32> source; bit<32> destination; bit<16> sport; bit<16> dport;
    bit<32> sequence; bit<16> ip_id; bit<8> category;
}

parser SwitchIngressParser(packet_in pkt, out headers_t hdr, out metadata_t md,
                           out ingress_intrinsic_metadata_t intrinsic) {
    TofinoIngressParser() base;
    state start {
        base.apply(pkt, intrinsic);
        md.monitor = 0; md.category = 0; md.sport = 0; md.dport = 0; md.sequence = 0;
        transition ethernet;
    }
    state ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.type) { 0x0800: ipv4; default: accept; }
    }
    state ipv4 {
        pkt.extract(hdr.ipv4);
        // Other protocols, IPv4 options and fragments pass unchanged, without classification.
        transition select(hdr.ipv4.ihl, hdr.ipv4.offset, hdr.ipv4.protocol) {
            (5, 0, 6): tcp; (5, 0, 17): udp; (5, 0, 1): icmp; default: accept;
        }
    }
    state tcp { pkt.extract(hdr.tcp); transition accept; }
    state udp { pkt.extract(hdr.udp); transition accept; }
    state icmp { pkt.extract(hdr.icmp); transition accept; }
}

control SwitchIngressDeparser(packet_out pkt, inout headers_t hdr, in metadata_t md,
                             in ingress_intrinsic_metadata_for_deparser_t deparser) {
    Digest<probe_digest_t>() probe_digest;
    apply {
        if (deparser.digest_type == 1) {
            probe_digest.pack({hdr.ipv4.src, hdr.ipv4.dst, md.sport, md.dport,
                               md.sequence, hdr.ipv4.id, md.category});
        }
        pkt.emit(hdr);
    }
}

control SwitchIngress(inout headers_t hdr, inout metadata_t md,
    in ingress_intrinsic_metadata_t intrinsic,
    in ingress_intrinsic_metadata_from_parser_t parser_md,
    inout ingress_intrinsic_metadata_for_deparser_t deparser,
    inout ingress_intrinsic_metadata_for_tm_t tm) {

    Counter<bit<64>, bit<8>>(16, CounterType_t.PACKETS) probe_counts;
    action watch() { md.monitor = 1; }
    table protected_host {
        key = { intrinsic.ingress_port: exact; hdr.ipv4.dst: exact; }
        actions = { watch; NoAction; }
        size = 1;
        const default_action = NoAction();
        const entries = { (60, 0xc0a80302): watch(); }
    }
    action classify(bit<8> category) { md.category = category; }
    table tcp_signature {
        key = { hdr.tcp.flags: exact; hdr.tcp.window: exact; }
        actions = { classify; NoAction; }
        size = 32;
        const default_action = NoAction();
        const entries = {
            (0x02, 1): classify(1); (0x02, 63): classify(1);
            (0x02, 4): classify(1); (0x02, 16): classify(1);
            (0x02, 512): classify(1); (0xc2, 3): classify(2);
            (0x00, 128): classify(3); (0x2b, 256): classify(4);
            (0x10, 1024): classify(5); (0x02, 31337): classify(6);
            (0x10, 32768): classify(7); (0x29, 65535): classify(8);
        }
    }
    apply {
        deparser.digest_type = 0;
        // Keep the verified dev_port forwarding relation; never forward unrelated ingress.
        if (intrinsic.ingress_port == 52) { tm.ucast_egress_port = 60; }
        else if (intrinsic.ingress_port == 60) { tm.ucast_egress_port = 52; }
        else { deparser.drop_ctl = 1; }
        tm.bypass_egress = 1;

        if (hdr.ipv4.isValid()) { protected_host.apply(); }
        if (md.monitor == 1 && hdr.ipv4.flags[0:0] == 0) {
            if (hdr.tcp.isValid() && hdr.tcp.offset > 5) {
                tcp_signature.apply();
                md.sport = hdr.tcp.sport; md.dport = hdr.tcp.dport; md.sequence = hdr.tcp.seq;
                if (md.category == 2 && hdr.tcp.urgent != 0xf7f5) { md.category = 0; }
            } else if (hdr.icmp.isValid() && hdr.icmp.type == 8) {
                if (hdr.icmp.code == 9 && hdr.icmp.seq == 295 && hdr.ipv4.length == 148) { md.category = 9; }
                else if (hdr.icmp.code == 0 && hdr.icmp.seq == 296 && hdr.ipv4.length == 178) { md.category = 10; }
                md.sequence = (bit<32>)hdr.icmp.seq;
            } else if (hdr.udp.isValid() && hdr.ipv4.id == 0x1042 && hdr.udp.length == 308) {
                md.category = 11; md.sport = hdr.udp.sport; md.dport = hdr.udp.dport;
            }
            if (md.category != 0) {
                probe_counts.count(md.category);
                deparser.digest_type = 1;
            }
        }
    }
}
Pipeline(SwitchIngressParser(), SwitchIngress(), SwitchIngressDeparser(),
         EmptyEgressParser(), EmptyEgress(), EmptyEgressDeparser()) pipe;
Switch(pipe) main;
