#ifndef MAIN_H
#define MAIN_H
#include <arpa/inet.h>
#include "util.h"

struct sflow_hdr_t {
    u32 version;
    u32 agent_addr_type;
    u32 agent_addr;
    u32 sub_agent_id;
    u32 seq_num;
    u32 sys_uptime;
    u32 sample_num;
}__attribute__((packed));

struct sflow_sample_hdr_t {
    u32 sample_type;
    u32 sample_len;
    u32 seq_num;
    u32 idx;
    u32 sample_rate;
    u32 sample_pool;
    u32 dropped_pkt;
    u32 input_intf;
    u32 output_intf;
    u32 flow_record;
}__attribute__((packed));;

struct raw_pkt_hdr_t { 
    u32 format;
    u32 flow_data_len;
    u32 hdr_protocol;
    u32 frame_len;
    u32 payload_removed;
    u32 ori_pkt_len;
}__attribute__((packed));;

struct arp_hdr_t {
    u16 hd_type;
    u16 prot_type;
    u8 hd_size;
    u8 prot_size;
    u16 op_code;
    u8 smac[6];
    u32 sip;
    u8 dmac[6];
    u32 dip;
} __attribute__((packed));;

struct ipv4_hdr_t {
    u8 hdr_len: 4,
       version: 4;
    u8  dsf;
    u16 total_len;
    u16 id;
    u16 flag;
    u8  ttl;
    u8  protocol;
    u16 hdr_chksum;
    u32 src_ip;
    u32 dst_ip;
}__attribute__((packed));;

struct icmpv4_hdr_t {
    u8  type;
    u8  code;
    u16 chksum;
    u16 id;
    u16 seq_num;
}__attribute__((packed));;

struct udp_hdr_t {
    u16 sport;
    u16 dport;
    u16 len;
    u16 chksum;
}__attribute__((packed));;

struct tcp_hdr_t {
    u16 sport;
    u16 dport;
    u32 seq_num;
    u32 ack_num;
    u8 reserve :4,
       offset  :4;
    u8 flag;
    u16 window;
    u16 chksum;
    u16 ugr_ptr;
};

#define ETH_LEN 14
#define IPV4_HDR_LEN sizeof(struct ipv4_hdr_t)
#define ICMPV4_HDR_LEN sizeof(struct icmpv4_hdr_t)
#define UDP_HDR_LEN sizeof(struct udp_hdr_t)
#define TCP_HDR_LEN sizeof(struct tcp_hdr_t)

static inline int make_ipv4(struct ipv4_hdr_t* ipv4_hdr, int sampled_pkt_payload_len, u8 type, u32 src_ip, u32 dst_ip) {

    ipv4_hdr->version = 0x4;
    ipv4_hdr->hdr_len = 0x5;
    ipv4_hdr->dsf = 0;
    ipv4_hdr->total_len = htons(20+sampled_pkt_payload_len);
    ipv4_hdr->id = htons(23559);
    ipv4_hdr->flag = 0;
    ipv4_hdr->ttl = 124;
    if (type == 0x1) {
        ipv4_hdr->protocol = 1;
    } else if (type == 0x6) {
        ipv4_hdr->protocol = 0x6;
    } else if (type == 0x11) {
        ipv4_hdr->protocol = 0x11;
    }
    ipv4_hdr->hdr_chksum = htons(0x9487);
    ipv4_hdr->src_ip = htonl(src_ip);
    ipv4_hdr->dst_ip = dst_ip;

    return IPV4_HDR_LEN;
}

static inline int make_icmpv4(struct icmpv4_hdr_t* icmpv4_hdr) {

    icmpv4_hdr->type = 8;
    icmpv4_hdr->code = 0;
    icmpv4_hdr->chksum = htons(0x9487);
    icmpv4_hdr->id = htons(0xa948);
    icmpv4_hdr->seq_num = htons(0x0cb2);

    return ICMPV4_HDR_LEN;
}

static inline int make_tcp(struct tcp_hdr_t* tcp_hdr, u16 sport, u16 dport) {

    tcp_hdr->sport = htons(sport);
    tcp_hdr->dport = htons(dport);
    tcp_hdr->seq_num = htonl(0x9487);
    tcp_hdr->ack_num = 0;
    tcp_hdr->offset = 0x5;
    tcp_hdr->reserve = 0;
    tcp_hdr->flag = 0x2;        // SYN
    tcp_hdr->window = 0x9487;
    tcp_hdr->chksum = 0x9487;
    tcp_hdr->ugr_ptr = 0;

    return TCP_HDR_LEN;
}

static inline int make_udp(struct udp_hdr_t* udp_hdr, u16 sport, u16 dport) {

    udp_hdr->sport = htons(sport);
    udp_hdr->dport = htons(dport);
    udp_hdr->len = htons(8);
    udp_hdr->chksum = htons(0x9487);

    return UDP_HDR_LEN;
}


#endif
