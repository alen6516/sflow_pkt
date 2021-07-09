#ifndef MAIN_H
#define MAIN_H

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "../util.h"
#include "config.h"

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
}__attribute__((packed));

struct raw_pkt_hdr_t { 
    u32 format;
    u32 flow_data_len;
    u32 hdr_protocol;
    u32 frame_len;
    u32 payload_removed;
    u32 ori_pkt_len;
}__attribute__((packed));

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
} __attribute__((packed));

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
}__attribute__((packed));

struct ipv6_hdr_t {
    u8 priority: 4,
       version:  4;
    u8 flow_lbl[3];
    u16 payload_len;
    u8 nexthdr;
    u8 hop_limit;
    struct in6_addr saddr;
    struct in6_addr daddr;
};

struct icmpv4_hdr_t {
    u8  type;
    u8  code;
    u16 chksum;
    u16 id;
    u16 seq_num;
}__attribute__((packed));

struct icmpv6_hdr_t {
    u8  type;
    u8  code;
    u16 chksum;
    u16 id;
    u16 seq_num;
};

struct udp_hdr_t {
    u16 sport;
    u16 dport;
    u16 len;
    u16 chksum;
}__attribute__((packed));

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
}__attribute__((packed));

#define ICMP 0x1
#define ICMPv6 0x3a
#define TCP 0x6
#define UDP 0x11

#define ACK 0x10
#define SYN 0x02
#define FIN 0x01
#define RST 0x04

#define ETH_LEN         14
#define IPV4_HDR_LEN    sizeof(struct ipv4_hdr_t)
#define IPV6_HDR_LEN    sizeof(struct ipv6_hdr_t)
#define ICMPV4_HDR_LEN  sizeof(struct icmpv4_hdr_t)
#define ICMPV6_HDR_LEN  sizeof(struct icmpv6_hdr_t)
#define UDP_HDR_LEN     sizeof(struct udp_hdr_t)
#define TCP_HDR_LEN     sizeof(struct tcp_hdr_t)

static inline int
make_ipv4(struct ipv4_hdr_t* ipv4_hdr, int sampled_pkt_payload_len, u8 type, u32 src_ip, u32 dst_ip, u8 is_frag)
{
    ipv4_hdr->version = 0x4;
    ipv4_hdr->hdr_len = 0x5;
    ipv4_hdr->dsf = 0;
    ipv4_hdr->total_len = htons(IPV4_HDR_LEN + sampled_pkt_payload_len);
    ipv4_hdr->id = htons(23559);
    if (is_frag) {
        ipv4_hdr->flag = htons(0x2000);
    } else {
        ipv4_hdr->flag = 0;
    }
    ipv4_hdr->ttl = 124;
    switch (type) {
        case ICMP:
        case TCP:
        case UDP:
            ipv4_hdr->protocol = type;
            break;
        default:
            ipv4_hdr->protocol = type;
            // ASSERT_WARN
    }
    ipv4_hdr->hdr_chksum = htons(CHECKSUM);
    ipv4_hdr->src_ip = src_ip;
    ipv4_hdr->dst_ip = dst_ip;

    return IPV4_HDR_LEN;
}

static inline int
make_ipv6(struct ipv6_hdr_t *ipv6_hdr, int sampled_pkt_payload_len, u8 type, struct in6_addr saddr, struct in6_addr daddr, u8 is_frag)
{
    ipv6_hdr->version = 0x6;
    ipv6_hdr->payload_len = htons(sampled_pkt_payload_len);
    switch (type) {
        case ICMPv6:
        case TCP:
        case UDP:
            ipv6_hdr->nexthdr = type;
            break;
        default:
            ipv6_hdr->nexthdr = type;
            // ASSERT_WARN
    }
    ipv6_hdr->hop_limit = 64;
    ipv6_hdr->saddr = saddr;
    ipv6_hdr->daddr = daddr;

    return IPV6_HDR_LEN;
}

static inline int
make_icmpv4(struct icmpv4_hdr_t* icmpv4_hdr)
{
    icmpv4_hdr->type = 8;
    icmpv4_hdr->code = 0;
    icmpv4_hdr->chksum = htons(CHECKSUM);
    icmpv4_hdr->id = htons(0xa948);
    icmpv4_hdr->seq_num = htons(0x0cb2);

    return ICMPV4_HDR_LEN;
}

static inline int
make_icmpv6(struct icmpv6_hdr_t* icmpv6_hdr)
{
    icmpv6_hdr->type = 128;
    icmpv6_hdr->code = 0;
    icmpv6_hdr->chksum = htons(0xd627);
    icmpv6_hdr->id = htons(0x66cf);
    icmpv6_hdr->seq_num = htons(1);
    return ICMPV6_HDR_LEN;
}

static inline int
make_tcp(struct tcp_hdr_t* tcp_hdr, u16 sport, u16 dport, u8 flag, u16 window_size)
{
    tcp_hdr->sport = htons(sport);
    tcp_hdr->dport = htons(dport);
    tcp_hdr->seq_num = htonl(CHECKSUM);
    tcp_hdr->ack_num = 0;
    tcp_hdr->offset = 0x5;
    tcp_hdr->reserve = 0;
    if (!flag) flag = ACK;
    tcp_hdr->flag = flag;
    tcp_hdr->window = window_size;
    tcp_hdr->chksum = CHECKSUM;
    tcp_hdr->ugr_ptr = 0;

    return TCP_HDR_LEN;
}

static inline int
make_udp(struct udp_hdr_t* udp_hdr, u16 sport, u16 dport)
{
    udp_hdr->sport = htons(sport);
    udp_hdr->dport = htons(dport);
    udp_hdr->len = htons(8);
    udp_hdr->chksum = htons(CHECKSUM);

    return UDP_HDR_LEN;
}

struct g_var_t {
    u32 interval;
    u32 send_count;
    u32 send_rate;          // when rate config by -I is less than 1sec, this take effect
    u8  is_test_arg: 1,     // only test the parsing of argument but not send pkt
        spare:       7;
}__attribute__((packed));

extern struct g_var_t g_var;

static inline void
show_g_var()
{
    printf("######## show g_var ########\n");
    if (g_var.interval > 1000000) {
        printf("interval = %0.1f sec\n", (float)g_var.interval/1000000);
    } else {
        printf("interval = %d u sec\n", g_var.interval);   
    }
    printf("send_count = %d\n", g_var.send_count);
}
#endif  // main.h
