#ifndef PKT_NODE_H
#define PKT_NODE_H

#include "../util.h"
#include "main.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>      // errno
#include <string.h>     // strerror
#include <arpa/inet.h>

typedef struct __pkt_node {
    u8 type; // 1 for icmpv4, 17 for udp

    union {
        u32 sip;
        struct in6_addr sip6;
    };
    union {
        u32 dip;
        struct in6_addr dip6;
    };
    u32 src_num;
    u16 sport;
    u16 dport;
    u8  tcp_flag;
    u16 tcp_window_size;
    u16 payload_size;
    u8 is_frag: 1,
       is_v6:   1,
       spare:   6;
    struct __pkt_node *next;
    int sample_len;
    u8* sample_ptr;
} __attribute__((packed)) PKT_NODE;

typedef struct __msg_node {
    struct __msg_node *next;
    u8 sample_num;      // num of sample in this msg
    u16 len;            // data length of this msg
    u8 data[1500];
} __attribute__((packed)) MSG_NODE;

static inline void
pkt_node_calloc(PKT_NODE *node)
{
    node = (PKT_NODE*) calloc(1, sizeof(PKT_NODE));
    if (NULL == node) {
        printf("strerror: %s\n", strerror(errno));
        err_exit(MALLOC_FAIL);
    }
}

static inline void
show_pkt_node(PKT_NODE* curr)
{    
    char buf[256];
    printf("-------------------\n");
    switch (curr->type) {
        case ICMP:
            printf("type: ICMP\n");
            break;
        case ICMPv6:
            printf("type: ICMPv6\n");
            break;
        case TCP:
            printf("type: TCP\n");
            break;
        case UDP:
            printf("type: UDP\n");
            break;
        default:
            printf("Unknown type\n");
            return;
    }
    if (curr->is_v6) {
        printf("sip6: %s\n", inet_ntop(AF_INET6, (const void*)&curr->sip6, buf, sizeof(buf)));
        printf("dip6: %s\n", inet_ntop(AF_INET6, (const void*)&curr->dip6, buf, sizeof(buf)));
    } else {
        //printf("sip: %x\n", ntohl(curr->sip));
        //printf("dip: %x\n", ntohl(curr->dip));
        printf("sip: %s\n", inet_ntop(AF_INET, (const void*)&curr->sip, buf, sizeof(buf)));
        printf("dip: %s\n", inet_ntop(AF_INET, (const void*)&curr->dip, buf, sizeof(buf)));
    }

    if (curr->type == TCP || curr->type == UDP) {
        printf("sport: %d\n", curr->sport);
        printf("dport: %d\n", curr->dport);
    }

    if (curr->type == TCP) {
        printf("tcp flag: ");
        if (curr->tcp_flag & SYN) printf("SYN, ");
        if (curr->tcp_flag & ACK) printf("ACK, ");
        if (curr->tcp_flag & FIN) printf("FIN, ");
        if (curr->tcp_flag & RST) printf("RST, ");
        printf("\n");
        printf("tcp window size: %d\n", curr->tcp_window_size);
    }
}

static inline int
pkt_node_get_num(PKT_NODE* curr_node)
{
    int ret = 0;
    while(curr_node) {
        ret++;
        curr_node = curr_node->next;
    }
    return ret;
}

#endif // PKT_NODE_H
