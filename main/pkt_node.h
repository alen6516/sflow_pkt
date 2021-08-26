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
    u16 sport;
    u16 dport;
    u8 tcp_flag;
    u16 tcp_window_size;
    u16 payload_size;
    u8 is_frag: 1,
       is_v6:   1,
       spare:   6;
    struct __pkt_node *next;
    int sample_len;
    u8* sample_ptr;
} __attribute__((packed)) PKT_NODE;


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
pkt_node_show(PKT_NODE* curr)
{    
    char buf[256];
    while (curr) {
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
            printf("sip: %x\n", ntohl(curr->sip));
            printf("dip: %x\n", ntohl(curr->dip));
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
        curr = curr->next;
    }
}

static inline int
pkt_node_get_num(PKT_NODE* head_node)
{
    int ret = 0;
    while(head_node) {
        ret++;
        head_node = head_node->next;
    }
    return ret;
}

#endif // PKT_NODE_H
