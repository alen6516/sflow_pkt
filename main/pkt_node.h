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
    u32 sip;
    u32 dip;
    u16 sport;
    u16 dport;
    u8 tcp_flag;
    u16 tcp_window_size;
    u16 payload_size;
    u8 is_frag;
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
    while (curr) {
        printf("-------------------\n");
        switch (curr->type) {
            case ICMP:
                printf("type: ICMP\n");
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
        printf("sip: %x\n", ntohl(curr->sip));
        printf("dip: %x\n", ntohl(curr->dip));
        printf("sport: %d\n", curr->sport);
        printf("dport: %d\n", curr->dport);
        
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
