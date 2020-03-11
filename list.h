#ifndef NODE_H
#define NODE_H

#include "util.h"
#include <stdio.h>
#include <stdlib.h>

struct node_t {
    u8 type; // 1 for icmpv4, 17 for udp
    u32 sip;
    u32 dip;
    u16 sport;
    u16 dport;
    struct node_t *next;
    int sample_len;
    u8* sample_ptr;
} __attribute__((packed));;

#define NODE_CALLOC() (struct node_t*) calloc(1, sizeof(struct node_t))

static inline void show(struct node_t* curr) {
    while (curr) {
        printf("-------------------\n");
        switch (curr->type) {
            case 0x1:
                printf("type: ICMP\n");
                break;
            case 0x6:
                printf("type: TCP\n");
                break;
            case 0x11:
                printf("type: UDP\n");
                break;
            default:
                printf("Unknown type\n");
                return;
        }
        printf("sip: %x\n", curr->sip);
        printf("dip: %x\n", curr->dip);
        printf("sport: %d\n", curr->sport);
        printf("dport: %d\n", curr->dport);
        curr = curr->next;
    }
}

static inline int get_node_num(struct node_t* head_node) {
    int ret = 0;
    while(head_node) {
        ret++;
        head_node = head_node->next;
    }
    return ret;
}

#endif
