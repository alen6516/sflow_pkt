#ifndef NODE_H
#define NODE_H

#include "util.h"
#include "main.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>      // errno
#include <string.h>     // strerror
#include <arpa/inet.h>

typedef struct node_t {
    u8 type; // 1 for icmpv4, 17 for udp
    u32 sip;
    u32 dip;
    u16 sport;
    u16 dport;
    struct node_t *next;
    int sample_len;
    u8* sample_ptr;
} __attribute__((packed)) PKT_NODE;


static inline void NODE_CALLOC(PKT_NODE *node)
{
    node = (PKT_NODE*) calloc(1, sizeof(PKT_NODE));
    if (NULL == node) {
        printf("strerror: %s\n", strerror(errno));
        err_exit(MALLOC_FAIL);
    }
}

static inline void list_show(PKT_NODE* curr)
{    
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
        printf("dip: %x\n", htonl(curr->dip));
        printf("sport: %d\n", curr->sport);
        printf("dport: %d\n", curr->dport);
        curr = curr->next;
    }
}

static inline int get_node_num(PKT_NODE* head_node)
{
    int ret = 0;
    while(head_node) {
        ret++;
        head_node = head_node->next;
    }
    return ret;
}

#endif
