#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>


#include <sys/socket.h>             /* socket(), bind(), listen(), ... */
#include <netinet/in.h>             /* AF_INET, AF_INET6 addr family and their corresponding protocol family PF_INET, PFINET6 */
#include <arpa/inet.h>              /* hton(), inet_ntop() */
#include <unistd.h>                 /* read(), write(), close() */

#include "main.h"
#include "list.h"

#define COLLECTOR_IP "127.0.0.1"
#define SFLOW_PORT   6343

#define SRC_IP 0x141414a1         // 20.20.20.160
#define DST_IP 0x141465a2         // 20.20.101.162

#define SRC_PORT 9487
#define DST_PORT 8000

#define SAMPLE_NUM 1

struct node_t* head_node;

void handle_argv(int argc, char **argv) {
    /*
     * -u 20.20.20.1 8787
     * -i 20.20.20.1
     */

    head_node = NODE_CALLOC();
    if (NULL == head_node) {
        printf("Can not malloc for head_node\n");
        exit(1);
    }

    if (argc == 1) {
        head_node->type = 0x1;
        head_node->sip = SRC_IP;
        head_node->dip = DST_IP;
        return;
    }

    struct node_t* curr = head_node;
    struct node_t* prev = NULL;
    int i = 1;
    int ret = 0;
    while (i < argc) {

        if (0 == strcmp("-i", argv[i]) && i+1 <= argc) {
            curr->type = 0x1;
            curr->sip = SRC_IP;
            ret = inet_pton(AF_INET, argv[i+1], &curr->dip);
            //curr->dip = DST_IP;
            i += 2;
        } else if (0 == strcmp("-u", argv[i]) && i+2 <= argc) {
            curr->type = 0x11;
            curr->sip = SRC_IP;
            ret = inet_pton(AF_INET, argv[i+1], &curr->dip);
            //curr->dip = DST_IP;
            curr->sport = SRC_PORT;
            curr->dport = strtol(argv[i+2], NULL, 10);
            i += 3;
        } else if (0 == strcmp("-t", argv[i]) && i+2 <= argc) {
            curr->type = 0x6;
            curr->sip = SRC_IP;
            ret = inet_pton(AF_INET, argv[i+1], &curr->dip);
            //curr->dip = DST_IP;
            curr->sport = SRC_PORT;
            curr->dport = strtol(argv[i+2], NULL, 10);
            i += 3;
        } else {
            printf("Parse arg fail\n");
            goto err;
        }

        if (ret == 0) {
            printf("Parse ip addr fail\n");
            goto err;
        }

        // before goto next
        if (curr != head_node) {
            prev->next = curr;
        } 
        prev = curr;
        curr = NODE_CALLOC();
    } 
    show(head_node);
    return;

err:
    exit(1);
}

int make_sflow_hdr(u8 **msg) {

    struct sflow_hdr_t* sflow_hdr;
    sflow_hdr = (struct sflow_hdr_t*) calloc(1, sizeof(struct sflow_hdr_t));
    sflow_hdr->version = htonl(5);
    sflow_hdr->agent_addr_type = htonl(1);
    sflow_hdr->agent_addr = htonl(0xac152311);
    sflow_hdr->sub_agent_id = htonl(1);
    sflow_hdr->seq_num = htonl(0x01a2);
    sflow_hdr->sys_uptime = htonl(0x673e7f08);
    sflow_hdr->sample_num = htonl(get_node_num(head_node));

    int ret_len = (int) sizeof(struct sflow_hdr_t);
    u8* ret = (u8*) calloc(1, ret_len);
    memcpy(ret, sflow_hdr, ret_len);

    *msg = ret;
    return ret_len;
}

int make_sflow_sample_hdr(u8 **msg, int curr_len) 
{

    struct sflow_sample_hdr_t* sflow_sample_hdr;
    sflow_sample_hdr = (struct sflow_sample_hdr_t*) calloc(1, sizeof(struct sflow_sample_hdr_t));
    sflow_sample_hdr->sample_type = htonl(1);
    sflow_sample_hdr->sample_len = htonl(curr_len+(int)sizeof(struct sflow_sample_hdr_t)-8);
    sflow_sample_hdr->seq_num = htonl(6);
    sflow_sample_hdr->idx = htonl(1043);
    sflow_sample_hdr->sample_rate = htonl(2048);
    sflow_sample_hdr->sample_pool = htonl(12288);
    sflow_sample_hdr->dropped_pkt = 0;
    sflow_sample_hdr->input_intf = htonl(1048);
    sflow_sample_hdr->output_intf = htonl(0x00000413);
    sflow_sample_hdr->flow_record = htonl(1);

    int ret_len = (int) sizeof(struct sflow_sample_hdr_t);
    u8* ret = (u8*) calloc(1, ret_len);
    memcpy(ret, sflow_sample_hdr, ret_len);

    *msg = ret;
    return ret_len;
}

int make_sampled_pkt(u8 **msg, struct node_t* node) 
{
    int sampled_pkt_payload_len = 0;
    if (node->type == 0x1) {
        sampled_pkt_payload_len = ICMPV4_HDR_LEN;
    } else if (node->type == 0x6) {
        sampled_pkt_payload_len = TCP_HDR_LEN;
    } else if (node->type == 0x11) {
        sampled_pkt_payload_len = UDP_HDR_LEN;
    }


    u8 *ret;
    int ori_len = 0;
    int padding_len = 0;
    int ret_len = 0;

    u8 eth_data[14] = { 0x00, 0x1c, 0x23, 0x9f, 0x15, 0x0b,
                        0x00, 0x19, 0xb9, 0xdd, 0xb2, 0x64,
                        0x08, 0x00 };
    ori_len += 14;

    struct ipv4_hdr_t* ipv4_hdr;
    struct icmpv4_hdr_t* icmpv4_hdr;
    struct udp_hdr_t* udp_hdr;
    struct tcp_hdr_t* tcp_hdr;

    ipv4_hdr = (struct ipv4_hdr_t*) calloc(1, sizeof(struct ipv4_hdr_t));
    make_ipv4(ipv4_hdr, sampled_pkt_payload_len, node->type, node->sip, node->dip);
    ori_len += IPV4_HDR_LEN;

    if (node->type == 0x1) {

        icmpv4_hdr = (struct icmpv4_hdr_t*) calloc(1, ICMPV4_HDR_LEN);
        make_icmpv4(icmpv4_hdr);
        ori_len += ICMPV4_HDR_LEN;

    } else if (node->type == 0x6) {

        tcp_hdr = (struct tcp_hdr_t*) calloc(1, TCP_HDR_LEN);
        make_tcp(tcp_hdr, SRC_PORT, DST_PORT);
        ori_len += TCP_HDR_LEN;

    } else if (node->type == 0x11) {
        ipv4_hdr->protocol = 17;     // 17 for udp

        udp_hdr = (struct udp_hdr_t*) calloc(1, UDP_HDR_LEN);
        make_udp(udp_hdr, SRC_PORT, DST_PORT);
        ori_len += UDP_HDR_LEN;
    }


    if (ori_len % 4 != 0) {
        padding_len = (ori_len/4 +1)*4 -ori_len;
    }
    ret = (u8*) calloc(1, ori_len + padding_len);
    memcpy(ret, eth_data, 14);
    ret_len += 14;

    memcpy(ret+ret_len, (void*) ipv4_hdr, IPV4_HDR_LEN);
    ret_len += IPV4_HDR_LEN;

    if (node->type == 0x1) {
        memcpy(ret+ret_len, (void*) icmpv4_hdr, ICMPV4_HDR_LEN);
        ret_len += ICMPV4_HDR_LEN;
    } else if (node->type == 0x6) {
        memcpy(ret+ret_len, (void*) tcp_hdr, TCP_HDR_LEN);
        ret_len += TCP_HDR_LEN;
    } else if (node->type == 0x11) {
        memcpy(ret+ret_len, (void*) udp_hdr, UDP_HDR_LEN);
        ret_len += UDP_HDR_LEN;
    }

    *msg = ret;
    return ret_len;
}

int make_raw_pkt_hdr(u8 **msg, int sampled_pkt_len, int padding_len) 
{
    
    struct raw_pkt_hdr_t* raw_pkt_hdr;
    raw_pkt_hdr = (struct raw_pkt_hdr_t*) calloc(1, sizeof(struct raw_pkt_hdr_t));
    raw_pkt_hdr->format = htonl(1);
    raw_pkt_hdr->flow_data_len = htonl(sampled_pkt_len + padding_len +(int)sizeof(struct raw_pkt_hdr_t) - 8);
    raw_pkt_hdr->hdr_protocol = htonl(1);
    raw_pkt_hdr->frame_len = htonl(sampled_pkt_len);
    raw_pkt_hdr->payload_removed = htonl(0);
    raw_pkt_hdr->ori_pkt_len = htonl(sampled_pkt_len);
    
    int ret_len = (int) sizeof(struct raw_pkt_hdr_t);
    u8 *ret = (u8*) calloc(1, ret_len);
    memcpy(ret, raw_pkt_hdr, ret_len);
    
    *msg = ret;
    return ret_len;
}

/* main caller */
int make_sflow_packet(u8 **msg) 
{

    // make sampled packet
    int sampled_pkt_len = 0;
    u8 *sampled_pkt;

    struct node_t* curr_node;
    curr_node = head_node;

    int curr_len = 0;
    int raw_pkt_hdr_len = 0;
    u8 *raw_pkt_hdr;
    int padding_len = 0;
    int sflow_sample_hdr_len = 0;
    int all_sample_len = 0;

    while (curr_node) {  // for every node, make a sample
    
        // make sampled pkt
        sampled_pkt_len = make_sampled_pkt(&sampled_pkt, curr_node);
        printf("sampled_pkt_len: %d\n", sampled_pkt_len);
        
        // cal padding len
        if (sampled_pkt_len % 4 != 0) {
            padding_len = (sampled_pkt_len/4 +1)*4 -sampled_pkt_len;
        }
        printf("padding_len: %d\n", padding_len);

        // make raw packet header
        raw_pkt_hdr_len = make_raw_pkt_hdr(&raw_pkt_hdr, sampled_pkt_len, padding_len);
        printf("raw_pkt_hdr_len: %d\n", raw_pkt_hdr_len);


        // make sflow sample
        u8* sflow_sample_hdr;
        sflow_sample_hdr_len = make_sflow_sample_hdr(&sflow_sample_hdr, sampled_pkt_len+raw_pkt_hdr_len+padding_len);
        printf("sflow_sample_hdr_len: %d\n", sflow_sample_hdr_len);


        // copy this sample to node->sample_ptr
        curr_node->sample_len = sflow_sample_hdr_len+raw_pkt_hdr_len+sampled_pkt_len+padding_len;
        curr_node->sample_ptr = (u8*) calloc(1, curr_node->sample_len);
        curr_len = 0;
        memcpy(curr_node->sample_ptr, sflow_sample_hdr, sflow_sample_hdr_len);
        curr_len += sflow_sample_hdr_len;
        memcpy(curr_node->sample_ptr+curr_len, raw_pkt_hdr, raw_pkt_hdr_len);
        curr_len += raw_pkt_hdr_len;
        memcpy(curr_node->sample_ptr+curr_len, sampled_pkt, sampled_pkt_len);


        // before goto next
        all_sample_len += curr_node->sample_len;
        curr_node = curr_node->next;
    }

    // make sflow header
    int sflow_hdr_len = 0;
    u8* sflow_hdr;
    sflow_hdr_len = make_sflow_hdr(&sflow_hdr);
    printf("sflow_hdr_len: %d\n", sflow_hdr_len);


    // make sflow packet
    int sflow_pkt_len = all_sample_len + sflow_hdr_len;
    printf("sflow_pkt_len: %d\n", sflow_pkt_len);
    u8* ret = (u8*) calloc(1, sflow_pkt_len);

    
    curr_len = 0;
    memcpy(ret, sflow_hdr, sflow_hdr_len);
    curr_len += sflow_hdr_len;

    // copy all stuff into
    curr_node = head_node;
    while (curr_node) {
        memcpy(ret+curr_len, curr_node->sample_ptr, curr_node->sample_len);
        curr_len += curr_node->sample_len;
        curr_node = curr_node->next;
    }

    assert(curr_len == sflow_pkt_len);

    *msg = ret;
    return curr_len;
}

int main (int argc, char *argv[]) {
    
    handle_argv(argc, argv);

    u8 *msg;
    int len = make_sflow_packet(&msg);


    int sockfd, n;
    struct sockaddr_in serv_addr;

    // init
    bzero(&serv_addr, sizeof(serv_addr));
    serv_addr.sin_addr.s_addr = inet_addr(COLLECTOR_IP);
    serv_addr.sin_port = htons(SFLOW_PORT);
    serv_addr.sin_family = AF_INET;

    // create socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    // connect to the server
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("connect fail\n");
        exit(1);
    }

    sendto(sockfd, (void*) msg, len, 0, (struct sockaddr*) NULL, sizeof(serv_addr));
    close(sockfd);
}
