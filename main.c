#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>


#include <sys/socket.h>             /* socket(), bind(), listen(), ... */
#include <netinet/in.h>             /* AF_INET, AF_INET6 addr family and their corresponding protocol family PF_INET, PFINET6 */
#include <arpa/inet.h>              /* hton(), inet_ntop() */
#include <unistd.h>                 /* read(), write(), close() */

#include "util.h"
#include "main.h"
#include "list.h"
#include "config.h"

struct g_var_t g_var = {
    .interval = 1000000,    // unit is micro seconds
    .send_count = 1,
};

static struct node_t* head_node;


/*
 * parse argu from command line
 */
void handle_argv(int argc, char **argv)
{
    /* argu:
     * -i 20.20.101.1
     * -u 20.20.101.1 8787
     * -t 20.20.101.1 8787
     * -a 20.20.20.1
     * -c 5
     * -I 2
     *
     * e.g.
     * -u 20.20.101.162 -p 8787 -a 20.20.20.1 -c 10 -i u1000
     */

    if (argc == 1) {
        // simple test if no any argu
        head_node->type = 0x1;
        head_node->sip = SRC_IP;
        head_node->dip = DST_IP;
        return;
    }

    struct node_t* curr = head_node;
    struct node_t* prev = NULL;
    u8 i = 1;
    int ret = 1;

    while (i < argc) {
        if (0 == strcmp("-i", argv[i]) && i+1 < argc) {
			// -i 20.20.101.1
            if (curr->dip) {
                goto add_node;
            }
            curr->type = 0x1;
            curr->sip = SRC_IP;
            ret = inet_pton(AF_INET, argv[i+1], &curr->dip);
            i += 2;
            
        } else if (0 == strcmp("-u", argv[i]) && i+2 < argc) {
			// -u 20.20.101.1 9000
            if (curr->dip) {
                goto add_node;
            }
            curr->type = 0x11;
            curr->sip = SRC_IP;
            ret = inet_pton(AF_INET, argv[i+1], &curr->dip);
            curr->sport = SRC_PORT;
            curr->dport = strtol(argv[i+2], NULL, 10);
            i += 3;

        } else if (0 == strcmp("-t", argv[i]) && i+2 < argc) {
			// -t 20.20.101.1 8000
            if (curr->dip) {
                goto add_node;
            }
            curr->type = 0x6;
            curr->sip = SRC_IP;
            ret = inet_pton(AF_INET, argv[i+1], &curr->dip);
            curr->sport = SRC_PORT;
            curr->dport = strtol(argv[i+2], NULL, 10);
            i += 3;
        
        } else if (0 == strcmp("-a", argv[i]) && i+1 < argc) {
			// -a 20.20.20.1
            ret = inet_pton(AF_INET, argv[i+1], &curr->sip);
            i += 2;

        } else if (0 == strcmp("-c", argv[i]) && i+1 < argc) {
			// -c 5
            g_var.send_count = (u32) strtol(argv[i+1], NULL, 10);
            if (!g_var.send_count) {
                printf("error, send_count == 0\n");
                ret = -1;
            }
            i += 2;

        } else if (0 == strcmp("-I", argv[i]) && i+1 < argc) {
			// -I 2
            if (argv[i+1][0] == 'u') {
                g_var.interval = (u32) strtol(&argv[i+1][1], NULL, 10);
            } else {
                g_var.interval = 1000000 * (u32) strtol(argv[i+1], NULL, 10);
            }
            if (g_var.interval == 0) {
                printf("error, interval == 0\n");
                ret = -1;
            }
            i += 2;

        } else if (0 == strcmp("--test-arg", argv[i])) {
            // --test-arg
            g_var.is_test_arg = 1;
            i += 1;

        } else {
            printf("error, Parse arg fail\n");
            goto err;
        }

        if (ret != 1) {
			if (ret == 0) {
            	printf("Parse ip addr fail\n");
          	}
			goto err;
		}
        continue;

add_node:
        if (!curr->sip) {
            curr->sip = SRC_IP;
        }
        prev = curr;
        NODE_CALLOC(curr);
        prev->next = curr;
    } // while

    show_g_var();
    return;

err:
    err_exit(PARSE_ARG_FAIL);
}

// make the header of the entire sflow pkt
static inline int make_sflow_hdr(u8 **msg)
{
    struct sflow_hdr_t* sflow_hdr;
    CALLOC_EXIT_ON_FAIL(struct sflow_hdr_t, sflow_hdr, 0);

    sflow_hdr->version = htonl(5);
    sflow_hdr->agent_addr_type = htonl(1);
    inet_pton(AF_INET, AGENT_IP, &sflow_hdr->agent_addr);
    sflow_hdr->sub_agent_id = htonl(1);
    sflow_hdr->seq_num = htonl(0x01a2);
    sflow_hdr->sys_uptime = htonl(0x673e7f08);
    sflow_hdr->sample_num = htonl(get_node_num(head_node));

    int ret_len = (int) sizeof(struct sflow_hdr_t);
    *msg = (u8*) sflow_hdr;
    return ret_len;
}

// make the header of a flow sample
static inline int make_sflow_sample_hdr(u8 **msg, int curr_len) 
{

    struct sflow_sample_hdr_t* sflow_sample_hdr;
    CALLOC_EXIT_ON_FAIL(struct sflow_sample_hdr_t, sflow_sample_hdr, 0);

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
    *msg = (u8*) sflow_sample_hdr;
    return ret_len;
}

 
// making the raw packet: eth + ip + icmp/udp/tcp
int make_sampled_pkt(u8 **msg, struct node_t* node) 
{
    int sampled_pkt_payload_len = 0;
    switch (node->type) {
        case 0x1:
            sampled_pkt_payload_len = ICMPV4_HDR_LEN;
            break;

        case 0x6:
            sampled_pkt_payload_len = TCP_HDR_LEN;
            break;

        case 0x11:
            sampled_pkt_payload_len = UDP_HDR_LEN;
            break;

        default:
            // ASSERT_WARN
            break;
    }

    u8 *ret;
    int ori_len = 0;
    int padding_len = 0;
    int ret_len = 0;

    u8 eth_data[] = { 0x00, 0x1c, 0x23, 0x9f, 0x15, 0x0b,
                        0x00, 0x19, 0xb9, 0xdd, 0xb2, 0x64,
                        0x08, 0x00 };
    ori_len += sizeof(eth_data);

    struct ipv4_hdr_t* ipv4_hdr;
    struct icmpv4_hdr_t* icmpv4_hdr;
    struct udp_hdr_t* udp_hdr;
    struct tcp_hdr_t* tcp_hdr;

    // make ipv4 header
    CALLOC_EXIT_ON_FAIL(struct ipv4_hdr_t, ipv4_hdr, 0);
    make_ipv4(ipv4_hdr, sampled_pkt_payload_len, node->type, node->sip, node->dip);
    ori_len += IPV4_HDR_LEN;

    // make l4 header
    switch (node->type) {
        case 0x1:
            CALLOC_EXIT_ON_FAIL(struct icmpv4_hdr_t, icmpv4_hdr, 0);
            make_icmpv4(icmpv4_hdr);
            ori_len += ICMPV4_HDR_LEN;
            break;

        case 0x6:
            CALLOC_EXIT_ON_FAIL(struct tcp_hdr_t, tcp_hdr, 0);
            make_tcp(tcp_hdr, node->sport, node->dport);
            ori_len += TCP_HDR_LEN;
            break;

        case 0x11:
            CALLOC_EXIT_ON_FAIL(struct udp_hdr_t, udp_hdr, 0);
            make_udp(udp_hdr, node->sport, node->dport);
            ori_len += UDP_HDR_LEN;
            break;

        default:
            // ASSERT_WARN
            break;
    }

    // padding
    if (ori_len % 4 != 0) {
        padding_len = (ori_len/4 +1)*4-ori_len;
    }
    CALLOC_EXIT_ON_FAIL(u8, ret, (ori_len + padding_len));
    memcpy(ret, eth_data, sizeof(eth_data));
    ret_len += sizeof(eth_data);

    memcpy(ret+ret_len, (void*) ipv4_hdr, IPV4_HDR_LEN);
    ret_len += IPV4_HDR_LEN;

    switch (node->type) {
        case 0x1:
            memcpy(ret+ret_len, (void*) icmpv4_hdr, ICMPV4_HDR_LEN);
            ret_len += ICMPV4_HDR_LEN;
            break;

        case 0x6:
            memcpy(ret+ret_len, (void*) tcp_hdr, TCP_HDR_LEN);
            ret_len += TCP_HDR_LEN;
            break;

        case 0x11:
            memcpy(ret+ret_len, (void*) udp_hdr, UDP_HDR_LEN);
            ret_len += UDP_HDR_LEN;
            break;

        default:
            // ASSERT_WARN
            break;
    }

    *msg = ret;
    return ret_len;
}

// make raw pkt header
int make_raw_pkt_hdr(u8 **msg, int sampled_pkt_len, int padding_len) 
{
    struct raw_pkt_hdr_t* raw_pkt_hdr;
    CALLOC_EXIT_ON_FAIL(struct raw_pkt_hdr_t, raw_pkt_hdr, 0);

    raw_pkt_hdr->format = htonl(1);
    raw_pkt_hdr->flow_data_len = htonl(sampled_pkt_len + padding_len +(int)sizeof(struct raw_pkt_hdr_t) - 8);
    raw_pkt_hdr->hdr_protocol = htonl(1);
    raw_pkt_hdr->frame_len = htonl(sampled_pkt_len);
    raw_pkt_hdr->payload_removed = htonl(0);
    raw_pkt_hdr->ori_pkt_len = htonl(sampled_pkt_len);
    
    *msg = (u8*) raw_pkt_hdr;
    return (int) sizeof(struct raw_pkt_hdr_t);
}

// main caller, making the sampled packet
int make_sflow_packet(u8 **msg) 
{
    int sampled_pkt_len = 0;
    u8 *sampled_pkt;

    struct node_t* curr_node = head_node;

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

        
        // calc padding len
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

int main (int argc, char *argv[])
{    
    CALLOC_EXIT_ON_FAIL(struct node_t, head_node, 0);
    handle_argv(argc, argv);

    if (g_var.is_test_arg) {
        printf("test arg parsing, exit\n");
        return 0;
    }
    if (!head_node->dip) {
        printf("no sflow node to send, exit\n");
        return 0;
    }

    u8 *msg;
    int len = make_sflow_packet(&msg);

    int ret;
    int sockfd;
    struct sockaddr_in serv_addr;

    // init sockaddr_in
    bzero(&serv_addr, sizeof(serv_addr));
    serv_addr.sin_addr.s_addr = inet_addr(COLLECTOR_IP);
    serv_addr.sin_port = htons(SFLOW_PORT);
    serv_addr.sin_family = AF_INET;

    // create socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    for (int t=0; t < g_var.send_count; t++) {
        if (t != 0) {
            sleep(g_var.interval);
        }

        ret = sendto(sockfd, (void*) msg, len, 0, (struct sockaddr*) &serv_addr, sizeof(serv_addr));
        printf("%d bytes has been sent\n", ret);
        if (ret < 0) {
            printf("strerror:%s\n", strerror(errno)); 
        }
        list_show(head_node);
    }
    close(sockfd);
}
