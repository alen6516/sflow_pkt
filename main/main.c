#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>

#include <sys/socket.h>             /* socket(), bind(), listen(), ... */
#include <netinet/in.h>             /* AF_INET, AF_INET6 addr family and their corresponding protocol family PF_INET, PFINET6 */
#include <arpa/inet.h>              /* hton(), inet_ntop() */
#include <unistd.h>                 /* read(), write(), close() */

#include "../util.h"
#include "config.h"
#include "main.h"
#include "pkt_node.h"

struct g_var_t g_var = {
    .interval = 1000000,        // unit is micro seconds
    .round_to_send = -1,        // infinite rounds
    .pkt_sampling_rate = SAMPLING_RATE,
};

static PKT_NODE* head_node;
static MSG_NODE* head_msg_node;

/*
 * parse argu from command line
 * return 0 on success
 */
int
handle_argv(int argc, char **argv)
{
    /* argu:
     * -i 20.20.101.1
     * -u 20.20.101.1 8787
     * -t -S 20.20.101.1 8787
     * -a 20.20.20.1
     * -s 12345
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
        head_node->src_num = 1;
        return 0;
    }

    PKT_NODE* curr = head_node;
    PKT_NODE* prev = NULL;
    u8 i = 1;

    while (i < argc) {
        if (0 == strcmp("-i", argv[i]) && i+1 < argc) {
			// -i 20.20.101.1
            if (curr->dip) {
                goto add_node;
            }
            curr->type = ICMP;
            curr->sip = htonl(SRC_IP);
            curr->src_num = 1;
            if (1 != inet_pton(AF_INET, argv[i+1], &curr->dip)) {
                printf("error, Parsing dst ip fail\n");
                goto err;
            }
            i += 2;

        } else if (0 == strcmp("-i6", argv[i]) && i+1 < argc) {
            // -i6 2001:2::162
            if (curr->dip) {
                goto add_node;
            }
            curr->is_v6 = 1;
            curr->type = ICMPv6;
            inet_pton(AF_INET6, SRC_IPv6, &curr->sip6);
            curr->src_num = 1;
            if (1 != inet_pton(AF_INET6, argv[i+1], &curr->dip6)) {
                printf("error, Parsing dst ip6 fail\n");
                goto err;
            }
            i += 2;
            
        } else if (0 == strcmp("-u", argv[i]) && i+2 < argc) {
			// -u 20.20.101.1 9000
            if (curr->dip) {
                goto add_node;
            }
            curr->type = UDP;
            curr->sip = htonl(SRC_IP);
            curr->src_num = 1;
            if (1 != inet_pton(AF_INET, argv[i+1], &curr->dip)) {
                printf("error, Parsing UDP dst ip fail\n");
                goto err;
            }
            curr->sport = SRC_PORT;
            curr->dport = strtol(argv[i+2], NULL, 10);
            i += 3;

        } else if (0 == strcmp("-u6", argv[i]) && i+2 < argc) {
			// -u6 2001:2::162 9000
            if (curr->dip) {
                goto add_node;
            }
            curr->is_v6 = 1;
            curr->type = UDP;
            inet_pton(AF_INET6, SRC_IPv6, &curr->sip6);
            curr->src_num = 1;
            if (1 != inet_pton(AF_INET6, argv[i+1], &curr->dip6)) {
                printf("error, Parsing UDP dst ip6 fail\n");
                goto err;
            }
            curr->sport = SRC_PORT;
            curr->dport = strtol(argv[i+2], NULL, 10);
            i += 3;

        } else if (0 == strcmp("-t", argv[i]) && i+2 < argc) {
			// -t 20.20.101.1 8000
            if (curr->dip) {
                goto add_node;
            }
            curr->type = 0x6;
            curr->sip = htonl(SRC_IP);
            curr->src_num = 1;
            if (1 != inet_pton(AF_INET, argv[i+1], &curr->dip)) {
                printf("error, Parsing TCP dst ip fail\n");
                goto err;
            }
            curr->sport = SRC_PORT;
            curr->dport = strtol(argv[i+2], NULL, 10);
            i += 3;

        } else if (0 == strcmp("-t6", argv[i]) && i+2 < argc) {
			// -t6 2001:2::162 9000
            if (curr->dip) {
                goto add_node;
            }
            curr->is_v6 = 1;
            curr->type = TCP;
            inet_pton(AF_INET6, SRC_IPv6, &curr->sip6);
            curr->src_num = 1;
            if (1 != inet_pton(AF_INET6, argv[i+1], &curr->dip6)) {
                printf("error, Parsing TCP dst ip6 fail\n");
                goto err;
            }
            curr->sport = SRC_PORT;
            curr->dport = strtol(argv[i+2], NULL, 10);
            i += 3;

        } else if (0 == strcmp("--flag", argv[i]) && i+1 < argc) {
            // --flag SA
            for (char *s = argv[i+1]; *s != '\0'; s++) {
                switch (*s) {
                    case 'A':
                        curr->tcp_flag |= ACK;
                        break;
                    case 'S':
                        curr->tcp_flag |= SYN;
                        break;
                    case 'F':
                        curr->tcp_flag |= FIN;
                        break;
                    case 'R':
                        curr->tcp_flag |= RST;
                        break;
                    default:
                        printf("error, unknown tcp flag %c\n", *s);
                        goto err;
                        break;
                }
            }
            i += 2;

        } else if (0 == strcmp("-w", argv[i]) && i+1 < argc) {
            // -w 8787
            curr->tcp_window_size = (u16) strtol(argv[i+1], NULL, 10);
            i += 2;

        } else if (0 == strcmp("-a", argv[i]) && i+1 < argc) {
			// -a 20.20.20.161
            if (curr->is_v6) {
                if (1 != inet_pton(AF_INET6, argv[i+1], &curr->sip6)) {
                    printf("error, Parsing src ip6 fail\n");
                    goto err;
                }
            } else {
                if (1 != inet_pton(AF_INET, argv[i+1], &curr->sip)) {
                    printf("error, Parsing src ip fail\n");
                    goto err;
                }
            }
            i += 2;

        } else if (0 == strcmp("-aN", argv[i]) && i+1 < argc) {
            curr->src_num = strtol(argv[i+1], NULL, 10);
            if (curr->src_num > 1000000) {
                printf("error, more than 100W random src-ip is not supported\n");
                goto err;
            }
            curr->sip = (~curr->dip) & 0xff;    // dip: 0x44332211, sip: 0x000000ee
            i += 2;

        } else if (0 == strcmp("-s", argv[i]) && i+1 < argc) {
            // -s 8787
            curr->sport = strtol(argv[i+1], NULL, 10);
            i += 2;

        } else if (0 == strcmp("-d", argv[i]) && i+1 < argc) {
            // payload size
            curr->payload_size = strtol(argv[i+1], NULL, 10);
            if (curr->payload_size > 1200) {
                printf("error, payload larger than 1200 bytes is not supported\n");
                goto err;
            }
            i += 2;

        } else if (0 == strcmp("-f", argv[i])) {
            // is frag
            curr->is_frag = 1;
            if (curr->payload_size == 0) {
                curr->payload_size = 500;
            }
            i += 1;

        // below config will apply to per sflow pkt sample
        } else if (0 == strcmp("-r", argv[i]) && i+1 < argc) {
            // -r RATE
            g_var.pkt_sampling_rate = (u32) strtol(argv[i+1], NULL, 10);
            i += 2;

        } else if (0 == strcmp("-c", argv[i]) && i+1 < argc) {
			// -c 5
            g_var.round_to_send = (u32) strtol(argv[i+1], NULL, 10);
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
                goto err;
            }
            i += 2;

        } else if (0 == strcmp("--quiet", argv[i])) {
            // --quiet
            g_var.is_quiet = 1;
            i += 1;

        } else if (0 == strcmp("--test", argv[i])) {
            // --test
            g_var.is_test_arg = 1;
            i += 1;

        } else {
            printf("error, Unknow arg \"%s\"\n", argv[i]);
            goto err;
        }
        continue;

add_node:
        if (!curr->sip) {
             curr->sip = htonl(SRC_IP);
        }
        prev = curr;
        CALLOC_EXIT_ON_FAIL(PKT_NODE, curr, 0);
        prev->next = curr;
    } // while

    if (!head_node->dip) {
        printf("error, no dip\n");
        goto err;
    }
    return 0;

err:
    return -1;
}

void
sig_handler(int signal)
{
    printf("Catch signal\n");
    show_g_var();
}

static inline int
fill_sflow_hdr(struct sflow_hdr_t *sflow_hdr, int sample_num)
{
    sflow_hdr->version = htonl(VERSION);
    sflow_hdr->agent_addr_type = htonl(AGENT_ADDR_TYPE);
    inet_pton(AF_INET, AGENT_IP, &sflow_hdr->agent_addr);
    sflow_hdr->sub_agent_id = htonl(SUB_AGENT_ID);
    sflow_hdr->seq_num = htonl(HDR_SEQ_NUM);
    sflow_hdr->sys_uptime = htonl(SYS_UPTIME);
    sflow_hdr->sample_num = htonl(sample_num);

    int ret_len = (int) sizeof(struct sflow_hdr_t);
    return ret_len;
}

// make the header of the entire sflow pkt
static inline int
make_sflow_hdr(u8 **msg)
{
    struct sflow_hdr_t* sflow_hdr;
    CALLOC_EXIT_ON_FAIL(struct sflow_hdr_t, sflow_hdr, 0);

    sflow_hdr->version = htonl(VERSION);
    sflow_hdr->agent_addr_type = htonl(AGENT_ADDR_TYPE);
    inet_pton(AF_INET, AGENT_IP, &sflow_hdr->agent_addr);
    sflow_hdr->sub_agent_id = htonl(SUB_AGENT_ID);
    sflow_hdr->seq_num = htonl(HDR_SEQ_NUM);
    sflow_hdr->sys_uptime = htonl(SYS_UPTIME);
    sflow_hdr->sample_num = htonl(pkt_node_get_num(head_node));

    int ret_len = (int) sizeof(struct sflow_hdr_t);
    *msg = (u8*) sflow_hdr;
    return ret_len;
}

// make the header of a flow sample
static inline int
make_sflow_sample_hdr(struct sflow_sample_hdr_t* sflow_sample_hdr, int curr_len) 
{

    //struct sflow_sample_hdr_t* sflow_sample_hdr;
    //CALLOC_EXIT_ON_FAIL(struct sflow_sample_hdr_t, sflow_sample_hdr, 0);

    sflow_sample_hdr->sample_type = htonl(SAMPLE_TYPE);
    sflow_sample_hdr->sample_len = htonl(curr_len+(int)sizeof(struct sflow_sample_hdr_t)-8);
    sflow_sample_hdr->seq_num = htonl(SAMPLE_SEQ_NUM);
    sflow_sample_hdr->idx = htonl(IDX);
    sflow_sample_hdr->sample_rate = htonl(g_var.pkt_sampling_rate);
    sflow_sample_hdr->sample_pool = htonl(SAMPLING_POOL);
    sflow_sample_hdr->dropped_pkt = htonl(DROPPED_PKT);
    sflow_sample_hdr->input_intf = htonl(INPUT_INTF);
    sflow_sample_hdr->output_intf = htonl(OUTPUT_INTF);
    sflow_sample_hdr->flow_record = htonl(FLOW_RECORD);

    int ret_len = (int) sizeof(struct sflow_sample_hdr_t);
    //*msg = (u8*) sflow_sample_hdr;
    return ret_len;
}

 
// making the raw packet: eth + ip + icmp/udp/tcp
static int
make_raw_pkt(u8 *buf, PKT_NODE* node) 
{
    int sampled_pkt_payload_len = 0;
    switch (node->type) {
        case ICMP:
            sampled_pkt_payload_len = ICMPV4_HDR_LEN;
            break;

        case ICMPv6:
            sampled_pkt_payload_len = ICMPV6_HDR_LEN;

        case TCP:
            sampled_pkt_payload_len = TCP_HDR_LEN;
            break;

        case UDP:
            sampled_pkt_payload_len = UDP_HDR_LEN;
            break;

        default:
            // ASSERT_WARN
            break;
    }
    sampled_pkt_payload_len += node->payload_size;

    //u8 *ret;
    int ori_len = 0;
    //int padding_len = 0;
    //int ret_len = 0;

    u8 eth_data[] = { 0x00, 0x1c, 0x23, 0x9f, 0x15, 0x0b,
                        0x00, 0x19, 0xb9, 0xdd, 0xb2, 0x64,
                        0x08, 0x00 };

    /*
    struct ipv4_hdr_t* ipv4_hdr;
    struct ipv6_hdr_t* ipv6_hdr;
    struct icmpv4_hdr_t* icmpv4_hdr;
    struct icmpv6_hdr_t* icmpv6_hdr;
    struct udp_hdr_t* udp_hdr;
    struct tcp_hdr_t* tcp_hdr;
    */

    if (node->is_v6) {
        // make ipv6 header
        eth_data[12] = 0x86;
        eth_data[13] = 0xdd;

        memcpy(buf, eth_data, sizeof(eth_data));
        ori_len += sizeof(eth_data);

        //CALLOC_EXIT_ON_FAIL(struct ipv6_hdr_t, ipv6_hdr, 0);
        make_ipv6((struct ipv6_hdr_t*)(buf+ori_len), ICMPV6_HDR_LEN, node->type, node->sip6, node->dip6, node->is_frag);
        ori_len += IPV6_HDR_LEN;
    } else {
        // make ipv4 header
        memcpy(buf, eth_data, sizeof(eth_data));
        ori_len += sizeof(eth_data);
        //CALLOC_EXIT_ON_FAIL(struct ipv4_hdr_t, ipv4_hdr, 0);
        make_ipv4((struct ipv4_hdr_t*)(buf+ori_len), sampled_pkt_payload_len, node->type, node->sip, node->dip, node->is_frag);
        ori_len += IPV4_HDR_LEN;
    }

    // make l4 header
    switch (node->type) {
        case ICMP:
            //CALLOC_EXIT_ON_FAIL(struct icmpv4_hdr_t, icmpv4_hdr, 0);
            make_icmpv4((struct icmpv4_hdr_t*)(buf+ori_len));
            ori_len += ICMPV4_HDR_LEN;
            break;

        case ICMPv6:
            //CALLOC_EXIT_ON_FAIL(struct icmpv6_hdr_t, icmpv6_hdr, 0);
            make_icmpv6((struct icmpv6_hdr_t*)(buf+ori_len));
            ori_len += ICMPV6_HDR_LEN;
            break;

        case TCP:
            //CALLOC_EXIT_ON_FAIL(struct tcp_hdr_t, tcp_hdr, 0);
            make_tcp((struct tcp_hdr_t*)(buf+ori_len), node->sport, node->dport, node->tcp_flag, node->tcp_window_size);
            ori_len += TCP_HDR_LEN;
            break;

        case UDP:
            //CALLOC_EXIT_ON_FAIL(struct udp_hdr_t, udp_hdr, 0);
            make_udp((struct udp_hdr_t*)(buf+ori_len), node->sport, node->dport, node->payload_size);
            ori_len += UDP_HDR_LEN;
            break;

        default:
            // ASSERT_WARN
            break;
    }

    if (node->payload_size) {
        memset(buf+ori_len, 'x', node->payload_size);
        ori_len += node->payload_size;
    }
    return ori_len;

    // padding
    //if (ori_len % 4 != 0) {
    //    padding_len = (ori_len/4 +1)*4-ori_len;
    //}

    /*
    CALLOC_EXIT_ON_FAIL(u8, ret, (ori_len + padding_len));
    memcpy(ret, eth_data, sizeof(eth_data));
    ret_len += sizeof(eth_data);

    if (node->is_v6) {
        memcpy(ret+ret_len, (void*) ipv6_hdr, IPV6_HDR_LEN);
        ret_len += IPV6_HDR_LEN;
        free(ipv6_hdr);
    } else {
        memcpy(ret+ret_len, (void*) ipv4_hdr, IPV4_HDR_LEN);
        ret_len += IPV4_HDR_LEN;
        free(ipv4_hdr);
    }

    switch (node->type) {
        case ICMP:
            memcpy(ret+ret_len, (void*) icmpv4_hdr, ICMPV4_HDR_LEN);
            ret_len += ICMPV4_HDR_LEN;
            free(icmpv4_hdr);
            break;

        case ICMPv6:
            memcpy(ret+ret_len, (void*) icmpv6_hdr, ICMPV6_HDR_LEN);
            ret_len += ICMPV6_HDR_LEN;
            free(icmpv6_hdr);
            break;

        case TCP:
            memcpy(ret+ret_len, (void*) tcp_hdr, TCP_HDR_LEN);
            ret_len += TCP_HDR_LEN;
            free(tcp_hdr);
            break;

        case UDP:
            memcpy(ret+ret_len, (void*) udp_hdr, UDP_HDR_LEN);
            ret_len += UDP_HDR_LEN;
            free(udp_hdr);
            break;

        default:
            // ASSERT_WARN
            break;
    }
    
    memset(ret+ret_len, 'x', node->payload_size);
    ret_len += node->payload_size;

    *msg = ret;
    return ret_len;
    */
}

// make raw pkt header
static int
make_raw_pkt_hdr(struct raw_pkt_hdr_t* raw_pkt_hdr, int sampled_pkt_len, int padding_len) 
{
    //CALLOC_EXIT_ON_FAIL(struct raw_pkt_hdr_t, raw_pkt_hdr, 0);

    raw_pkt_hdr->format = htonl(1);
    raw_pkt_hdr->flow_data_len = htonl(sampled_pkt_len + padding_len +(int)sizeof(struct raw_pkt_hdr_t) - 8);
    raw_pkt_hdr->hdr_protocol = htonl(1);
    raw_pkt_hdr->frame_len = htonl(sampled_pkt_len);
    raw_pkt_hdr->payload_removed = htonl(0);
    raw_pkt_hdr->ori_pkt_len = htonl(sampled_pkt_len);
    
    return (int) sizeof(struct raw_pkt_hdr_t);
}

// main caller, making the sampled packet
static int
make_sflow_packet() 
{
    int raw_pkt_len = 0;
    u8 raw_pkt[1500];

    PKT_NODE* curr_node = head_node;

    struct raw_pkt_hdr_t raw_pkt_hdr;
    int raw_pkt_hdr_len = 0;
    int padding_len = 0;

    struct sflow_sample_hdr_t sflow_sample_hdr;
    int sflow_sample_hdr_len = 0;
    //int all_sample_len = 0;

    int msg_len;
    MSG_NODE *msg_node = head_msg_node;
    int curr_offset = (int)sizeof(struct sflow_hdr_t);
    int curr_src;

    while (curr_node) {  // for every node, make a sample
    
        curr_src = 0;

        while(curr_src < curr_node->src_num) {
            if (curr_node->src_num > 1) {
                curr_node->sip = htonl(ntohl(curr_node->sip)+1);
            }

            // make sampled pkt
            raw_pkt_len = make_raw_pkt(raw_pkt, curr_node);
            printf("raw_pkt_len: %d\n", raw_pkt_len);

            
            // calculate padding len
            if (raw_pkt_len % 4 != 0) {
                padding_len = (raw_pkt_len/4 +1)*4 -raw_pkt_len;
            }
            printf("padding_len: %d\n", padding_len);


            // make raw packet header
            raw_pkt_hdr_len = make_raw_pkt_hdr(&raw_pkt_hdr, raw_pkt_len, padding_len);
            printf("raw_pkt_hdr_len: %d\n", raw_pkt_hdr_len);


            // make sflow sample
            sflow_sample_hdr_len = make_sflow_sample_hdr(&sflow_sample_hdr, raw_pkt_len+raw_pkt_hdr_len+padding_len);
            printf("sflow_sample_hdr_len: %d\n", sflow_sample_hdr_len);


            // copy this sample to node->sample_ptr
            //curr_node->sample_len = sflow_sample_hdr_len+raw_pkt_hdr_len+raw_pkt_len+padding_len;
            //curr_node->sample_ptr = (u8*) calloc(1, curr_node->sample_len);
            
            msg_len = sflow_sample_hdr_len + raw_pkt_hdr_len + raw_pkt_len + padding_len;
            if (msg_node->len + msg_len >= 1460) {

                // fill sflow header for curr msg
                fill_sflow_hdr((struct sflow_hdr_t*) msg_node->data, msg_node->sample_num);
                printf("sflow_hdr_len: %d\n", (int)sizeof(struct sflow_hdr_t));
                g_var.pkt_node_count += msg_node->sample_num;
                g_var.msg_node_count += 1;

                // create new msg
                CALLOC_EXIT_ON_FAIL(MSG_NODE, msg_node->next, 0);
                msg_node = msg_node->next;
                msg_node->len = (int)sizeof(struct sflow_hdr_t);
                curr_offset = (int)sizeof(struct sflow_hdr_t);
            }

            memcpy(&msg_node->data[curr_offset], &sflow_sample_hdr, sflow_sample_hdr_len);  
            curr_offset += sflow_sample_hdr_len;
            //free(sflow_sample_hdr);
            memcpy(&msg_node->data[curr_offset], &raw_pkt_hdr, raw_pkt_hdr_len);  
            curr_offset += raw_pkt_hdr_len;
            //free(raw_pkt_hdr);
            memcpy(&msg_node->data[curr_offset], raw_pkt, raw_pkt_len);  
            curr_offset += (raw_pkt_len + padding_len);
            //free(raw_pkt);

            // before continue
            msg_node->len = curr_offset;
            msg_node->sample_num += 1;
            curr_src += 1;
        }
        /*
        curr_offset = 0;
        memcpy(curr_node->sample_ptr, sflow_sample_hdr, sflow_sample_hdr_len);
        curr_offset += sflow_sample_hdr_len;
        memcpy(curr_node->sample_ptr+curr_offset, raw_pkt_hdr, raw_pkt_hdr_len);
        curr_offset += raw_pkt_hdr_len;
        memcpy(curr_node->sample_ptr+curr_offset, raw_pkt, raw_pkt_len);
        */


        // before goto next
        //all_sample_len += curr_node->sample_len;
        curr_node = curr_node->next;
    }


    // fill sflow header for curr msg
    fill_sflow_hdr((struct sflow_hdr_t*) msg_node->data, msg_node->sample_num);
    printf("sflow_hdr_len: %d\n", (int)sizeof(struct sflow_hdr_t));
    g_var.pkt_node_count += msg_node->sample_num;
    g_var.msg_node_count += 1;


    /*
    // make sflow header
    int sflow_hdr_len = 0;
    u8* sflow_hdr;
    sflow_hdr_len = make_sflow_hdr(&sflow_hdr);
    printf("sflow_hdr_len: %d\n", sflow_hdr_len);


    // make sflow packet
    int sflow_pkt_len = all_sample_len + sflow_hdr_len;
    printf("sflow_pkt_len: %d\n", sflow_pkt_len);
    u8* ret = (u8*) calloc(1, sflow_pkt_len);

    curr_offset = 0;
    memcpy(ret, sflow_hdr, sflow_hdr_len);
    curr_offset += sflow_hdr_len;


    // copy all stuff into
    curr_node = head_node;
    while (curr_node) {
        memcpy(ret+curr_offset, curr_node->sample_ptr, curr_node->sample_len);
        curr_offset += curr_node->sample_len;
        curr_node = curr_node->next;
    }

    assert(curr_offset == sflow_pkt_len);

    *msg = ret;
    return curr_offset;
    */
    
    return 0;
}


// printer thread keep printing
static inline void*
print_pkt_node(void *arg)
{
    int finished_count = 0;
    PKT_NODE *curr_node = head_node;
    while (1) {
        if (finished_count == g_var.finished_pkt_node_count) {
            if (g_var.is_over) {
                break;
            } else {
                usleep(1000);
                continue;
            }
        }
        show_pkt_node(curr_node);
        finished_count += 1;
        curr_node = curr_node->next;
        if (!curr_node) {
            curr_node = head_node;
        }
    }
    return NULL;
}

int
main (int argc, char *argv[])
{    
    CALLOC_EXIT_ON_FAIL(PKT_NODE, head_node, 0);
    CALLOC_EXIT_ON_FAIL(MSG_NODE, head_msg_node, 0);
    
    if (0 != handle_argv(argc, argv)) {
        err_exit(PARSE_ARG_FAIL);
    }

    make_sflow_packet();

    show_g_var();

    if (g_var.is_test_arg) {
        printf("test arg parsing, exit\n");
        return 0;
    }

    signal(SIGQUIT, sig_handler);   // ctrl-\ shows current sending status

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

    // sending loop
    pthread_t printer = 0;
    if (!g_var.is_quiet) {
        pthread_create(&printer, NULL, print_pkt_node ,NULL);
    }

    // prepare to start
    MSG_NODE *msg_node = head_msg_node;
    g_var.is_running = 1;
    g_var.start_time = clock();

    while (1) {

        //ret = sendto(sockfd, (void*) msg, len, 0, (struct sockaddr*) &serv_addr, sizeof(serv_addr));
        while(msg_node) {
            ret = sendto(sockfd, (void*)msg_node->data, msg_node->len, 0, (struct sockaddr*) &serv_addr, sizeof(serv_addr));
            printf("%d samples, %d bytes has been sent\n", msg_node->sample_num, ret);
            if (ret < 0) {
                printf("strerror:%s\n", strerror(errno)); 
            }

            g_var.finished_pkt_node_count += msg_node->sample_num;
            msg_node = msg_node->next;
        }
        msg_node = head_msg_node;


        g_var.finished_round ++;
        if (g_var.round_to_send == -1 || g_var.finished_round < g_var.round_to_send) {
            usleep(g_var.interval);
        } else {
            break;
        }
    }

    g_var.end_time = clock();
    g_var.is_over = 1;

    close(sockfd);

    if (printer) {
        pthread_join(printer, NULL);
    }

    printf("######## Finished #########\n");
    show_g_var();
}
