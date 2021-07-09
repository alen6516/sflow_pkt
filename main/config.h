#ifndef CONFIG_H
#define CONFIG_H

#define SRC_IP          0x141414a1         // 20.20.20.161
#define DST_IP          0x141465a2         // 20.20.101.162, deprecated
#define SRC_IPv6        "2001:1::161"
#define DST_IPv6        "2001:2::162"
#define SRC_PORT        9487
#define DST_PORT        8000

#define AGENT_IP        "20.20.20.161"
#define COLLECTOR_IP    "20.20.20.160"
#define SFLOW_PORT      6343
#define CHECKSUM        0x9487


// sflow_hdr fix value
#define VERSION         5
#define AGENT_ADDR_TYPE 1
#define SUB_AGENT_ID    1
#define HDR_SEQ_NUM     0x01a2
#define SYS_UPTIME      0x673e7f08


// sflow_sample_hdr fix value
#define SAMPLE_TYPE     1
#define SAMPLE_SEQ_NUM  6
#define IDX             1043          
#define SAMPLING_RATE   1000
#define SAMPLING_POOL   12288
#define DROPPED_PKT     0
#define INPUT_INTF      1048
#define OUTPUT_INTF     0x0413
#define FLOW_RECORD     1

#endif
