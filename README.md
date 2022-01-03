# Usage
1. modify agent ip and collector ip in config.h
2. make under main/
3. test by ./a.out
4. argument:

* Gerneral:
    --test
        just test argument parsing result and exit

    -d PAYLOAD_SIZE
        specify the payload size of the packet, now only support up to 1200

    -f
        mark the packet is a fragment packet, now only support ipv4

    -a SRC_IP
        specify the src ip, default is 20.20.101.162 or 2001:2:162

    -aN NUMBER_OF_RANDOM_SRC_IP
        specify the number of src ip, default is 1, and now only support up to 100w src ip

    -s SRC_PORT
        specify the src port of a tcp/udp packet, default is 9487

* ICMP

    -i 20.20.1.1
        add an icmp packet with dst ip = 20.20.1.1

    -i6 2001:1::162
        add an icmpv6 packet with dsp ipv4 = 2001:1::162

* UDP

    -u 20.20.1.1 8787
        add an udp packet with dst ip = 20.20.1.1, dst port = 8787

    -u6 2001:1::162 8787
        add an udp packet with dst ipv6 = 2001:1::162, dst port = 8787

* TCP

    -t 20.20.1.1 8787
        add an tcp packet with dst ip = 20.20.1.1, dst port = 8787

    -t6 2001:1::162 8787
        add an tcp packet with dst ipv6 = 2001:1::162, dst port = 8787

    --flag FA
        specify the tcp flag of a tcp packet, support ACK(A), SYN(Y), FIN(F), RST(R) now

    -w TCP_WINDOW_SIZE
        specify the tcp window size of a tcp packet

* Apply to all packet

    -r SAMPLING_RATE, default is 1000
        specify the sampling-rate of the sflow sample packet

    -c NUM
        set how many rouds you want to send this sflow packet
        0 means don't stop

    -I SEC/uMSEC
        set how many seconds is the interval between each round.

    --quiet
        silent mode, don't print log

5. use ctrl-\ to check current status when program is running

# Example
* generate example
./a.out -i 20.20.101.162 -a 20.20.20.1 -r 1000 -I 5 -c 3
    * send a icmpv4 sflow sample with
    * dst ip = 20.20.101.162
    * src ip = 20.20.20.1
    * sampling-rate is 1000
    * send every 5 seconds
    * totally send 3 times

./a.out -i6 2001:1::161
    * send a icmpv6 sflow sample with
    * dst ipv6 = 2001:1::161
    * src ipv6 = 2001:2::162 (default)
    * sampling-rate is 1000 (default)
    * send every 1 second (default)
    * totally send infinite times (default)

./a.out -u 20.20.101.162 9000 -a 20.20.20.1 -f -r 1000 -I u500000 -c 10
    * send a udp fragmented sflow sample with
    * dst ip = 20.20.101.162
    * src ip = 20.20.20.1
    * dst port = 9000
    * src port = 8787 (default)
    * sampling-rate is 1000
    * send every 500000 msec
    * totally send 10 times

./a.out -u6 2001:1::161 9000 -a 2001:2::87 -s 9487 -d 500
    * send a udp sflow sample with
    * dst ipv6 = 2001:1::161
    * src ipv6 = 2001:2::162 (default)
    * dst port = 9000
    * src port = 9487
    * payload is 500 bytes
    * sampling-rate is 1000 (default)
    * send every 1 second (default)
    * totally send infinite times (default)


./a.out -t 20.20.101.162 8000 -a 20.20.20.1 --flag SA
    * send a udp fragmented sflow sample with
    * dst ip = 20.20.101.162
    * src ip = 20.20.20.1
    * dst port = 8000
    * src port = 8787 (default)
    * tcp flags is SYN,ACK
    * sampling-rate is 1000 (default)
    * send every 1 sec (default)
    * totally send infinite times (default)

./a.out -t6 2001:1::161 8000 -a 2001:2::87 -s 9487 -w 0
    * send a udp sflow sample with
    * dst ipv6 = 2001:1::161
    * src ipv6 = 2001:2::87
    * dst port = 8000
    * src port = 9487
    * tcp window size is 0
    * tcp flags is none (default)
    * sampling-rate is 1000 (default)
    * send every 1 second (default)
    * totally send infinite times (default)

* random src example
./a.out -u 20.20.101.162 9000 -aN 1000000
    * send a udp sflow sample with
    * dst ip = 20.20.101.162
    * src ip is random, start from 
    * dst port = 9000
    * src port = 8787 (default)
    * sampling-rate is 1000
    * send every 500000 msec
    * totally send 10 times

# Todo
* log is not correct when using -aN
