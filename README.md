1. modify agent ip and collector ip in config.h
2. gcc main.c
3. test by ./a.out
4. argu:
    -i 20.20.1.1
        add an icmp packet with dst ip = 20.20.1.1

    -u 20.20.1.1 8787
        add an udp packet with dst ip = 20.20.1.1, dst port = 8787

    -t 20.20.1.1 8787
        add an tcp packet with dst ip = 20.20.1.1, src ip = 8.8.8.8, dst port = 8787

    -a SRC_IP
        spoof src ip

    -c NUM
        set how many rouds you want to send this sflow packet
        0 means don't stop

    -I SEC
        set how many seconds is the interval between each round.

    --test
        just test argument parsing result and exit

5. example
    ./a.out -i 1.1.1.1 -a 2.2.2.2 -u 3.3.3.3 8787 -a 4.4.4.4 -c 3 -I 5
