#include <stdio.h>
#include <memory.h>
#include <stdlib.h>
#include <getopt.h>
#include "packet.h"
#include "sniffer.h"

void usage(char *prog_name) {
    printf("Usage: %s [options]\n", prog_name);
    printf("Must be run with admin privileges to properly use\n");
    printf("\nOptions:\n");
    printf("  -s, --sip <ip>      Filter by Source IP\n");
    printf("  -d, --dip <ip>      Filter by Destination IP\n");
    printf("  -p, --sport <port>  Filter by Source Port\n");
    printf("  -o, --dport <port>  Filter by Destination Port\n");
    printf("  -i, --sif <iface>   Filter by Source Interface (MAC)\n");
    printf("  -t, --tcp           Filter for TCP packets only\n");
    printf("  -u, --udp           Filter for UDP packets only\n");
    printf("  -r, --pcap <file>   Read from PCAP file instead of live capture\n");
    printf("  -f, --logfile <file> Specify output log file (default: packet_sniffer_log.txt)\n");
    printf("  -h, --help          Show this help message\n");
    printf("\nExample:\n");
    printf("  sudo %s -i eth0 -t -p 80\n", prog_name);
    exit(EXIT_SUCCESS);
}

//#define DEBUG 1
#define exit_with_error(msg) do{ perror(msg); exit(EXIT_FAILURE);} while(0)
int main(int argc, char *argv[]) {
    int c;
    char pcap[255] = { '\0' };
    char log[255] = { '\0' };
    FILE *logfile = NULL;
    FILE *pcapfile = NULL;

    struct sockaddr saddr;
    int sockfd, saddr_len, bufflen;

    uint8_t *buf = (uint8_t*)malloc(65536);
    memset(buf, 0, 65536);

    packet_filter_t pkt_filter = { 0 };

    while(1) {
        static struct option long_options[] = {
            {"sip", required_argument, NULL, 's'},
            {"dip", required_argument, NULL, 'd'},
            {"sport", required_argument, NULL, 'p'},
            {"dport", required_argument, NULL, 'o'},
            {"sif", required_argument, NULL, 'i'},
            {"dif", required_argument, NULL, 'g'},
            {"logfile", required_argument, NULL, 'f'},
            {"tcp", no_argument, NULL, 't'},
            {"udp", no_argument, NULL, 'u'},
            {"pcap", required_argument, NULL, 'r'},
            {"help", no_argument, NULL, 'h'},
        };

        c = getopt_long(argc, argv, "tus:d:p:o:i:g:f:r:", long_options, NULL);
        
        if(c == -1) {
            break;
        }

        switch(c) {
            case 't':
                pkt_filter.t_protocol = IPPROTO_TCP;
                break;
            case 'u':
                pkt_filter.t_protocol = IPPROTO_UDP;
                break;
            case 'p':
                pkt_filter.src_port = atoi(optarg);
                break;
            case 'o':
                pkt_filter.dst_port = atoi(optarg);
                break;
            case 's':
                pkt_filter.src_ip = optarg;
                break;
            case 'd':
                pkt_filter.dst_ip = optarg;
                break;
            case 'i':
                pkt_filter.src_if = optarg;
                break;
            case 'g':
                pkt_filter.dst_if = optarg;
                break;
            case 'f':
                strncpy(log, optarg, strlen(optarg));
                break;
            case 'r':
                strncpy(pcap, optarg, strlen(optarg));
                break;
            case 'h':
            default:
                usage(argv[0]);
                exit(EXIT_SUCCESS);
        }
    }

    // ETH_P_ALL is a bitmask for filtering ALL packets
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(sockfd < 0)
        exit_with_error("socket() error");

    if(log[0] == 0) {
        char *t = "packet_sniffer_log.txt";
        strncpy(log, t, strnlen(t, 22));
    }

    if(pcap[0] != 0) {
        pcapfile = fopen(pcap, "rb");
    }

    logfile = fopen(log, "w");
    if(!logfile) {
        exit_with_error("fopen() error");
    }

    if(pkt_filter.src_if != NULL) {
        get_mac_addr(pkt_filter.src_if, &pkt_filter, "source");
    }

    if(pkt_filter.dst_if != NULL) {
        get_mac_addr(pkt_filter.dst_if, &pkt_filter, "dest");
    }

#ifdef DEBUG
    printf("t_protocol: %d\n", pkt_filter.t_protocol);
    printf("src port: %d\n", pkt_filter.src_port);
    printf("dst_port: %d\n", pkt_filter.dst_port) ;
    printf("src ip: %s\n", pkt_filter.src_ip);
    printf("dst_ip: %s\n", pkt_filter.dst_ip);
    printf("src interface: %s\n", pkt_filter.src_if);
    printf("dst interface: %s\n", pkt_filter.dst_if) ;
    printf("log file: %s\n", log);
#endif

    if(pcap[0] != 0) {
        pcap_header_t pch;
        packet_record_t *prt;
        
        fprintf(logfile, "Begin Parsing of PCAP\n");

        fread(&pch, sizeof(pcap_header_t), 1, pcapfile);
        log_pcap_header(&pch, logfile) ;
        fprintf(logfile, "\n===========================\n");

        if(pch.magic_number == 0xA1B23C4D) {
            set_use_ms(0);
        } else if(pch.magic_number == 0xA1B2C3D4) {
            set_use_ms(1);
        }
        
        if(pch.magic_number == 0xD4C32B1A) {
            set_swap(1);
        } else if(pch.magic_number == 0x4D3C2B1A) {
            set_swap(1);
            set_use_ms(1);
        }

        while(fread(buf, sizeof(packet_record_t), 1, pcapfile) > 0) {
            prt = (packet_record_t*)buf;
            int offset = prt->captured_packet_len;
            log_packet_record(prt, logfile);

            fread(buf, prt->captured_packet_len, 1, pcapfile);
            process_packet(buf,  offset, &pkt_filter, logfile);
            fprintf(logfile, "\n===========================\n");
            fflush(logfile);
        }
    } else {
        while(1) {
            saddr_len = sizeof(struct sockaddr_in);
            bufflen = recvfrom(sockfd, buf, 65536, 0, &saddr, (socklen_t*)&saddr_len);
            if(bufflen < 0) {
                exit_with_error("recvfrom() error");
            }

            process_packet(buf, bufflen, &pkt_filter, logfile);

            fprintf(logfile, "\n===========================\n");
            fflush(logfile);
        }
    }


    free(buf);

    return 0;
}
