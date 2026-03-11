#include <stdio.h>
#include <inttypes.h>
#include <stddef.h>
#include <memory.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <byteswap.h>

#include <arpa/inet.h>
#include "packet.h"

sniffer_ctx_t snfx;
struct sockaddr_in src_addr, dst_addr;

void set_use_ms(int val ) { snfx.use_ms = val; };
void set_swap(int val) { snfx.swap_needed = val; };

// Byte swap functions only applicable to the Packet and IP Header
// Actual packet data is not affected
uint16_t read_u16(uint16_t val) {
    return snfx.swap_needed ? bswap_16(val) : val;
}

uint32_t read_u32(uint32_t val) {
    return snfx.swap_needed ? bswap_32(val) : val;
}

void get_mac_addr(char *if_name, packet_filter_t *pkt_filter, char *if_type) {
    int fd;
    struct ifreq idr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    idr.ifr_addr.sa_family = AF_INET;
    strncpy(idr.ifr_name, if_name, IFNAMSIZ - 1);

    ioctl(fd, SIOCGIFHWADDR, &idr);
    close(fd);

    if(strcmp("source", if_type) == 0) {
        //strcpy(pkt_filter->src_mac, (uint8_t*)idr.ifr_hwaddr.sa_data);
        memcpy(pkt_filter->src_mac, idr.ifr_hwaddr.sa_data, 14);
    } else {
        //strcpy(pkt_filter->dst_mac, (uint8_t*)idr.ifr_hwaddr.sa_data);
        memcpy(pkt_filter->dst_mac, idr.ifr_hwaddr.sa_data, 14);
    }
}

uint8_t maccmp(uint8_t *a, uint8_t *b) {
    return !memcmp(a, b, 6);
}

uint8_t filter_ip(packet_filter_t *pkt_filter) {
    char *src = inet_ntoa(src_addr.sin_addr);
    char *dst = inet_ntoa(dst_addr.sin_addr);
    if(pkt_filter->src_ip != NULL && strcmp(pkt_filter->src_ip, src) != 0) {
        return 0;
    }

    if(pkt_filter->dst_ip != NULL && strcmp(pkt_filter->dst_ip, dst) != 0) {
        return 0;
    }

    return 1;
}

uint8_t filter_port(uint8_t src_port, uint8_t dst_port, packet_filter_t *pkt_filter) {
#ifdef DEBUG
    printf("Source Port: %d %d\n", src_port, pkt_filter->src_port);
    printf("dest Port: %d %d\n", dst_port, pkt_filter->dst_port);
#endif
    if(pkt_filter->src_port == 0 && pkt_filter->dst_port == 0) return 1;
    if(src_port != 0 && pkt_filter->src_port != src_port) {
        return 0;
    }

    if(dst_port != 0 && pkt_filter->dst_port != dst_port) {
        return 0;
    }
    return 1;
}

void log_pcap_header(pcap_header_t *pch, FILE *lf) {
    fprintf(lf, "\nPCAP Header\n");
    fprintf(lf, "    Magic Number: %" PRIu32, read_u32(pch->magic_number));
    fprintf(lf, "\n    Major Version: %" PRIu16, read_u16(pch->major_version));
    fprintf(lf, "\n    Minor Version: %" PRIu16, read_u16(pch->minor_version));
    fprintf(lf, "\n    Snap Length: %" PRIu32, read_u32(pch->snap_len));
    fprintf(lf, "\n    Link Type: %" PRIu32, read_u32(pch->link_type));
}

void log_packet_record(packet_record_t *prt, FILE *lf) {
    time_t t = read_u32(prt->ts_s);
    struct tm *x = gmtime(&t);
    fprintf(lf, "\nPCAP Packet Record");
    fprintf(lf, "\n    Timestamp: %d-%d-%d %d:%d:%d GMT", x->tm_mon, x->tm_mday, x->tm_year + 1900, x->tm_hour, x->tm_min, x->tm_sec);
    fprintf(lf, "\n    Timestamp(%s): %" PRIu32, snfx.use_ms ? "ms" : "ns", read_u32(prt->ts_u));
    fprintf(lf, "\n    Captured Packet Len: %" PRIu32, read_u32(prt->captured_packet_len));
    fprintf(lf, "\n    Original Packet Len: %" PRIu32, read_u32(prt->og_packet_len));
}

void log_eth_headers(struct ethhdr *eth, FILE *lf) {
    fprintf(lf, "\nEthernet Header\n");
    fprintf(lf, "    Source MAC %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",
                eth->h_source[0],
                eth->h_source[1],
                eth->h_source[2],
                eth->h_source[3],
                eth->h_source[4],
                eth->h_source[5]);

    fprintf(lf, "    Destination MAC %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",
                eth->h_dest[0],
                eth->h_dest[1],
                eth->h_dest[2],
                eth->h_dest[3],
                eth->h_dest[4],
                eth->h_dest[5]);

    fprintf(lf, "    Protocol: %d\n", ntohs(eth->h_proto));
}

void log_ip_header(struct iphdr *iph, FILE *lf) {
    fprintf(lf, "IP Header\n");
    fprintf(lf, "    Internet Header Length: %d\n", iph->ihl * 4);
    fprintf(lf, "    Version: %d\n", iph->version);
    fprintf(lf, "    Type of Service: %" PRIu8, iph->tos);
    fprintf(lf, "\n    Total Length: %" PRIu16, ntohs(iph->tot_len));
    fprintf(lf, "\n    Identification: %" PRIu16, iph->id);
    fprintf(lf, "\n    Fragmentation: %" PRIu16, iph->frag_off);
    fprintf(lf, "\n    Time to Live: %" PRIu8, iph->ttl);
    fprintf(lf, "\n    Protocol: %" PRIu8, iph->protocol);
    fprintf(lf, "\n    IP Checksum: %" PRIu16, ntohs(iph->check));
    fprintf(lf, "\n    Source Addr: %s", inet_ntoa(src_addr.sin_addr));
    fprintf(lf, "\n    Destination Addr: %s", inet_ntoa(dst_addr.sin_addr));
}

void log_tcp_header(struct tcphdr *tcp, FILE *lf) {
    fprintf(lf, "\nTCP Header\n");
    fprintf(lf, "    Source Port: %d\n", ntohs(tcp->source));
    fprintf(lf, "    Destination Port: %d\n", ntohs(tcp->dest));
    fprintf(lf, "    Sequence Number: %d\n", ntohl(tcp->source));
    fprintf(lf, "    Acknowledgement Number: %d\n", ntohl(tcp->ack_seq));
    fprintf(lf, "======FLAGS======\n");
    fprintf(lf, "      URG %d\n", tcp->urg);
    fprintf(lf, "      ACK %d\n", tcp->ack);
    fprintf(lf, "      PSH %d\n", tcp->psh);
    fprintf(lf, "      RST %d\n", tcp->rst);
    fprintf(lf, "      SYN %d\n", tcp->syn);
    fprintf(lf, "      FIN %d\n", tcp->fin);
    fprintf(lf, "    Window Size: %d\n", ntohs(tcp->window));
    fprintf(lf, "    TCP Checksum: %d\n", ntohs(tcp->check));
    fprintf(lf, "    Urgent Pointer: %d\n", ntohs(tcp->urg_ptr));
}

void log_udp_header(struct udphdr *udp, FILE *lf) {
    fprintf(lf, "\nUDP Header\n");
    fprintf(lf, "    Source Port: %d\n", ntohs(udp->source));
    fprintf(lf, "    Destination Port: %d\n", ntohs(udp->dest));
    fprintf(lf, "    UDP Length: %d\n", ntohs(udp->len));
    fprintf(lf, "    UDP Checksum: %d\n", ntohs(udp->len));
}

void log_payload(uint8_t *buf, int buflen, int iphdrlen, uint8_t t_protocol, FILE *lf, struct tcphdr *tcp) {
    uint32_t t_protocol_header_size = sizeof(struct udphdr);
    if(t_protocol == IPPROTO_TCP) {
        t_protocol_header_size = (uint32_t)tcp->doff * 4;
    }

    int offset = sizeof(struct ethhdr) + iphdrlen + t_protocol_header_size;
    uint8_t *pkt_data = buf + offset;
    int remaining = buflen - offset;

    fprintf(lf, "\nPayload (%d bytes)\n", remaining);
    for(int i = 0; i < remaining; i++) {
        if(i != 0 && i % 16 == 0) {
            fprintf(lf, "\n");
        }
        fprintf(lf, " %02X", pkt_data[i]);
    }
}

void process_packet(uint8_t *buf, int buf_len, packet_filter_t *pkt_filter, FILE *logfile) {
    int iphdrlen;
    struct ethhdr *eth = (struct ethhdr*)buf;
    if(ntohs(eth->h_proto) != ETH_P_IP) {
        return;
    }

    if(pkt_filter->src_if != NULL && maccmp(pkt_filter->src_mac, eth->h_source) == 0) {
        return;
    }

    if(pkt_filter->dst_if != NULL && maccmp(pkt_filter->dst_mac, eth->h_dest) == 0) {
        return;
    }

    struct iphdr *iph = (struct iphdr*)(buf + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4; // * 4 because a DWORD is 32 bytes
    
    memset(&src_addr, 0, sizeof(src_addr));
    memset(&dst_addr, 0, sizeof(dst_addr));

    src_addr.sin_addr.s_addr = iph->saddr;
    dst_addr.sin_addr.s_addr = iph->daddr;

    if(filter_ip(pkt_filter) == 0) {
        return;
    }

    if(pkt_filter->t_protocol != 0 && pkt_filter->t_protocol != iph->protocol) {
        return;
    }

    struct tcphdr *tcp = NULL;
    struct udphdr *udp = NULL;
    if(iph->protocol == IPPROTO_TCP) {
        tcp = (struct tcphdr*)(buf + iphdrlen + sizeof(struct ethhdr));
        if(filter_port(ntohs(tcp->source), ntohs(tcp->dest), pkt_filter) == 0) {
            return;
        }
    } else if(iph->protocol == IPPROTO_UDP) {
        udp = (struct udphdr*)(buf + iphdrlen + sizeof(struct ethhdr));
        if(filter_port(ntohs(udp->source), ntohs(udp->dest), pkt_filter) == 0) {
            return;
        }
    } else { return; }

    log_eth_headers(eth, logfile);
    log_ip_header(iph, logfile);

    if(tcp != NULL)
        log_tcp_header(tcp, logfile);

    if(udp != NULL)
        log_udp_header(udp, logfile);

    log_payload(buf, buf_len, iphdrlen, iph->protocol, logfile, tcp);
}

