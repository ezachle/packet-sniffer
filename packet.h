#ifndef PACKET_H
#define PACKET_H
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <linux/if_ether.h>
#include <bits/types/FILE.h>
#include "sniffer.h"

typedef struct {
    uint8_t swap_needed;
    uint8_t use_ms;
} sniffer_ctx_t;

typedef struct {
    uint8_t t_protocol;
    char *src_ip;
    char *dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    char *src_if;
    char *dst_if;
    uint8_t src_mac[6];
    uint8_t dst_mac[6];
} packet_filter_t;

uint8_t filter_ip(packet_filter_t * pkt_filter);
uint8_t filter_port(uint8_t src_port, uint8_t dst_port, packet_filter_t * pkt_filter);
void get_mac_addr(char * if_name, packet_filter_t * pkt_filter, char * if_type);
void log_eth_headers(struct ethhdr * eth, FILE * lf);
void log_ip_header(struct iphdr * iph, FILE * lf);
void log_packet_record(packet_record_t * prt, FILE * lf);
void log_payload(uint8_t * buf, int buflen, int iphdrlen, uint8_t t_protocol, FILE * lf, struct tcphdr * tcp);
void log_pcap_header(pcap_header_t * pch, FILE * lf);
void log_tcp_header(struct tcphdr * tcp, FILE * lf);
void log_udp_header(struct udphdr * udp, FILE * lf);
uint8_t maccmp(uint8_t * a, uint8_t * b);
void process_packet(uint8_t * buf, int buf_len, packet_filter_t * pkt_filter, FILE * logfile);

void set_use_ms(int val);
void set_swap(int val);

#endif
