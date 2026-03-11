#ifndef SNIFFER_H
#define SNIFFER_H
#include <inttypes.h>
#include <netinet/in.h>

typedef struct {
    uint32_t magic_number;
    uint16_t major_version;
    uint16_t minor_version;
    uint32_t reserved1;
    uint32_t reserved2;
    uint32_t snap_len;
    uint32_t link_type;
} pcap_header_t;

typedef struct {
    uint32_t ts_s;
    uint32_t ts_u;
    uint32_t captured_packet_len;
    uint32_t og_packet_len;
} packet_record_t;

#endif
