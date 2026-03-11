# packet-sniffer

Low-level network traffic analyzer written in C. This tool supports live packet capture
via raw sockets and PCAP analysis.

## Features
- **PCAP Parsing**: Support for reading `.pcap` files with automatic endianess detection based on the packet's magic number.
- **Traffic Filtering**: Flags can be passed to filter by source/destination IP, port, MAC addresses or protocol.
- **Protocol Support**: Supports **Ethernet, IPv4, TCP and UDP** headers.

## Pre-requisites
- GCC Compiler
- GNU Make
- Linux Headers (for sockets, networking, etc);

## How to Compile
In the directory containing the source files, run `make`
For clean up, run `make clean`.
