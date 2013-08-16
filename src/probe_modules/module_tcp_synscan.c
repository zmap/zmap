/*
 * ZMap Copyright 2013 Regents of the University of Michigan 
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

// probe module for performing TCP SYN scans 

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "probe_modules.h"
#include "packet.h"

probe_module_t module_tcp_synscan;
uint32_t num_ports = 1;

int synscan_init_perthread(void* buf, macaddr_t *src,
		macaddr_t *gw, port_h_t dst_port)
{
	memset(buf, 0, MAX_PACKET_SIZE);
	struct ethhdr *eth_header = (struct ethhdr *)buf;
	make_eth_header(eth_header, src, gw);
	struct iphdr *ip_header = (struct iphdr*)(&eth_header[1]);
	uint16_t len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
	make_ip_header(ip_header, IPPROTO_TCP, len);
	struct tcphdr *tcp_header = (struct tcphdr*)(&ip_header[1]);
	make_tcp_header(tcp_header, dst_port);
	num_ports = zconf.source_port_last - zconf.source_port_first + 1;
	return EXIT_SUCCESS;
}

int synscan_make_packet(void *buf, ipaddr_n_t src_ip, ipaddr_n_t dst_ip,
		uint32_t *validation, int probe_num)
{
	struct ethhdr *eth_header = (struct ethhdr *)buf;
	struct iphdr *ip_header = (struct iphdr*)(&eth_header[1]);
	struct tcphdr *tcp_header = (struct tcphdr*)(&ip_header[1]);
	uint16_t src_port = zconf.source_port_first 
					+ ((validation[1] + probe_num) % num_ports);
	uint32_t tcp_seq = validation[0];
	

	ip_header->saddr = src_ip;
	ip_header->daddr = dst_ip;

	tcp_header->source = htons(src_port);
	tcp_header->seq = tcp_seq;
	tcp_header->check = 0;
	tcp_header->check = tcp_checksum(sizeof(struct tcphdr),
			ip_header->saddr, ip_header->daddr, tcp_header);

	ip_header->check = 0;
	ip_header->check = ip_checksum((unsigned short *) ip_header);

	return EXIT_SUCCESS;
}

void synscan_print_packet(FILE *fp, void* packet)
{
	struct ethhdr *ethh = (struct ethhdr *) packet;
	struct iphdr *iph = (struct iphdr *) &ethh[1];
	struct tcphdr *tcph = (struct tcphdr *) &iph[1];
	fprintf(fp, "tcp { source: %u | dest: %u | seq: %u | checksum: %u }\n",
			ntohs(tcph->source),
			ntohs(tcph->dest),
			ntohl(tcph->seq),
			ntohl(tcph->check));
	struct in_addr *s = (struct in_addr *) &(iph->saddr);
	struct in_addr *d = (struct in_addr *) &(iph->daddr);
	char srcip[20];
	char dstip[20];
	// inet_ntoa is a const char * so we if just call it in
	// fprintf, you'll get back wrong results since we're
	// calling it twice.
	strncpy(srcip, inet_ntoa(*s), 19);
	strncpy(dstip, inet_ntoa(*d), 19);
	fprintf(fp, "ip { saddr: %s | daddr: %s | checksum: %u }\n",
			srcip,
			dstip,
			ntohl(iph->check));
	fprintf(fp, "eth { shost: %02x:%02x:%02x:%02x:%02x:%02x | "
			"dhost: %02x:%02x:%02x:%02x:%02x:%02x }\n",
			(int) ((unsigned char *) ethh->h_source)[0],
			(int) ((unsigned char *) ethh->h_source)[1],
			(int) ((unsigned char *) ethh->h_source)[2],
			(int) ((unsigned char *) ethh->h_source)[3],
			(int) ((unsigned char *) ethh->h_source)[4],
			(int) ((unsigned char *) ethh->h_source)[5],
			(int) ((unsigned char *) ethh->h_dest)[0],
			(int) ((unsigned char *) ethh->h_dest)[1],
			(int) ((unsigned char *) ethh->h_dest)[2],
			(int) ((unsigned char *) ethh->h_dest)[3],
			(int) ((unsigned char *) ethh->h_dest)[4],
			(int) ((unsigned char *) ethh->h_dest)[5]);
	fprintf(fp, "------------------------------------------------------\n");
}

response_type_t* synscan_classify_packet(const u_char *packet, uint32_t len)
{
	(void)len;
	struct iphdr *ip_hdr = (struct iphdr *)&packet[sizeof(struct ethhdr)];
	struct tcphdr *tcp = (struct tcphdr*)((char *)ip_hdr 
					+ (sizeof(struct iphdr)));
	if (tcp->rst) { // RST packet
			return &(module_tcp_synscan.responses[1]);
	} else { // SYNACK packet
			return &(module_tcp_synscan.responses[0]);
	}
}
// Returns 0 if dst_port is outside the expected valid range, non-zero otherwise
static inline int check_dst_port(uint16_t port, uint32_t *validation)
{
	if (port > zconf.source_port_last 
					|| port < zconf.source_port_first) {
		return EXIT_FAILURE;
	}
	int32_t to_validate = port - zconf.source_port_first;
	int32_t min = validation[1] % num_ports;
	int32_t max = (validation[1] + zconf.packet_streams - 1) % num_ports;

	return (((max - min) % num_ports) >= ((to_validate - min) % num_ports));
}

int synscan_validate_packet(const struct iphdr *ip_hdr, uint32_t len, 
				__attribute__((unused))uint32_t *src_ip, uint32_t *validation)
{
	if (ip_hdr->protocol != IPPROTO_TCP) {
		return 0;
	}

	if ((4*ip_hdr->ihl + sizeof(struct tcphdr)) > len) {
		// buffer not large enough to contain expected tcp header 
		return 0;
	}
	struct tcphdr *tcp = (struct tcphdr*)((char *)ip_hdr + 4*ip_hdr->ihl);
	uint16_t sport = tcp->source;
	uint16_t dport = tcp->dest;

	// validate source port
	if (ntohs(sport) != zconf.target_port) {
		return 0;
	}

	// validate destination port
	if (!check_dst_port(ntohs(dport), validation)) {
		return 0;
	}

	// validate tcp acknowledgement number
	if (htonl(tcp->ack_seq) != htonl(validation[0])+1) {
		return 0;
	}
	
	return 1;
}

static response_type_t responses[] = {
	{
		.is_success = 1,	
		.name = "synack"
	},
	{
		.is_success = 0,
		.name = "rst"
	}
};

probe_module_t module_tcp_synscan = {
	.name = "tcp_synscan",
	.packet_length = 54,
	.pcap_filter = "tcp && tcp[13] & 4 != 0 || tcp[13] == 18",
	.pcap_snaplen = 96,
	.port_args = 1,
	.thread_initialize = &synscan_init_perthread,
	.make_packet = &synscan_make_packet,
	.print_packet = &synscan_print_packet,
	.classify_packet = &synscan_classify_packet,
	.validate_packet = &synscan_validate_packet,
	.close = NULL,
	.responses = responses,
};

