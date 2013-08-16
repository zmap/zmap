/*
 * ZMap Copyright 2013 Regents of the University of Michigan 
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

// probe module for performing ICMP echo request (ping) scans

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <string.h>

#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "probe_modules.h"
#include "packet.h"
#include "validate.h"

probe_module_t module_icmp_echo;

int icmp_echo_init_perthread(void* buf, macaddr_t *src,
		macaddr_t *gw, __attribute__((unused)) port_h_t dst_port)
{
	memset(buf, 0, MAX_PACKET_SIZE);

	struct ethhdr *eth_header = (struct ethhdr *)buf;
	make_eth_header(eth_header, src, gw);

	struct iphdr *ip_header = (struct iphdr*)(&eth_header[1]);
	uint16_t len = htons(sizeof(struct iphdr) + sizeof(struct icmp) - 8);
	make_ip_header(ip_header, IPPROTO_ICMP, len);

	struct icmp *icmp_header = (struct icmp*)(&ip_header[1]);
	make_icmp_header(icmp_header);

	return EXIT_SUCCESS;
}

int icmp_echo_make_packet(void *buf, ipaddr_n_t src_ip, ipaddr_n_t dst_ip,
				uint32_t *validation, __attribute__((unused))int probe_num)
{
	struct ethhdr *eth_header = (struct ethhdr *)buf;
	struct iphdr *ip_header = (struct iphdr*)(&eth_header[1]);
	struct icmp *icmp_header = (struct icmp*)(&ip_header[1]);
	uint16_t icmp_idnum = validation[2] & 0xFFFF;

	ip_header->saddr = src_ip;
	ip_header->daddr = dst_ip;

	icmp_header->icmp_id = icmp_idnum;
	icmp_header->icmp_cksum = 0;
	icmp_header->icmp_cksum = icmp_checksum((unsigned short *) icmp_header);

	ip_header->check = 0;
	ip_header->check = ip_checksum((unsigned short *) ip_header);

	return EXIT_SUCCESS;
}

void icmp_echo_print_packet(FILE *fp, void* packet)
{
	struct ethhdr *ethh = (struct ethhdr *) packet;
	struct iphdr *iph = (struct iphdr *) &ethh[1];
	struct icmp *icmp_header = (struct icmp*)(&iph[1]);

	fprintf(fp, "icmp { type: %u | code: %u "
			"| checksum: %u | id: %u | seq: %u }\n",
			icmp_header->icmp_type,
			icmp_header->icmp_code,
			ntohs(icmp_header->icmp_cksum),
			ntohs(icmp_header->icmp_id),
			ntohs(icmp_header->icmp_seq));
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

response_type_t* icmp_echo_classify_packet(const u_char *packet, uint32_t len)
{
	(void)len;
	struct iphdr *ip_hdr = (struct iphdr *)&packet[sizeof(struct ethhdr)];
	struct icmp *icmp_hdr = (struct icmp*)((char *)ip_hdr
					+ sizeof(struct iphdr)); 
	switch (icmp_hdr->icmp_type) {
		case ICMP_ECHOREPLY:
			return &(module_icmp_echo.responses[0]);
		case ICMP_UNREACH: 
			return &(module_icmp_echo.responses[1]);
		case ICMP_SOURCEQUENCH:
			return &(module_icmp_echo.responses[2]);
		case ICMP_REDIRECT:
			return &(module_icmp_echo.responses[3]);
		case ICMP_TIMXCEED:
			return &(module_icmp_echo.responses[4]);
		default:
			return &(module_icmp_echo.responses[5]);
	}
}

int icmp_validate_packet(const struct iphdr *ip_hdr, uint32_t len, uint32_t *src_ip, uint32_t *validation)
{
	if (ip_hdr->protocol != IPPROTO_ICMP) {
		return 0;
	}
	
	if ((4*ip_hdr->ihl + sizeof(struct icmphdr)) > len) {
		// buffer not large enough to contain expected icmp header 
		return 0;
	}
	
	struct icmphdr *icmp_h = (struct icmphdr*)((char *)ip_hdr + 4*ip_hdr->ihl);
	uint16_t icmp_idnum = icmp_h->un.echo.id;

	// ICMP validation is tricky: for some packet types, we must look inside 
	// the payload
	if (icmp_h->type == ICMP_TIME_EXCEEDED || icmp_h->type == ICMP_DEST_UNREACH) {
		if ((4*ip_hdr->ihl + sizeof(struct icmphdr) +
			sizeof(struct iphdr)) > len) {
			return 0;
		}
		struct iphdr *ip_inner = (struct iphdr *)(icmp_h + 1);
		if ((4*ip_hdr->ihl + sizeof(struct icmphdr) +
				4*ip_inner->ihl + sizeof(struct icmphdr)) > len) {
			return 0;
		}
		struct icmphdr *icmp_inner = (struct icmphdr*)((char *)ip_inner + 4 *ip_hdr->ihl);

		// Regenerate validation and icmp id based off inner payload
		icmp_idnum = icmp_inner->un.echo.id;
		*src_ip = ip_inner->daddr;
		validate_gen(ip_hdr->daddr, ip_inner->daddr, (uint8_t *)validation);
	} 

	// validate icmp id
	if (icmp_idnum != (validation[2] & 0xFFFF)) {
		return 0;
	}

	return 1;
}

static response_type_t responses[] = {
	{
		.name = "echoreply",
		.is_success = 1	
	},
	{
		.name = "unreach",
		.is_success = 0
	},
	{
		.name = "sourcequench",
		.is_success = 0
	},
	{
		.name = "redirect",
		.is_success = 0
	},
	{
		.name = "timxceed",
		.is_success = 0
	},
	{
		.name = "other",
		.is_success = 0
	}
};

probe_module_t module_icmp_echo = {
	.name = "icmp_echoscan",
	.packet_length = 62,
	.pcap_filter = "icmp and icmp[0]!=8",
	.pcap_snaplen = 96,
	.port_args = 0,
	.thread_initialize = &icmp_echo_init_perthread,
	.make_packet = &icmp_echo_make_packet,
	.print_packet = &icmp_echo_print_packet,
	.classify_packet = &icmp_echo_classify_packet,
	.validate_packet = &icmp_validate_packet,
	.close = NULL,
	.responses = responses
};

