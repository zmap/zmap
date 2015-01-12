/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

// probe module for performing ARP scans

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <string.h>

#include "../../lib/includes.h"
#include "probe_modules.h"
#include "../fieldset.h"
#include "packet.h"
#include "validate.h"

probe_module_t module_arp;

#define ARPHRD_ETHER 1

#define ARPOP_REQUEST 1
#define ARPOP_REPLY 2
#define ARPOP_RREQUEST 3
#define ARPOP_RREPLY 4
#define ARPOP_InREQUEST 8
#define ARPOP_InREPLY 9
#define ARPOP_NAK 10

#define IP_ADDR_LEN_STR 20

struct __attribute__((__packed__)) arphdr
{
 unsigned short ar_hrd;
 unsigned short ar_pro;
 unsigned char ar_hln;
 unsigned char ar_pln;
 unsigned short ar_op;
};

struct __attribute__((__packed__)) arp_pkt
{
  struct arphdr hdr;
  macaddr_t sha[6];
  ipaddr_n_t spa;
  macaddr_t tha[6];
  ipaddr_n_t tpa;
};

void make_arp_header(struct arphdr *buf)
{
	buf->ar_hrd = htons(ARPHRD_ETHER);
	buf->ar_pro = htons(ETHERTYPE_IP);
	buf->ar_hln = ETHER_ADDR_LEN;
	buf->ar_pln = 4;
	buf->ar_op = htons(ARPOP_REQUEST);
}

int arp_init_perthread(void* buf, macaddr_t *src,
		__attribute__((unused)) macaddr_t *gw, __attribute__((unused)) port_h_t dst_port,
		__attribute__((unused)) void **arg_ptr)
{
	memset(buf, 0, MAX_PACKET_SIZE);

	macaddr_t bcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	struct ether_header *eth_header = (struct ether_header *) buf;
	make_eth_header(eth_header, src, bcast);
	eth_header->ether_type = htons(ETHERTYPE_ARP);

	struct arphdr *arp_header = (struct arphdr *) (&eth_header[1]);
	make_arp_header(arp_header);

	memcpy((macaddr_t *) (&arp_header[1]), src, ETHER_ADDR_LEN);
	
	return EXIT_SUCCESS;
}

int arp_make_packet(void *buf, ipaddr_n_t src_ip, ipaddr_n_t dst_ip,
				__attribute__((unused)) uint32_t *validation, 
		    		__attribute__((unused)) int probe_num,
				__attribute__((unused)) void *arg)
{
	struct ether_header *eth_header = (struct ether_header *) buf;
	struct arp_pkt *arp_request = (struct arp_pkt *)(&eth_header[1]);

	arp_request->spa = src_ip;
	arp_request->tpa = dst_ip;

	return EXIT_SUCCESS;
}

void arp_print_packet(FILE *fp, void* packet)
{
	struct ether_header *ethh = (struct ether_header *) packet;
	struct arp_pkt *arp_packet = (struct arp_pkt *)(&ethh[1]);

	struct in_addr *s = (struct in_addr *) &(arp_packet->spa);
	struct in_addr *d = (struct in_addr *) &(arp_packet->tpa);

	char srcip[IP_ADDR_LEN_STR+1];
	char dstip[IP_ADDR_LEN_STR+1];
	strncpy(srcip, inet_ntoa(*s), IP_ADDR_LEN_STR - 1);
	strncpy(dstip, inet_ntoa(*d), IP_ADDR_LEN_STR - 1);

	char *smac = make_mac_str(arp_packet->sha);
	char *dmac = make_mac_str(arp_packet->tha);

	fprintf(fp, "arp { opcode: %u | smac: %s | dmac: %s "
			"| saddr: %s | daddr: %s }\n",
			ntohs(arp_packet->hdr.ar_op), smac, dmac,
			srcip, dstip);

	free(smac);
	free(dmac);

	fprintf_eth_header(fp, ethh);
	fprintf(fp, "------------------------------------------------------\n");
}

int arp_validate_packet(const struct ip *ip_hdr,
		uint32_t len, __attribute__((unused)) uint32_t *src_ip, __attribute__((unused)) uint32_t *validation)
{
	// This violates the abstraction a bit since we are assuming we don't actually have an IP frame
	// Fortunately an ARP message is larger than the IPv4 header
	struct arp_pkt *arp_packet = (struct arp_pkt *) ip_hdr;

	if (sizeof(arp_packet) > len) {
		return 0;
	}

	if (arp_packet->hdr.ar_hrd != htons(ARPHRD_ETHER) ||
	    arp_packet->hdr.ar_pro != htons(ETHERTYPE_IP) ||
	    arp_packet->hdr.ar_hln != ETHER_ADDR_LEN ||
	    arp_packet->hdr.ar_pln != 4 ||
	    arp_packet->hdr.ar_op != htons(ARPOP_REPLY)) {
		return 0;
	}

	//TODO validate destination IP and MAC address against us

	return 1;
}

void arp_process_packet(const u_char *packet,
		__attribute__((unused)) uint32_t len, fieldset_t *fs)
{
	struct ether_header *ethh = (struct ether_header *) packet;
	struct arp_pkt *arp_packet = (struct arp_pkt *)(&ethh[1]);

	fs_add_uint64(fs, "opcode", ntohs(arp_packet->hdr.ar_op));
	fs_add_string(fs, "arp-saddr", make_ip_str(arp_packet->spa), 1);
	fs_add_uint64(fs, "arp-saddr-raw", (uint64_t) arp_packet->spa);
	fs_add_string(fs, "arp-daddr", make_ip_str(arp_packet->tpa), 1);
	fs_add_uint64(fs, "arp-daddr-raw", (uint64_t) arp_packet->tpa);
	fs_add_string(fs, "classification", (char *) "reply", 0);
	fs_add_uint64(fs, "success", 1);
}

// currently renaming these fields so we can override them...
static fielddef_t fields[] = {
	{.name="opcode", .type="int", .desc="arp opcode"},
	{.name="arp-saddr", .type="string", .desc="source IP address of response"},
	{.name="arp-saddr-raw", .type="int", .desc="network order integer form of source IP address"},
	{.name="arp-daddr", .type="string", .desc="destination IP address of response"},
	{.name="arp-daddr-raw", .type="int", .desc="network order integer form of destination IP address"},
	{.name="classification", .type="string", .desc="probe module classification"},
	{.name="success", .type="int", .desc="did probe module classify response as success"}
};


probe_module_t module_arp = {
	.name = "arp",
	.packet_length = 60,
	.pcap_filter = "arp",
	.pcap_snaplen = 96,
	.port_args = 0,
	.thread_initialize = &arp_init_perthread,
	.make_packet = &arp_make_packet,
	.print_packet = &arp_print_packet,
	.process_packet = &arp_process_packet,
	.validate_packet = &arp_validate_packet,
	.close = NULL,
	.fields = fields,
	.numfields = 7};

