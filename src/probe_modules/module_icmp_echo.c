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

#include "../../lib/includes.h"
#include "probe_modules.h"
#include "../fieldset.h"
#include "packet.h"
#include "validate.h"

probe_module_t module_icmp_echo;

int icmp_echo_init_perthread(void* buf, macaddr_t *src,
		macaddr_t *gw, __attribute__((unused)) port_h_t dst_port)
{
	memset(buf, 0, MAX_PACKET_SIZE);

	struct ether_header *eth_header = (struct ether_header *) buf;
	make_eth_header(eth_header, src, gw);

	struct ip *ip_header = (struct ip *) (&eth_header[1]);
	uint16_t len = htons(sizeof(struct ip) + sizeof(struct icmp) - 8);
	make_ip_header(ip_header, IPPROTO_ICMP, len);

	struct icmp *icmp_header = (struct icmp*)(&ip_header[1]);
	make_icmp_header(icmp_header);

	return EXIT_SUCCESS;
}

int icmp_echo_make_packet(void *buf, ipaddr_n_t src_ip, ipaddr_n_t dst_ip,
				uint32_t *validation, __attribute__((unused))int probe_num)
{
	struct ether_header *eth_header = (struct ether_header *) buf;
	struct ip *ip_header = (struct ip *)(&eth_header[1]);
	struct icmp *icmp_header = (struct icmp*)(&ip_header[1]);
	uint16_t icmp_idnum = validation[2] & 0xFFFF;

	ip_header->ip_src.s_addr = src_ip;
	ip_header->ip_dst.s_addr = dst_ip;

	icmp_header->icmp_id = icmp_idnum;
	icmp_header->icmp_cksum = 0;
	icmp_header->icmp_cksum = icmp_checksum((unsigned short *) icmp_header);

	ip_header->ip_sum = 0;
	ip_header->ip_sum = zmap_ip_checksum((unsigned short *) ip_header);

	return EXIT_SUCCESS;
}

void icmp_echo_print_packet(FILE *fp, void* packet)
{
	struct ether_header *ethh = (struct ether_header *) packet;
	struct ip *iph = (struct ip *) &ethh[1];
	struct icmp *icmp_header = (struct icmp*) (&iph[1]);

	fprintf(fp, "icmp { type: %u | code: %u "
			"| checksum: %u | id: %u | seq: %u }\n",
			icmp_header->icmp_type,
			icmp_header->icmp_code,
			ntohs(icmp_header->icmp_cksum),
			ntohs(icmp_header->icmp_id),
			ntohs(icmp_header->icmp_seq));
	fprintf_ip_header(fp, iph);
	fprintf_eth_header(fp, ethh);
	fprintf(fp, "------------------------------------------------------\n");
}



int icmp_validate_packet(const struct ip *ip_hdr, 
		uint32_t len, uint32_t *src_ip, uint32_t *validation)
{
	if (ip_hdr->ip_p != IPPROTO_ICMP) {
		return 0;
	}
	
	if ((4*ip_hdr->ip_hl + sizeof(struct icmp)) > len) {
		// buffer not large enough to contain expected icmp header 
		return 0;
	}
	
	struct icmp *icmp_h = (struct icmp *) ((char *) ip_hdr + 4*ip_hdr->ip_hl);
	uint16_t icmp_idnum = icmp_h->icmp_id;

	// ICMP validation is tricky: for some packet types, we must look inside 
	// the payload
	if (icmp_h->icmp_type == ICMP_TIMXCEED || icmp_h->icmp_type == ICMP_UNREACH) {
		if ((4*ip_hdr->ip_hl + sizeof(struct icmp) +
			sizeof(struct ip)) > len) {
			return 0;
		}
		struct ip *ip_inner = (struct ip *)(icmp_h + 1);
		if ((4*ip_hdr->ip_hl + sizeof(struct icmp) +
				4*ip_inner->ip_hl + sizeof(struct icmp)) > len) {
			return 0;
		}
		struct icmp *icmp_inner = (struct icmp *)((char *) ip_inner + 4*ip_hdr->ip_hl);

		// Regenerate validation and icmp id based off inner payload
		icmp_idnum = icmp_inner->icmp_id;
		*src_ip = ip_inner->ip_dst.s_addr;
		validate_gen(ip_hdr->ip_dst.s_addr, ip_inner->ip_dst.s_addr,
			     (uint8_t *) validation);
	} 

	// validate icmp id
	if (icmp_idnum != (validation[2] & 0xFFFF)) {
		return 0;
	}
	return 1;
}

void icmp_echo_process_packet(const u_char *packet,
		__attribute__((unused)) uint32_t len, fieldset_t *fs)
{
	struct ip *ip_hdr = (struct ip *) &packet[sizeof(struct ether_header)];
	struct icmp *icmp_hdr = (struct icmp *) ((char *) ip_hdr + 4*ip_hdr->ip_hl);
	fs_add_uint64(fs, "type", icmp_hdr->icmp_type);
	fs_add_uint64(fs, "code", icmp_hdr->icmp_code);
	fs_add_uint64(fs, "icmp-id", ntohs(icmp_hdr->icmp_id));
	fs_add_uint64(fs, "seq", ntohs(icmp_hdr->icmp_seq));
	switch (icmp_hdr->icmp_type) {
		case ICMP_ECHOREPLY:
			fs_add_string(fs, "classification", (char*) "echoreply", 0); 
			fs_add_uint64(fs, "success", 1); 
		case ICMP_UNREACH: 
			fs_add_string(fs, "classification", (char*) "unreach", 0); 
			fs_add_uint64(fs, "success", 0); 
		case ICMP_SOURCEQUENCH:
			fs_add_string(fs, "classification", (char*) "sourcequench", 0); 
			fs_add_uint64(fs, "success", 0); 
		case ICMP_REDIRECT:
			fs_add_string(fs, "classification", (char*) "redirect", 0); 
			fs_add_uint64(fs, "success", 0); 
		case ICMP_TIMXCEED:
			fs_add_string(fs, "classification", (char*) "timxceed", 0); 
			fs_add_uint64(fs, "success", 0); 
		default:
			fs_add_string(fs, "classification", (char*) "other", 0); 
			fs_add_uint64(fs, "success", 0); 
	}
}

fielddef_t fields[] = {
	{.name="type", .type="int", .desc="icmp message type"},
	{.name="code", .type="int", .desc="icmp message sub type code"},
	{.name="icmp-id", .type="int", .desc="icmp id number"},
	{.name="seq", .type="int", .desc="icmp sequence number"},
	{.name="classification", .type="string", .desc="probe module classification"},
	{.name="success", .type="int", .desc="did probe module classify response as success"}
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
	.process_packet = &icmp_echo_process_packet,
	.validate_packet = &icmp_validate_packet,
	.close = NULL,
	.fields = fields,
	.numfields = 6};

