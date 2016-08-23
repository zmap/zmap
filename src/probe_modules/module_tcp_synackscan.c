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
#include <assert.h>

#include "../../lib/includes.h"
#include "../fieldset.h"
#include "probe_modules.h"
#include "packet.h"
#include "module_tcp_synscan.h"

probe_module_t module_tcp_synackscan;

static int synackscan_init_perthread(void* buf, macaddr_t *src,
		macaddr_t *gw, port_h_t dst_port,
		__attribute__((unused)) void **arg_ptr)
{
	memset(buf, 0, MAX_PACKET_SIZE);
	struct ether_header *eth_header = (struct ether_header *) buf;
	make_eth_header(eth_header, src, gw);
	struct ip *ip_header = (struct ip*)(&eth_header[1]);
	uint16_t len = htons(sizeof(struct ip) + sizeof(struct tcphdr));
	make_ip_header(ip_header, IPPROTO_TCP, len);
	struct tcphdr *tcp_header = (struct tcphdr*)(&ip_header[1]);
	make_tcp_header(tcp_header, dst_port, TH_SYN | TH_ACK);
	return EXIT_SUCCESS;
}

static void synackscan_process_packet(const u_char *packet,
		__attribute__((unused)) uint32_t len, fieldset_t *fs,
        __attribute__((unused)) uint32_t *validation)
{
	struct ip *ip_hdr = (struct ip *)&packet[sizeof(struct ether_header)];
	struct tcphdr *tcp = (struct tcphdr*)((char *)ip_hdr
					+ 4*ip_hdr->ip_hl);

	fs_add_uint64(fs, "sport", (uint64_t) ntohs(tcp->th_sport));
	fs_add_uint64(fs, "dport", (uint64_t) ntohs(tcp->th_dport));
	fs_add_uint64(fs, "seqnum", (uint64_t) ntohl(tcp->th_seq));
	fs_add_uint64(fs, "acknum", (uint64_t) ntohl(tcp->th_ack));
	fs_add_uint64(fs, "window", (uint64_t) ntohs(tcp->th_win));
	fs_add_uint64(fs, "ipid", (uint64_t) ntohs(ip_hdr->ip_id));

	if (tcp->th_flags & TH_RST) { // RST packet
		fs_add_string(fs, "classification", (char*) "rst", 0);
	} else { // SYNACK packet
		fs_add_string(fs, "classification", (char*) "synack", 0);
	}

    fs_add_bool(fs, "success", 1);
}

static fielddef_t fields[] = {
	{.name = "sport",  .type = "int", .desc = "TCP source port"},
	{.name = "dport",  .type = "int", .desc = "TCP destination port"},
	{.name = "seqnum", .type = "int", .desc = "TCP sequence number"},
	{.name = "acknum", .type = "int", .desc = "TCP acknowledgement number"},
	{.name = "window", .type = "int", .desc = "TCP window"},
	{.name = "ipid", .type = "int", .desc = "IP Identification"},
	{.name = "classification", .type="string", .desc = "packet classification"},
	{.name = "success", .type="bool", .desc = "is response considered success"}
};

probe_module_t module_tcp_synackscan = {
	.name = "tcp_synackscan",
	.packet_length = 54,
	.pcap_filter = "tcp && tcp[13] & 4 != 0 || tcp[13] == 18",
	.pcap_snaplen = 96,
	.port_args = 1,
	.global_initialize = &synscan_global_initialize,
	.thread_initialize = &synackscan_init_perthread,
	.make_packet = &synscan_make_packet,
	.print_packet = &synscan_print_packet,
	.process_packet = &synackscan_process_packet,
	.validate_packet = &synscan_validate_packet,
	.close = NULL,
	.helptext = "Probe module that sends a TCP SYNACK packet to a specific "
		"port. Possible classifications are: synack and rst. A "
		"SYN-ACK packet is considered a failure and a reset packet "
		"is considered a success.",
	.output_type = OUTPUT_TYPE_STATIC,
	.fields = fields,
	.numfields = 8};

