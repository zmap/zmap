/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

// probe module for performing TCP SYN scans
// validation is turned off since attacker does not care about validity of responses,
// only about traffic volume
// this doubles amount of results for TCP-handshake amplification

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

probe_module_t module_tcp_synscan_novalidation;
static uint32_t num_ports;

static int synscan_novalidation_global_initialize(struct state_conf *state)
{
	num_ports = state->source_port_last - state->source_port_first + 1;
	return EXIT_SUCCESS;
}

static int synscan_novalidation_init_perthread(void *buf, macaddr_t *src, macaddr_t *gw,
				  port_h_t dst_port,
				  __attribute__((unused)) void **arg_ptr)
{
	memset(buf, 0, MAX_PACKET_SIZE);
	struct ether_header *eth_header = (struct ether_header *)buf;
	make_eth_header(eth_header, src, gw);
	struct ip *ip_header = (struct ip *)(&eth_header[1]);
	uint16_t len = htons(sizeof(struct ip) + sizeof(struct tcphdr));
	make_ip_header(ip_header, IPPROTO_TCP, len);
	struct tcphdr *tcp_header = (struct tcphdr *)(&ip_header[1]);
	make_tcp_header(tcp_header, dst_port, TH_SYN);
	return EXIT_SUCCESS;
}

static int synscan_novalidation_make_packet(void *buf, UNUSED size_t *buf_len,
			       ipaddr_n_t src_ip, ipaddr_n_t dst_ip,
			       uint32_t *validation, int probe_num,
			       UNUSED void *arg)
{
	struct ether_header *eth_header = (struct ether_header *)buf;
	struct ip *ip_header = (struct ip *)(&eth_header[1]);
	struct tcphdr *tcp_header = (struct tcphdr *)(&ip_header[1]);
	uint32_t tcp_seq = validation[0];

	ip_header->ip_src.s_addr = src_ip;
	ip_header->ip_dst.s_addr = dst_ip;

	tcp_header->th_sport =
	    htons(get_src_port(num_ports, probe_num, validation));
	tcp_header->th_seq = tcp_seq;
	tcp_header->th_sum = 0;
	tcp_header->th_sum =
	    tcp_checksum(sizeof(struct tcphdr), ip_header->ip_src.s_addr,
			 ip_header->ip_dst.s_addr, tcp_header);

	ip_header->ip_sum = 0;
	ip_header->ip_sum = zmap_ip_checksum((unsigned short *)ip_header);

	return EXIT_SUCCESS;
}

static int synscan_novalidation_validate_packet(const struct ip *ip_hdr, uint32_t len,
				   __attribute__((unused)) uint32_t *src_ip,
				   uint32_t *validation)
{
	return 1;
}

static void synscan_novalidation_process_packet(const u_char *packet,
				   __attribute__((unused)) uint32_t len,
				   fieldset_t *fs,
				   __attribute__((unused)) uint32_t *validation)
{
	struct ip *ip_hdr = (struct ip *)&packet[sizeof(struct ether_header)];
	struct tcphdr *tcp =
	    (struct tcphdr *)((char *)ip_hdr + 4 * ip_hdr->ip_hl);

	fs_add_uint64(fs, "sport", (uint64_t)ntohs(tcp->th_sport));
	fs_add_uint64(fs, "dport", (uint64_t)ntohs(tcp->th_dport));
	fs_add_uint64(fs, "seqnum", (uint64_t)ntohl(tcp->th_seq));
	fs_add_uint64(fs, "acknum", (uint64_t)ntohl(tcp->th_ack));
	fs_add_uint64(fs, "window", (uint64_t)ntohs(tcp->th_win));

	if (tcp->th_flags & TH_PUSH) { // PUSH packet
		fs_add_string(fs, "classification", (char *)"push", 0);
		fs_add_bool(fs, "success", 0);
	} else if (tcp->th_flags & TH_RST) { // RST packet
		fs_add_string(fs, "classification", (char *)"rst", 0);
		fs_add_bool(fs, "success", 0);
	} else { // SYNACK packet
		fs_add_string(fs, "classification", (char *)"synack", 0);
		fs_add_bool(fs, "success", 1);
	}
}

static fielddef_t fields[] = {
    {.name = "sport", .type = "int", .desc = "TCP source port"},
    {.name = "dport", .type = "int", .desc = "TCP destination port"},
    {.name = "seqnum", .type = "int", .desc = "TCP sequence number"},
    {.name = "acknum", .type = "int", .desc = "TCP acknowledgement number"},
    {.name = "window", .type = "int", .desc = "TCP window"},
    {.name = "classification",
     .type = "string",
     .desc = "packet classification"},
    {.name = "success",
     .type = "bool",
     .desc = "is response considered success"}};

probe_module_t module_tcp_synscan_novalidation = {
    .name = "tcp_synscan_no_validation",
    .packet_length = 54,
    .pcap_filter = "tcp && tcp[13] & 4 != 0 || tcp[13] == 18",
    .pcap_snaplen = 96,
    .port_args = 1,
    .global_initialize = &synscan_novalidation_global_initialize,
    .thread_initialize = &synscan_novalidation_init_perthread,
    .make_packet = &synscan_novalidation_make_packet,
    .print_packet = NULL,
    .process_packet = &synscan_novalidation_process_packet,
    .validate_packet = &synscan_novalidation_validate_packet,
    .close = NULL,
    .helptext = "Probe module that sends a TCP SYN packet to a specific "
		"port. Possible classifications are: synack and rst. A "
		"SYN-ACK packet is considered a success and a reset packet "
		"is considered a failed response.",
    .output_type = OUTPUT_TYPE_STATIC,
    .fields = fields,
    .numfields = 7};
