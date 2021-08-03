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
#include "validate.h"
#include "module_tcp_synscan.h"

#define ZMAP_TCP_SYNACKSCAN_TCP_HEADER_LEN 24
#define ZMAP_TCP_SYNACKSCAN_PACKET_LEN 58

probe_module_t module_tcp_synackscan;
static uint32_t num_ports;

static int synackscan_global_initialize(struct state_conf *state)
{
	num_ports = state->source_port_last - state->source_port_first + 1;
	return EXIT_SUCCESS;
}

static int synackscan_init_perthread(void *buf, macaddr_t *src, macaddr_t *gw,
				     port_h_t dst_port,
				     UNUSED void **arg_ptr)
{
	memset(buf, 0, MAX_PACKET_SIZE);
	struct ether_header *eth_header = (struct ether_header *)buf;
	make_eth_header(eth_header, src, gw);
	struct ip *ip_header = (struct ip *)(&eth_header[1]);
	uint16_t len = htons(sizeof(struct ip) + ZMAP_TCP_SYNACKSCAN_TCP_HEADER_LEN);
	make_ip_header(ip_header, IPPROTO_TCP, len);
	struct tcphdr *tcp_header = (struct tcphdr *)(&ip_header[1]);
	make_tcp_header(tcp_header, dst_port, TH_SYN | TH_ACK);
	set_mss_option(tcp_header);
	return EXIT_SUCCESS;
}

static int synackscan_make_packet(void *buf, UNUSED size_t *buf_len,
				  ipaddr_n_t src_ip, ipaddr_n_t dst_ip, uint8_t ttl,
				  uint32_t *validation, int probe_num,
				  UNUSED void *arg)
{
	struct ether_header *eth_header = (struct ether_header *)buf;
	struct ip *ip_header = (struct ip *)(&eth_header[1]);
	struct tcphdr *tcp_header = (struct tcphdr *)(&ip_header[1]);
	uint32_t tcp_seq = validation[0];
	uint32_t tcp_ack =
	    validation[2]; // get_src_port() below uses validation 1 internally.

	ip_header->ip_src.s_addr = src_ip;
	ip_header->ip_dst.s_addr = dst_ip;
	ip_header->ip_ttl = ttl;

	tcp_header->th_sport =
	    htons(get_src_port(num_ports, probe_num, validation));
	tcp_header->th_seq = tcp_seq;
	tcp_header->th_ack = tcp_ack;
	tcp_header->th_sum = 0;
	tcp_header->th_sum =
	    tcp_checksum(ZMAP_TCP_SYNACKSCAN_TCP_HEADER_LEN, ip_header->ip_src.s_addr,
			 ip_header->ip_dst.s_addr, tcp_header);

	ip_header->ip_sum = 0;
	ip_header->ip_sum = zmap_ip_checksum((unsigned short *)ip_header);
	*buf_len = ZMAP_TCP_SYNACKSCAN_PACKET_LEN;

	return EXIT_SUCCESS;
}

static int synackscan_validate_packet(const struct ip *ip_hdr, uint32_t len,
				      UNUSED uint32_t *src_ip,
				      uint32_t *validation)
{

	if (ip_hdr->ip_p == IPPROTO_TCP) {
		struct tcphdr *tcp = get_tcp_header(ip_hdr, len);
		if (!tcp) {
			return PACKET_INVALID;
		}
		uint16_t sport = ntohs(tcp->th_sport);
		uint16_t dport = ntohs(tcp->th_dport);
		// validate source port
		if (sport != zconf.target_port) {
			return PACKET_INVALID;
		}
		// validate destination port
		if (!check_dst_port(dport, num_ports, validation)) {
			return PACKET_INVALID;
		}
		// check whether we'll ever send to this IP during the scan
		if (!blocklist_is_allowed(*src_ip)) {
			return PACKET_INVALID;
		}
		// We handle RST packets different than all other packets
		if (tcp->th_flags & TH_RST) {
			// A RST packet must have either:
			//	1) resp(ack) == sent(seq) + 1, or
			//	2) resp(seq) == sent(ack), or
			//	3) resp(seq) == sent(ack) + 1
			// All other cases are a failure.
			if (htonl(tcp->th_ack) != htonl(validation[0]) + 1 &&
			    htonl(tcp->th_seq) != htonl(validation[2]) &&
			    htonl(tcp->th_seq) != (htonl(validation[2]) + 1)) {
				return PACKET_INVALID;
			}
		} else {
			// For non RST packets, we must have resp(ack) == sent(seq) + 1
			if (htonl(tcp->th_ack) != htonl(validation[0]) + 1) {
				return PACKET_INVALID;
			}
		}
	} else if (ip_hdr->ip_p == IPPROTO_ICMP) {
		struct ip *ip_inner;
		size_t ip_inner_len;
		if (icmp_helper_validate(ip_hdr, len, sizeof(struct udphdr),
					 &ip_inner,
					 &ip_inner_len) == PACKET_INVALID) {
			return PACKET_INVALID;
		}
		struct tcphdr *tcp = get_tcp_header(ip_inner, ip_inner_len);
		if (!tcp) {
			return PACKET_INVALID;
		}
		// we can always check the destination port because this is the
		// original packet and wouldn't have been altered by something
		// responding on a different port
		uint16_t sport = ntohs(tcp->th_sport);
		uint16_t dport = ntohs(tcp->th_dport);
		if (dport != zconf.target_port) {
			return PACKET_INVALID;
		}
		validate_gen(ip_hdr->ip_dst.s_addr, ip_inner->ip_dst.s_addr,
			     (uint8_t *)validation);
		if (!check_dst_port(sport, num_ports, validation)) {
			return PACKET_INVALID;
		}
	} else {
		return PACKET_INVALID;
	}
	return PACKET_VALID;
}

static void synackscan_process_packet(const u_char *packet,
				      UNUSED uint32_t len,
				      fieldset_t *fs,
				      UNUSED uint32_t *validation,
				      UNUSED struct timespec ts)
{
	struct ip *ip_hdr = get_ip_header(packet, len);
	if (ip_hdr->ip_p == IPPROTO_TCP) {
		struct tcphdr *tcp = get_tcp_header(ip_hdr, len);
		fs_add_uint64(fs, "sport", (uint64_t)ntohs(tcp->th_sport));
		fs_add_uint64(fs, "dport", (uint64_t)ntohs(tcp->th_dport));
		fs_add_uint64(fs, "seqnum", (uint64_t)ntohl(tcp->th_seq));
		fs_add_uint64(fs, "acknum", (uint64_t)ntohl(tcp->th_ack));
		fs_add_uint64(fs, "window", (uint64_t)ntohs(tcp->th_win));
		if (tcp->th_flags & TH_RST) { // RST packet
			fs_add_constchar(fs, "classification", "rst");
		} else { // SYNACK packet
			fs_add_constchar(fs, "classification", "synack");
		}
		fs_add_bool(fs, "success", 1);
		fs_add_null_icmp(fs);
	} else if (ip_hdr->ip_p == IPPROTO_ICMP) {
		// tcp
		fs_add_null(fs, "sport");
		fs_add_null(fs, "dport");
		fs_add_null(fs, "seqnum");
		fs_add_null(fs, "acknum");
		fs_add_null(fs, "window");
		// global
		fs_add_constchar(fs, "classification", "icmp");
		fs_add_bool(fs, "success", 0);
		// icmp
		fs_populate_icmp_from_iphdr(ip_hdr, len, fs);
	}
}

static fielddef_t fields[] = {
    {.name = "sport", .type = "int", .desc = "TCP source port"},
    {.name = "dport", .type = "int", .desc = "TCP destination port"},
    {.name = "seqnum", .type = "int", .desc = "TCP sequence number"},
    {.name = "acknum", .type = "int", .desc = "TCP acknowledgement number"},
    {.name = "window", .type = "int", .desc = "TCP window"},
    CLASSIFICATION_SUCCESS_FIELDSET_FIELDS,
    ICMP_FIELDSET_FIELDS,
};

probe_module_t module_tcp_synackscan = {
    .name = "tcp_synackscan",
    .max_packet_length = ZMAP_TCP_SYNACKSCAN_PACKET_LEN,
    .pcap_filter = "(tcp && tcp[13] & 4 != 0 || tcp[13] == 18) || icmp",
    .pcap_snaplen = 96,
    .port_args = 1,
    .global_initialize = &synackscan_global_initialize,
    .thread_initialize = &synackscan_init_perthread,
    .make_packet = &synackscan_make_packet,
    .print_packet = &synscan_print_packet,
    .process_packet = &synackscan_process_packet,
    .validate_packet = &synackscan_validate_packet,
    .close = NULL,
    .helptext = "Probe module that sends a TCP SYNACK packet to a specific "
		"port. Possible classifications are: synack and rst. A "
		"SYN-ACK packet is considered a failure and a reset packet "
		"is considered a success.",
    .output_type = OUTPUT_TYPE_STATIC,
    .fields = fields,
    .numfields = sizeof(fields) / sizeof(fields[0])
};
