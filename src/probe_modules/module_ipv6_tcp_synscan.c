/*
 * ZMapv6 Copyright 2016 Chair of Network Architectures and Services
 * Technical University of Munich
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

// probe module for performing TCP SYN scans over IPv6

// Needed for asprintf
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

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

probe_module_t module_ipv6_tcp_synscan;
static uint32_t num_ports;

int ipv6_synscan_global_initialize(struct state_conf *state)
{
	num_ports = state->source_port_last - state->source_port_first + 1;

	// Only look at received packets destined to the specified scanning address (useful for parallel zmap scans)
	if (asprintf((char ** restrict) &module_ipv6_tcp_synscan.pcap_filter, "%s && ip6 dst host %s", module_ipv6_tcp_synscan.pcap_filter, state->ipv6_source_ip) == -1) {
		return 1;
	}

	return EXIT_SUCCESS;
}

int ipv6_synscan_init_perthread(void* buf, macaddr_t *src,
		macaddr_t *gw, port_h_t dst_port,
		__attribute__((unused)) void **arg_ptr)
{
	memset(buf, 0, MAX_PACKET_SIZE);
	struct ether_header *eth_header = (struct ether_header *) buf;
	make_eth_header_ethertype(eth_header, src, gw, ETHERTYPE_IPV6);
	struct ip6_hdr *ip6_header = (struct ip6_hdr*)(&eth_header[1]);
	uint16_t payload_len = sizeof(struct tcphdr);
	make_ip6_header(ip6_header, IPPROTO_TCP, payload_len);
	struct tcphdr *tcp_header = (struct tcphdr*)(&ip6_header[1]);
	make_tcp_header(tcp_header, dst_port, TH_SYN);
	return EXIT_SUCCESS;
}

int ipv6_synscan_make_packet(void *buf, UNUSED size_t *buf_len, UNUSED ipaddr_n_t src_ip, UNUSED ipaddr_n_t dst_ip,
        uint8_t ttl, uint32_t *validation, int probe_num, void *arg)
{
	struct ether_header *eth_header = (struct ether_header *) buf;
	struct ip6_hdr *ip6_header = (struct ip6_hdr*) (&eth_header[1]);
	struct tcphdr *tcp_header = (struct tcphdr*) (&ip6_header[1]);
	uint32_t tcp_seq = validation[0];

	ip6_header->ip6_src = ((struct in6_addr *) arg)[0];
	ip6_header->ip6_dst = ((struct in6_addr *) arg)[1];
	ip6_header->ip6_ctlun.ip6_un1.ip6_un1_hlim = ttl;

	tcp_header->th_sport = htons(get_src_port(num_ports,
				probe_num, validation));
	tcp_header->th_seq = tcp_seq;
	tcp_header->th_sum = 0;
	tcp_header->th_sum = tcp6_checksum(sizeof(struct tcphdr),
			&ip6_header->ip6_src, &ip6_header->ip6_dst, tcp_header);

	return EXIT_SUCCESS;
}

void ipv6_synscan_print_packet(FILE *fp, void* packet)
{
	struct ether_header *ethh = (struct ether_header *) packet;
	struct ip6_hdr *iph = (struct ip6_hdr *) &ethh[1];
	struct tcphdr *tcph = (struct tcphdr *) &iph[1];
	fprintf(fp, "tcp { source: %u | dest: %u | seq: %u | checksum: %#04X }\n",
			ntohs(tcph->th_sport),
			ntohs(tcph->th_dport),
			ntohl(tcph->th_seq),
			ntohs(tcph->th_sum));
	fprintf_ipv6_header(fp, iph);
	fprintf_eth_header(fp, ethh);
	fprintf(fp, "------------------------------------------------------\n");
}

int ipv6_synscan_validate_packet(const struct ip *ip_hdr, uint32_t len,
		__attribute__((unused))uint32_t *src_ip,
		uint32_t *validation)
{
	struct ip6_hdr *ipv6_hdr = (struct ip6_hdr *) ip_hdr;

	if (ipv6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt != IPPROTO_TCP) {
		return 0;
	}
	if ((ntohs(ipv6_hdr->ip6_ctlun.ip6_un1.ip6_un1_plen)) > len) {
		// buffer not large enough to contain expected tcp header, i.e. IPv6 payload
		return 0;
	}
	struct tcphdr *tcp_hdr = (struct tcphdr*) (&ipv6_hdr[1]);
	uint16_t sport = tcp_hdr->th_sport;
	uint16_t dport = tcp_hdr->th_dport;
	// validate source port
	if (ntohs(sport) != zconf.target_port) {
		return 0;
	}
	// validate destination port
	if (!check_dst_port(ntohs(dport), num_ports, validation)) {
		return 0;
	}
	// validate tcp acknowledgement number
	if (htonl(tcp_hdr->th_ack) != htonl(validation[0])+1) {
		return 0;
	}
	return 1;
}

void ipv6_synscan_process_packet(const u_char *packet,
		__attribute__((unused)) uint32_t len, fieldset_t *fs,
		__attribute__((unused)) uint32_t *validation)
{
	struct ether_header *eth_hdr = (struct ether_header *) packet;
	struct ip6_hdr *ipv6_hdr = (struct ip6_hdr *) (&eth_hdr[1]);
	struct tcphdr *tcp_hdr = (struct tcphdr*) (&ipv6_hdr[1]);

	fs_add_uint64(fs, "sport", (uint64_t) ntohs(tcp_hdr->th_sport));
	fs_add_uint64(fs, "dport", (uint64_t) ntohs(tcp_hdr->th_dport));
	fs_add_uint64(fs, "seqnum", (uint64_t) ntohl(tcp_hdr->th_seq));
	fs_add_uint64(fs, "acknum", (uint64_t) ntohl(tcp_hdr->th_ack));
	fs_add_uint64(fs, "window", (uint64_t) ntohs(tcp_hdr->th_win));

	if (tcp_hdr->th_flags & TH_RST) { // RST packet
		fs_add_string(fs, "classification", (char*) "rst", 0);
		fs_add_uint64(fs, "success", 0);
	} else { // SYNACK packet
		fs_add_string(fs, "classification", (char*) "synack", 0);
		fs_add_uint64(fs, "success", 1);
	}
}

static fielddef_t fields[] = {
	{.name = "sport",  .type = "int", .desc = "TCP source port"},
	{.name = "dport",  .type = "int", .desc = "TCP destination port"},
	{.name = "seqnum", .type = "int", .desc = "TCP sequence number"},
	{.name = "acknum", .type = "int", .desc = "TCP acknowledgement number"},
	{.name = "window", .type = "int", .desc = "TCP window"},
	{.name = "classification", .type="string", .desc = "packet classification"},
	{.name = "success", .type="int", .desc = "is response considered success"}
};

probe_module_t module_ipv6_tcp_synscan = {
	.name = "ipv6_tcp_synscan",
	.packet_length = 74,
	.pcap_filter = "ip6 proto 6 && (ip6[53] & 4 != 0 || ip6[53] == 18)",
	.pcap_snaplen = 116, // was 96 for IPv4
	.port_args = 1,
	.global_initialize = &ipv6_synscan_global_initialize,
	.thread_initialize = &ipv6_synscan_init_perthread,
	.make_packet = &ipv6_synscan_make_packet,
	.print_packet = &ipv6_synscan_print_packet,
	.process_packet = &ipv6_synscan_process_packet,
	.validate_packet = &ipv6_synscan_validate_packet,
	.close = NULL,
	.helptext = "Probe module that sends an IPv6+TCP SYN packet to a specific "
		"port. Possible classifications are: synack and rst. A "
		"SYN-ACK packet is considered a success and a reset packet "
		"is considered a failed response.",

	.fields = fields,
	.numfields = 7};

