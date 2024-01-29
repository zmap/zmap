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

#define ZMAP_TCP_SYNSCAN_TCP_HEADER_LEN 24
// #define ZMAP_TCP_SYNSCAN_TCP_HEADER_LEN 32
#define ZMAP_TCP_SYNSCAN_PACKET_LEN 58

#define TCP_OPTION_KIND_END 0
#define TCP_OPTION_KIND_MSS 2
#define TCP_OPTION_KIND_WINDOW_SCALE 3
#define TCP_OPTION_KIND_SACK_PERMITTED 4
#define TCP_OPTION_KIND_TIMESTAMP 8

// Define the lengths of the TCP options
#define TCP_OPTION_LENGTH_MSS 4
#define TCP_OPTION_LENGTH_WINDOW_SCALE 3
#define TCP_OPTION_LENGTH_SACK_PERMITTED 2
#define TCP_OPTION_LENGTH_TIMESTAMP 10

probe_module_t module_tcp_synscan;

static uint16_t num_source_ports;

static int synscan_global_initialize(struct state_conf *state)
{
	num_source_ports =
	    state->source_port_last - state->source_port_first + 1;
	return EXIT_SUCCESS;
}

static int synscan_init_perthread(void *buf, macaddr_t *src, macaddr_t *gw,
				  UNUSED void **arg_ptr)
{
	struct ether_header *eth_header = (struct ether_header *)buf;
	make_eth_header(eth_header, src, gw);
	struct ip *ip_header = (struct ip *)(&eth_header[1]);
	uint16_t len =
	    htons(sizeof(struct ip) + ZMAP_TCP_SYNSCAN_TCP_HEADER_LEN);
	make_ip_header(ip_header, IPPROTO_TCP, len);
	struct tcphdr *tcp_header = (struct tcphdr *)(&ip_header[1]);
	make_tcp_header(tcp_header, TH_SYN);
	set_mss_option(tcp_header);
	return EXIT_SUCCESS;
}

static int synscan_make_packet(void *buf, size_t *buf_len, ipaddr_n_t src_ip,
			       ipaddr_n_t dst_ip, port_n_t dport, uint8_t ttl,
			       uint32_t *validation, int probe_num,
			       UNUSED void *arg)
{
	printf("Starting packet creation...\n");

	struct ether_header *eth_header = (struct ether_header *)buf;
	struct ip *ip_header = (struct ip *)(&eth_header[1]);
	struct tcphdr *tcp_header = (struct tcphdr *)(&ip_header[1]);
	uint32_t tcp_seq = validation[0];

	printf("Ethernet header created.\n");

	ip_header->ip_src.s_addr = src_ip;
	ip_header->ip_dst.s_addr = dst_ip;
	ip_header->ip_ttl = ttl;

	printf("IP header set: src_ip=%s, dst_ip=%s, ttl=%d\n",
	       inet_ntoa(*(struct in_addr *)&src_ip),
	       inet_ntoa(*(struct in_addr *)&dst_ip), ttl);

	port_h_t sport = get_src_port(num_source_ports, probe_num, validation);
	tcp_header->th_sport = htons(sport);
	tcp_header->th_dport = dport;
	tcp_header->th_seq = tcp_seq;

	printf("TCP header set: src_port=%d, dst_port=%d, seq_num=%u\n",
	       ntohs(sport), ntohs(dport), tcp_seq);

	// BEGIN JA4TS IMPLEMENTATION
	// tcp_header->th_off =
	//     5 + (TCP_OPTION_LENGTH_MSS + TCP_OPTION_LENGTH_WINDOW_SCALE +
	// 	 TCP_OPTION_LENGTH_SACK_PERMITTED +
	// 	 TCP_OPTION_LENGTH_TIMESTAMP + 1) /
	// 	    4; // data offset

	// // Start setting TCP options right after the TCP header
	// unsigned char *tcp_options = (unsigned char *)(tcp_header + 1);
	// int option_index = 0;

	// // Set Maximum Segment Size option
	// tcp_options[option_index++] = TCP_OPTION_KIND_MSS;
	// tcp_options[option_index++] = TCP_OPTION_LENGTH_MSS;
	// *(uint16_t *)(tcp_options + option_index) =
	//     htons(1460); // example MSS value
	// option_index += 2;

	// // Set Window Scale option
	// tcp_options[option_index++] = TCP_OPTION_KIND_WINDOW_SCALE;
	// tcp_options[option_index++] = TCP_OPTION_LENGTH_WINDOW_SCALE;
	// tcp_options[option_index++] = 4; // example scale factor

	// // Set SACK Permitted option
	// tcp_options[option_index++] = TCP_OPTION_KIND_SACK_PERMITTED;
	// tcp_options[option_index++] = TCP_OPTION_LENGTH_SACK_PERMITTED;

	// // Set Timestamps option
	// tcp_options[option_index++] = TCP_OPTION_KIND_TIMESTAMP;
	// tcp_options[option_index++] = TCP_OPTION_LENGTH_TIMESTAMP;
	// // Timestamp value and echo reply (8 bytes total)
	// *(uint32_t *)(tcp_options + option_index) =
	//     htonl(12345678); // example timestamp
	// option_index += 4;
	// *(uint32_t *)(tcp_options + option_index) =
	//     0; // example echo reply (usually 0 in SYN)
	// option_index += 4;

	// // End of option list
	// tcp_options[option_index++] = TCP_OPTION_KIND_END;

	// // Adjust packet length to include TCP options
	// *buf_len = ((unsigned char *)tcp_header - (unsigned char *)buf) +
	// 	   sizeof(struct tcphdr) + option_index;

	// END JA4TS IMPLEMENTATION
	// checksum value must be zero when calculating packet's checksum
	tcp_header->th_sum = 0;
	tcp_header->th_sum = tcp_checksum(ZMAP_TCP_SYNSCAN_TCP_HEADER_LEN,
					  ip_header->ip_src.s_addr,
					  ip_header->ip_dst.s_addr, tcp_header);
	// checksum value must be zero when calculating packet's checksum
	ip_header->ip_sum = 0;
	ip_header->ip_sum = zmap_ip_checksum((unsigned short *)ip_header);

	*buf_len = ZMAP_TCP_SYNSCAN_PACKET_LEN;
	printf("Packet creation completed. Packet length: %zu\n", *buf_len);
	// print ip_header
	printf("ip_header: ");
	for (int i = 0; i < sizeof(struct ip); i++)
	{
		printf("%02x ", ((unsigned char *)ip_header)[i]);
	}
	return EXIT_SUCCESS;
}

// not static because used by synack scan
void synscan_print_packet(FILE *fp, void *packet)
{
	struct ether_header *ethh = (struct ether_header *)packet;
	struct ip *iph = (struct ip *)&ethh[1];
	struct tcphdr *tcph = (struct tcphdr *)&iph[1];
	fprintf(fp,
		"tcp { source: %u | dest: %u | seq: %u | checksum: %#04X }\n",
		ntohs(tcph->th_sport), ntohs(tcph->th_dport),
		ntohl(tcph->th_seq), ntohs(tcph->th_sum));
	fprintf_ip_header(fp, iph);
	fprintf_eth_header(fp, ethh);
	fprintf(fp, PRINT_PACKET_SEP);
}

static int synscan_validate_packet(const struct ip *ip_hdr, uint32_t len,
				   uint32_t *src_ip, uint32_t *validation,
				   const struct port_conf *ports)
{
	if (ip_hdr->ip_p == IPPROTO_TCP) {
		struct tcphdr *tcp = get_tcp_header(ip_hdr, len);
		if (!tcp) {
			return PACKET_INVALID;
		}
		port_h_t sport = ntohs(tcp->th_sport);
		port_h_t dport = ntohs(tcp->th_dport);
		// validate source port
		if (!check_src_port(sport, ports)) {
			return PACKET_INVALID;
		}
		// validate destination port
		if (!check_dst_port(dport, num_source_ports, validation)) {
			return PACKET_INVALID;
		}
		// check whether we'll ever send to this IP during the scan
		if (!blocklist_is_allowed(*src_ip)) {
			return PACKET_INVALID;
		}
		// We treat RST packets different from non RST packets
		if (tcp->th_flags & TH_RST) {
			// For RST packets, recv(ack) == sent(seq) + 0 or + 1
			if (htonl(tcp->th_ack) != htonl(validation[0]) &&
			    htonl(tcp->th_ack) != htonl(validation[0]) + 1) {
				return PACKET_INVALID;
			}
		} else {
			// For non RST packets, recv(ack) == sent(seq) + 1
			if (htonl(tcp->th_ack) != htonl(validation[0]) + 1) {
				return PACKET_INVALID;
			}
		}
	} else if (ip_hdr->ip_p == IPPROTO_ICMP) {
		struct ip *ip_inner;
		size_t ip_inner_len;
		if (icmp_helper_validate(ip_hdr, len, sizeof(struct tcphdr),
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
		// responding on a different port. Note this is *different*
		// than the logic above because we're validating the probe packet
		// rather than the response packet
		port_h_t sport = ntohs(tcp->th_sport);
		port_h_t dport = ntohs(tcp->th_dport);
		if (!check_src_port(dport, ports)) {
			return PACKET_INVALID;
		}
		validate_gen(ip_hdr->ip_dst.s_addr, ip_inner->ip_dst.s_addr,
			     tcp->th_dport, (uint8_t *)validation);
		if (!check_dst_port(sport, num_source_ports, validation)) {
			return PACKET_INVALID;
		}
	} else {
		return PACKET_INVALID;
	}
	return PACKET_VALID;
}

static void synscan_process_packet(const u_char *packet, UNUSED uint32_t len,
				   fieldset_t *fs, UNUSED uint32_t *validation,
				   UNUSED struct timespec ts)
{
	struct ip *ip_hdr = get_ip_header(packet, len);
	assert(ip_hdr);
	if (ip_hdr->ip_p == IPPROTO_TCP) {
		struct tcphdr *tcp = get_tcp_header(ip_hdr, len);
		assert(tcp);
		fs_add_uint64(fs, "sport", (uint64_t)ntohs(tcp->th_sport));
		fs_add_uint64(fs, "dport", (uint64_t)ntohs(tcp->th_dport));
		fs_add_uint64(fs, "seqnum", (uint64_t)ntohl(tcp->th_seq));
		fs_add_uint64(fs, "acknum", (uint64_t)ntohl(tcp->th_ack));
		fs_add_uint64(fs, "window", (uint64_t)ntohs(tcp->th_win));
		if (tcp->th_flags & TH_RST) { // RST packet
			fs_add_constchar(fs, "classification", "rst");
			fs_add_bool(fs, "success", 0);
		} else { // SYNACK packet
			fs_add_constchar(fs, "classification", "synack");
			fs_add_bool(fs, "success", 1);
		}
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

probe_module_t module_tcp_synscan = {
    .name = "tcp_synscan",
    .max_packet_length = ZMAP_TCP_SYNSCAN_PACKET_LEN,
    .pcap_filter = "(tcp && tcp[13] & 4 != 0 || tcp[13] == 18) || icmp",
    .pcap_snaplen = 96,
    .port_args = 1,
    .global_initialize = &synscan_global_initialize,
    .thread_initialize = &synscan_init_perthread,
    .make_packet = &synscan_make_packet,
    .print_packet = &synscan_print_packet,
    .process_packet = &synscan_process_packet,
    .validate_packet = &synscan_validate_packet,
    .close = NULL,
    .helptext = "Probe module that sends a TCP SYN packet to a specific "
		"port. Possible classifications are: synack and rst. A "
		"SYN-ACK packet is considered a success and a reset packet "
		"is considered a failed response.",
    .output_type = OUTPUT_TYPE_STATIC,
    .fields = fields,
    .numfields = sizeof(fields) / sizeof(fields[0])};
