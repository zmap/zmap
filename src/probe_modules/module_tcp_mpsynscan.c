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

static uint32_t num_ports;

#define htonll(x) ((((uint64_t)htonl(x)) << 32) + htonl((x) >> 32))
#define ntohll(x) ((((uint64_t)ntohl(x)) << 32) + ntohl((x) >> 32))
// todo::
// #define HTONLL(x) ((1==htonl(1)) ? (x) : (((uint64_t)htonl((x) & 0xFFFFFFFFUL)) << 32) | htonl((uint32_t)((x) >> 32)))
// #define NTOHLL(x) ((1==ntohl(1)) ? (x) : (((uint64_t)ntohl((x) & 0xFFFFFFFFUL)) << 32) | ntohl((uint32_t)((x) >> 32)))
// // ^^ https://stackoverflow.com/questions/16375340/c-htonll-and-back

#define MP_CAPABLE 30
//#define MP_KEY 0xdeadcafe
#define MP_KEY htonll(4242424242)
#define MPTCP_RESET 0
#define MPTCP_MIRROR 1
#define MPTCP_EMPTY 2
#define MPTCP_SUPPORTED 3

struct __attribute__((__packed__)) tcp_options {
	uint8_t kind;
	uint8_t size;
	uint8_t subtype_version;
	uint8_t flags;
	uint64_t key;
};


static int mpsynscan_global_initialize(struct state_conf *state)
{
	num_ports = state->source_port_last - state->source_port_first + 1;
	return EXIT_SUCCESS;
}

static int mpsynscan_init_perthread(void *buf, macaddr_t *src, macaddr_t *gw,
				  port_h_t dst_port,
				  __attribute__((unused)) void **arg_ptr)
{
	memset(buf, 0, MAX_PACKET_SIZE);
	struct ether_header *eth_header = (struct ether_header *)buf;
	make_eth_header(eth_header, src, gw);
	struct ip *ip_header = (struct ip *)(&eth_header[1]);
	uint16_t len = htons(sizeof(struct ip) + sizeof(struct tcphdr) + sizeof(struct tcp_options));
	make_ip_header(ip_header, IPPROTO_TCP, len);
	struct tcphdr *tcp_header = (struct tcphdr *)(&ip_header[1]);
	make_tcp_header(tcp_header, dst_port, TH_SYN);
	// https://stackoverflow.com/questions/42750552/read-tcp-options-fields
	// fill in options
	struct tcp_options *opts = (struct tcp_options*)(&tcp_header[1]);
	opts->kind = MP_CAPABLE;
	opts->size = sizeof(struct tcp_options);
	opts->subtype_version = 0;
	opts->flags =  1<<7 | 1;
	opts->key = MP_KEY;

	return EXIT_SUCCESS;
}

static int mpsynscan_make_packet(void *buf, UNUSED size_t *buf_len,
			       ipaddr_n_t src_ip, ipaddr_n_t dst_ip, uint8_t ttl,
			       uint32_t *validation, int probe_num,
			       UNUSED void *arg)
{
	struct ether_header *eth_header = (struct ether_header *)buf;
	struct ip *ip_header = (struct ip *)(&eth_header[1]);
	struct tcphdr *tcp_header = (struct tcphdr *)(&ip_header[1]);
	uint32_t tcp_seq = validation[0];

	ip_header->ip_src.s_addr = src_ip;
	ip_header->ip_dst.s_addr = dst_ip;
	ip_header->ip_ttl = ttl;

	tcp_header->th_sport =
	    htons(get_src_port(num_ports, probe_num, validation));
	tcp_header->th_seq = tcp_seq;
	tcp_header->th_sum = 0;
	tcp_header->th_sum =
	    tcp_checksum(sizeof(struct tcphdr) + sizeof(struct tcp_options), ip_header->ip_src.s_addr,
			 ip_header->ip_dst.s_addr, tcp_header);

	ip_header->ip_sum = 0;
	ip_header->ip_sum = zmap_ip_checksum((unsigned short *)ip_header);

	return EXIT_SUCCESS;
}

static int mpsynscan_validate_packet(const struct ip *ip_hdr, uint32_t len,
				   __attribute__((unused)) uint32_t *src_ip,
				   uint32_t *validation)
{
	if (ip_hdr->ip_p != IPPROTO_TCP) {
		return 0;
	}
	if ((4 * ip_hdr->ip_hl + sizeof(struct tcphdr)) > len) {
		// buffer not large enough to contain expected tcp header
		return 0;
	}
	struct tcphdr *tcp =
	    (struct tcphdr *)((char *)ip_hdr + 4 * ip_hdr->ip_hl);
	uint16_t sport = tcp->th_sport;
	uint16_t dport = tcp->th_dport;
	// validate source port
	if (ntohs(sport) != zconf.target_port) {
		return 0;
	}
	// validate destination port
	if (!check_dst_port(ntohs(dport), num_ports, validation)) {
		return 0;
	}

	// We treat RST packets different from non RST packets
	if (tcp->th_flags & TH_RST) {
		// For RST packets, recv(ack) == sent(seq) + 0 or + 1
		if (htonl(tcp->th_ack) != htonl(validation[0]) &&
		    htonl(tcp->th_ack) != htonl(validation[0]) + 1) {
			return 0;
		}
	} else {
		// For non RST packets, recv(ack) == sent(seq) + 1
		if (htonl(tcp->th_ack) != htonl(validation[0]) + 1) {
			return 0;
		}
	}

	return 1;
}

// similar to tcp_parse_options from Linux kernel `
// https://elixir.bootlin.com/linux/v5.4.25/source/net/ipv4/tcp_input.c#L3839
static inline struct tcp_options *get_mptcp(struct tcphdr *tcp) {

		int length = (tcp->doff * 4) - sizeof(struct tcphdr);
		const unsigned char *ptr = (const unsigned char *)&tcp[1];

		while (length > 0) {
			int opcode = *ptr++;
			int opsize;
			switch(opcode) {
				case TCPOPT_EOL:
					return NULL;
				case TCPOPT_NOP:
					length--;
					continue;
				case MP_CAPABLE:
					return (struct tcp_options*)(ptr - 1);
				default:
					if (length< 2) break;
					opsize = *ptr++;
					if (opsize < 2) break; // linux does so..
					if (opsize > length) break;
					ptr += opsize -2;
					length -= opsize;
			}
		}
		return NULL;
}

static void mpsynscan_process_packet(const u_char *packet,
				   __attribute__((unused)) uint32_t len,
				   fieldset_t *fs,
				   __attribute__((unused)) uint32_t *validation,
				   __attribute__((unused)) struct timespec ts)
{
	struct ip *ip_hdr = (struct ip *)&packet[sizeof(struct ether_header)];
	struct tcphdr *tcp =
	    (struct tcphdr *)((char *)ip_hdr + 4 * ip_hdr->ip_hl);

	fs_add_uint64(fs, "sport", (uint64_t)ntohs(tcp->th_sport));
	fs_add_uint64(fs, "dport", (uint64_t)ntohs(tcp->th_dport));
	fs_add_uint64(fs, "seqnum", (uint64_t)ntohl(tcp->th_seq));
	fs_add_uint64(fs, "acknum", (uint64_t)ntohl(tcp->th_ack));
	fs_add_uint64(fs, "window", (uint64_t)ntohs(tcp->th_win));

	if (tcp->th_flags & TH_RST) { // RST packet
		fs_add_uint64(fs, "mptcp", MPTCP_RESET);
		fs_add_string(fs, "classification", (char *)"rst", 0);
		fs_add_bool(fs, "success", 0);
	} else { // SYNACK packet

		struct tcp_options *opts = get_mptcp(tcp);
		if (opts != NULL)
		{
			if (MP_KEY == opts->key)
			{
				fs_add_uint64(fs, "mptcp", MPTCP_MIRROR);
			}
			else
			{
				// can log ntohll(opts->key)
				// if you want to collect server responce keys
				fs_add_uint64(fs, "mptcp", MPTCP_SUPPORTED);
			}

		} else {
			fs_add_uint64(fs, "mptcp", MPTCP_EMPTY);
		}

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
    {.name = "mptcp", .type = "int", .desc = "MPTCP key"},
    {.name = "classification",
     .type = "string",
     .desc = "packet classification"},
    {.name = "success",
     .type = "bool",
     .desc = "is response considered success"}};

probe_module_t module_tcp_mpsynscan = {
    .name = "tcp_mpsynscan",
    .packet_length = sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr) + sizeof(struct tcp_options),
    .pcap_filter = "tcp && tcp[13] & 4 != 0 || tcp[13] == 18",
    .pcap_snaplen = 96,
    .port_args = 1,
    .global_initialize = &mpsynscan_global_initialize,
    .thread_initialize = &mpsynscan_init_perthread,
    .make_packet = &mpsynscan_make_packet,
    .print_packet = &synscan_print_packet,
    .process_packet = &mpsynscan_process_packet,
    .validate_packet = &mpsynscan_validate_packet,
    .close = NULL,
    .helptext = "Probe module that sends a TCP SYN packet with MP_CAPABLE "
	         "MPTCP (http://multipath-tcp.org/)  extension to a specific "
		"port. Possible classifications are: synack and rst. A "
		"SYN-ACK packet is considered a success and a reset packet "
		"is considered a failed response.",
    .output_type = OUTPUT_TYPE_STATIC,
    .fields = fields,
    .numfields = sizeof(fields) / sizeof(fields[0])};
