/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

// probe module for performing TCP SYN scans

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <assert.h>
#include <math.h>
#include <errno.h>

#include "../../lib/includes.h"
#include "../../lib/util.h"
#include "../fieldset.h"
#include "logger.h"
#include "module_tcp_synscan.h"
#include "probe_modules.h"
#include "packet.h"
#include "validate.h"

// defaults
static uint8_t zmap_tcp_synscan_tcp_header_len = 20;
static uint8_t zmap_tcp_synscan_packet_len = 54;
#define SOURCE_PORT_VALIDATION_MODULE_DEFAULT true; // default to validating source port
static bool should_validate_src_port = SOURCE_PORT_VALIDATION_MODULE_DEFAULT

probe_module_t module_tcp_synscan;

static uint16_t num_source_ports;
static uint8_t os_for_tcp_options;
static bool rtt_enabled = false;

// RTT is encoded in the lower RTT_TIMESTAMP_BITS of the TCP SYN sequence number
// (XOR'd with validation[0]). The upper RTT_VALIDATION_BITS are used for packet
// validation. At 0.1 ms resolution and 24  timestamp bits, the timestamp wraps
// after ~28 minutes; RTT values up to that are computed correctly via unsigned
// modular arithmetic.
#define RTT_TIMESTAMP_BITS  24
#define RTT_VALIDATION_BITS 8
#define RTT_TIMESTAMP_MASK  ((1u << RTT_TIMESTAMP_BITS) - 1)
#define RTT_VALIDATION_MASK ((1u << RTT_VALIDATION_BITS) - 1)

#define RTT_TICKS_PER_SEC 10000 // 10000 ticks/s -> 0.1 ms per tick

static double t_begin;
static double t_begin_realtime;

static uint64_t rtt_ticks_since_begin(void)
{
	return (uint64_t)((steady_now() - t_begin) * RTT_TICKS_PER_SEC);
}

static uint64_t rtt_ticks_from_pcap_ts(struct timespec ts)
{
	double ts_sec = (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
	return (uint64_t)((ts_sec - t_begin_realtime) * RTT_TICKS_PER_SEC);
}

static int synscan_global_initialize(struct state_conf *state)
{
	num_source_ports =
	    state->source_port_last - state->source_port_first + 1;
	if (state->validate_source_port_override == VALIDATE_SRC_PORT_DISABLE_OVERRIDE) {
		log_debug("tcp_synscan", "disabling source port validation");
		should_validate_src_port = false;
	}

	// Parse probe-args as comma-separated tokens.
	// OS tokens: smallest-probes, bsd, windows (default), linux
	// Option token: rtt (enables RTT measurement)
	// Examples: --probe-args=windows, --probe-args=rtt, --probe-args=linux,rtt
	os_for_tcp_options = WINDOWS_OS_OPTIONS;
	zmap_tcp_synscan_tcp_header_len = 32;
	zmap_tcp_synscan_packet_len = 66;
	bool os_set = false;

	const char *probe_args_str = state->probe_args ? state->probe_args : "windows";
	if (!state->probe_args) {
		log_debug("tcp_synscan", "no probe-args, defaulting to Windows-style TCP options. "
			   "Windows-style TCP options offer the highest hit-rate with the least bytes per probe.");
	}

	char *args_copy = strdup(probe_args_str);
	if (!args_copy) {
		log_fatal("tcp_synscan", "failed to allocate memory for probe-args parsing");
	}
	char *token = strtok(args_copy, ",");
	while (token) {
		if (strcmp(token, "rtt") == 0) {
			rtt_enabled = true;
		} else if (strcmp(token, "smallest-probes") == 0) {
			if (os_set) {
				log_fatal("tcp_synscan", "multiple OS options specified in probe-args");
			}
			os_for_tcp_options = SMALLEST_PROBES_OS_OPTIONS;
			zmap_tcp_synscan_tcp_header_len = 24;
			zmap_tcp_synscan_packet_len = 58;
			os_set = true;
		} else if (strcmp(token, "bsd") == 0) {
			if (os_set) {
				log_fatal("tcp_synscan", "multiple OS options specified in probe-args");
			}
			os_for_tcp_options = BSD_OS_OPTIONS;
			zmap_tcp_synscan_tcp_header_len = 44;
			zmap_tcp_synscan_packet_len = 78;
			os_set = true;
		} else if (strcmp(token, "windows") == 0) {
			if (os_set) {
				log_fatal("tcp_synscan", "multiple OS options specified in probe-args");
			}
			os_for_tcp_options = WINDOWS_OS_OPTIONS;
			zmap_tcp_synscan_tcp_header_len = 32;
			zmap_tcp_synscan_packet_len = 66;
			os_set = true;
		} else if (strcmp(token, "linux") == 0) {
			if (os_set) {
				log_fatal("tcp_synscan", "multiple OS options specified in probe-args");
			}
			os_for_tcp_options = LINUX_OS_OPTIONS;
			zmap_tcp_synscan_tcp_header_len = 40;
			zmap_tcp_synscan_packet_len = 74;
			os_set = true;
		} else {
			log_fatal("tcp_synscan",
				  "unknown probe-arg: \"%s\"; "
				  "probe-args should be comma-separated and valid options are: "
				  "an OS option (\"smallest-probes\", \"bsd\", \"linux\", \"windows\"(default)) "
				  "and optionally \"rtt\" to enable RTT measurement. "
				  "Examples: --probe-args=windows, --probe-args=rtt, --probe-args=linux,rtt",
				  token);
		}
		token = strtok(NULL, ",");
	}
	free(args_copy);

	// set max packet length accordingly for accurate send rate calculation
	module_tcp_synscan.max_packet_length = zmap_tcp_synscan_packet_len;
	// double-check arithmetic
	assert(zmap_tcp_synscan_packet_len - zmap_tcp_synscan_tcp_header_len == 34);

	// Warn if "rtt" was explicitly requested as an output field but not enabled via probe-args
	if (!rtt_enabled && state->raw_output_fields &&
	    strcmp(state->raw_output_fields, "*") != 0) {
		for (int i = 0; i < state->output_fields_len; i++) {
			if (strcmp(state->output_fields[i], "rtt") == 0) {
				log_warn("tcp_synscan",
					 "\"rtt\" is listed in --output-fields but RTT is not enabled; "
					 "add \"rtt\" to --probe-args to enable it "
					 "(e.g. --probe-args=rtt or --probe-args=windows,rtt)");
				break;
			}
		}
	}

	if (rtt_enabled) {
		t_begin = steady_now();
		struct timespec ts_rt;
		if (clock_gettime(CLOCK_REALTIME, &ts_rt) == -1) {
			log_fatal("tcp_synscan", "Failed to obtain realtime clock: %s", strerror(errno));
		}
		t_begin_realtime = (double)ts_rt.tv_sec + (double)ts_rt.tv_nsec / 1e9;
		if (zconf.batch != 1) {
			log_warn("tcp_synscan", "RTT measurement works best with --batch 1 for accurate time measurement");
		}
	}

	return EXIT_SUCCESS;
}

static int synscan_prepare_packet(void *buf, macaddr_t *src, macaddr_t *gw,
				  UNUSED void *arg_ptr)
{
	struct ether_header *eth_header = (struct ether_header *)buf;
	make_eth_header(eth_header, src, gw);
	struct ip *ip_header = (struct ip *)(&eth_header[1]);
	uint16_t len =
	    htons(sizeof(struct ip) + zmap_tcp_synscan_tcp_header_len);
	make_ip_header(ip_header, IPPROTO_TCP, len);
	struct tcphdr *tcp_header = (struct tcphdr *)(&ip_header[1]);
	make_tcp_header(tcp_header, TH_SYN);
	set_tcp_options(tcp_header, os_for_tcp_options);
	return EXIT_SUCCESS;
}

static int synscan_make_packet(void *buf, size_t *buf_len, ipaddr_n_t src_ip,
			       ipaddr_n_t dst_ip, port_n_t dport, uint8_t ttl,
			       uint32_t *validation, int probe_num,
			       uint16_t ip_id, UNUSED void *arg)
{
	struct ether_header *eth_header = (struct ether_header *)buf;
	struct ip *ip_header = (struct ip *)(&eth_header[1]);
	struct tcphdr *tcp_header = (struct tcphdr *)(&ip_header[1]);

	uint32_t tcp_seq;
	if (rtt_enabled) {
		uint64_t ticks = rtt_ticks_since_begin();
		tcp_seq = validation[0] ^ ((uint32_t)ticks & RTT_TIMESTAMP_MASK);
	} else {
		tcp_seq = validation[0];
	}

	ip_header->ip_src.s_addr = src_ip;
	ip_header->ip_dst.s_addr = dst_ip;
	ip_header->ip_ttl = ttl;

	port_h_t sport = get_src_port(num_source_ports, probe_num, validation);
	tcp_header->th_sport = htons(sport);
	tcp_header->th_dport = dport;
	tcp_header->th_seq = tcp_seq;
	// checksum value must be zero when calculating packet's checksum
	tcp_header->th_sum = 0;
	tcp_header->th_sum = tcp_checksum(zmap_tcp_synscan_tcp_header_len,
					  ip_header->ip_src.s_addr,
					  ip_header->ip_dst.s_addr, tcp_header);

	ip_header->ip_id = ip_id;
	// checksum value must be zero when calculating packet's checksum
	ip_header->ip_sum = 0;
	ip_header->ip_sum = zmap_ip_checksum((unsigned short *)ip_header);

	*buf_len = zmap_tcp_synscan_packet_len;
	return EXIT_SUCCESS;
}

// not static because used by synack scan
void synscan_print_packet(FILE *fp, void *packet)
{
	struct ether_header *ethh = (struct ether_header *)packet;
	struct ip *iph = (struct ip *)&ethh[1];
	struct tcphdr *tcph = (struct tcphdr *)&iph[1];
	if (zconf.fast_dryrun) {
		// We'll just print a binary representation of the dst IP and the dst Port to reduce data output/save time
		struct in_addr *dest_IP = (struct in_addr *)&(iph->ip_dst);
		// Writing binary IP addresses
		const uint8_t IP_ADDR_LEN = 4;
		const uint8_t TCP_PORT_LEN = 2;
		fwrite(&(dest_IP->s_addr),  IP_ADDR_LEN,1, fp);  // Write destination IP (binary)
		fwrite(&(tcph->th_dport),  TCP_PORT_LEN,1, fp);  // Write destination port (binary)
		return;
	}
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
		if (should_validate_src_port && !check_src_port(sport, ports)) {
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
			if (rtt_enabled) {
				if ((ntohl(tcp->th_ack) & RTT_VALIDATION_MASK) != (ntohl(validation[0]) & RTT_VALIDATION_MASK) &&
				    (ntohl(tcp->th_ack) & RTT_VALIDATION_MASK) != ((ntohl(validation[0]) + 1) & RTT_VALIDATION_MASK)) {
					return PACKET_INVALID;
				}
			} else {
				if (ntohl(tcp->th_ack) != ntohl(validation[0]) &&
				    ntohl(tcp->th_ack) != ntohl(validation[0]) + 1) {
					return PACKET_INVALID;
				}
			}
		} else {
			// For non RST packets, recv(ack) == sent(seq) + 1
			if (rtt_enabled) {
				if ((ntohl(tcp->th_ack) & RTT_VALIDATION_MASK) != ((ntohl(validation[0]) + 1) & RTT_VALIDATION_MASK)) {
					return PACKET_INVALID;
				}
			} else {
				if (ntohl(tcp->th_ack) != ntohl(validation[0]) + 1) {
					return PACKET_INVALID;
				}
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


static void add_tcpopt_to_fs(fieldset_t *fs, int64_t *val, const char *label)
{
	if (*val != -1) {
		fs_add_uint64(fs, label, *((uint64_t *) val));
	} else {
		fs_add_null(fs, label);
	}
}

static void parse_tcp_opts(struct tcphdr *tcp, fieldset_t *fs)
{
	int64_t mss = -1, wscale = -1, sack_perm = -1, ts_val = -1, ts_ecr = -1;

	size_t header_size = tcp->th_off * 4;
	for (size_t curr_idx = 20; curr_idx < header_size; ) {
		uint8_t kind = *(((uint8_t *) tcp) + curr_idx);

		// single-octet options without length field
		switch (kind) {
			case TCPOPT_EOL: // End of option list
			case TCPOPT_NOP: // NOP
				curr_idx += 1;
				continue;
			default:
				break;
		}

		if (curr_idx + 1 >= header_size) {
			// length field extends beyond end of header
			break;
		}

		uint8_t len = *(((uint8_t *) tcp) + curr_idx + 1);
		if ((len <= 1) || (curr_idx + len > header_size)) {
			// option length is too small to include the length
			// field itself, or extends beyond end of header
			break;
		}

		uint8_t *val = ((uint8_t *) tcp) + curr_idx + 2;
		switch (kind) {
			case TCPOPT_MAXSEG: // MSS
				if (len != TCPOLEN_MAXSEG) {
					goto break_loop;
				}
				mss = ntohs(*(uint16_t *) val);
				break;

			case TCPOPT_WINDOW: // Window scale
				if (len != TCPOLEN_WINDOW) {
					goto break_loop;
				}
				wscale = pow(2, *((uint8_t *) val));
				break;

			case TCPOPT_SACK_PERMITTED: // SACK permitted
				if (len != TCPOLEN_SACK_PERMITTED) {
					goto break_loop;
				}
				sack_perm = 1;
				break;

			case TCPOPT_TIMESTAMP: // TCP Timestamp
				if (len != TCPOLEN_TIMESTAMP) {
					goto break_loop;
				}
				// Retrieve TS value and TS echo reply
				ts_val = ntohl(*(uint32_t *) val);
				ts_ecr = ntohl(*((uint32_t *) (val + 4)));
				break;

			default:
				break;
		}
		curr_idx += len;
	}

break_loop:
	add_tcpopt_to_fs(fs, &mss, "tcpopt_mss");
	add_tcpopt_to_fs(fs, &wscale, "tcpopt_wscale");
	add_tcpopt_to_fs(fs, &sack_perm, "tcpopt_sack_perm");
	add_tcpopt_to_fs(fs, &ts_val, "tcpopt_ts_val");
	add_tcpopt_to_fs(fs, &ts_ecr, "tcpopt_ts_ecr");
}

// Recover the RTT tick count encoded in the sent sequence number.
static uint64_t
recover_rtt_ticks(uint32_t th_ack, uint32_t *validation, int ack_offset)
{
	return (htonl(ntohl(th_ack) - (uint32_t)ack_offset) ^ validation[0]) & RTT_TIMESTAMP_MASK;
}

static void synscan_process_packet(const u_char *packet, UNUSED uint32_t len,
				   fieldset_t *fs, uint32_t *validation,
				   struct timespec ts)
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
		parse_tcp_opts(tcp, fs);
		if (tcp->th_flags & TH_RST) { // RST packet
			fs_add_constchar(fs, "classification", "rst");
			fs_add_bool(fs, "success", 0);
		} else { // SYNACK packet
			fs_add_constchar(fs, "classification", "synack");
			fs_add_bool(fs, "success", 1);
		}
		fs_add_null_icmp(fs);
		if (rtt_enabled) {
			uint64_t ticks_now = rtt_ticks_from_pcap_ts(ts) & RTT_TIMESTAMP_MASK;
			int ack_offset;
			if (tcp->th_flags & TH_RST) {
				// RST ack may be sent_seq (offset 0) or sent_seq+1 (offset 1)
				ack_offset = ((ntohl(tcp->th_ack) & RTT_VALIDATION_MASK) ==
				              (ntohl(validation[0]) & RTT_VALIDATION_MASK)) ? 0 : 1;
			} else {
				ack_offset = 1;
			}
			// ticks_pkt is the time we sent the packet, encoded in the SEQ number
			uint64_t ticks_pkt = recover_rtt_ticks(tcp->th_ack, validation, ack_offset);
			// ticks_now is recovered from the pcap to minimize processing delay affecting the rtt measurement
			uint64_t rtt_ticks = (ticks_now - ticks_pkt) & RTT_TIMESTAMP_MASK;
			char *rtt_str = malloc(16);
			if (rtt_str) {
				snprintf(rtt_str, 16, "%llu.%llu",
					 (unsigned long long)(rtt_ticks / 10),
					 (unsigned long long)(rtt_ticks % 10));
				fs_add_string(fs, "rtt", rtt_str, 1);
			} else {
				log_warn("tcp_synscan", "failed to allocate memory for RTT string, adding null RTT field");
				fs_add_null(fs, "rtt");
			}
		} else {
			fs_add_null(fs, "rtt");
		}
	} else if (ip_hdr->ip_p == IPPROTO_ICMP) {
		// tcp
		fs_add_null(fs, "sport");
		fs_add_null(fs, "dport");
		fs_add_null(fs, "seqnum");
		fs_add_null(fs, "acknum");
		fs_add_null(fs, "window");
		fs_add_null(fs, "tcpopt_mss");
		fs_add_null(fs, "tcpopt_wscale");
		fs_add_null(fs, "tcpopt_sack_perm");
		fs_add_null(fs, "tcpopt_ts_val");
		fs_add_null(fs, "tcpopt_ts_ecr");
		// global
		fs_add_constchar(fs, "classification", "icmp");
		fs_add_bool(fs, "success", 0);
		// icmp
		fs_populate_icmp_from_iphdr(ip_hdr, len, fs);
		// rtt
		fs_add_null(fs, "rtt");
	}
}

static fielddef_t fields[] = {
    {.name = "sport", .type = "int", .desc = "TCP source port"},
    {.name = "dport", .type = "int", .desc = "TCP destination port"},
    {.name = "seqnum", .type = "int", .desc = "TCP sequence number"},
    {.name = "acknum", .type = "int", .desc = "TCP acknowledgement number"},
    {.name = "window", .type = "int", .desc = "TCP window"},
    {.name = "tcpopt_mss", .type = "int", .desc = "TCP MSS option"},
    {.name = "tcpopt_wscale", .type = "int", .desc = "TCP Window scale option"},
    {.name = "tcpopt_sack_perm", .type = "int", .desc = "TCP SACK permitted option"},
    {.name = "tcpopt_ts_val", .type = "int", .desc = "TCP timestamp option value"},
    {.name = "tcpopt_ts_ecr", .type = "int", .desc = "TCP timestamp option echo reply"},
    CLASSIFICATION_SUCCESS_FIELDSET_FIELDS,
    ICMP_FIELDSET_FIELDS,
    {.name = "rtt", .type = "string", .desc = "RTT in ms to one decimal place, max RTT reliably measured = ~28min"},
};

probe_module_t module_tcp_synscan = {
    .name = "tcp_synscan",
    .pcap_filter = "(tcp && tcp[13] & 4 != 0 || tcp[13] == 18) || icmp",
    .pcap_snaplen = 96,
    .port_args = 1,
    .global_initialize = &synscan_global_initialize,
    .prepare_packet = &synscan_prepare_packet,
    .make_packet = &synscan_make_packet,
    .print_packet = &synscan_print_packet,
    .process_packet = &synscan_process_packet,
    .validate_packet = &synscan_validate_packet,
    .close = NULL,
    .helptext =
	"Probe module that sends a TCP SYN packet to a specific port. Possible "
	"classifications are: synack and rst. A SYN-ACK packet is considered a "
	"success and a reset packet is considered a failed response. "
	"--probe-args accepts comma-separated args:\n"
		" 1.  An optional arg to control TCP header options, "
		"making them identical to common OS stacks:\n"
		"   - \"windows\" (default, MSS + SACK + WindowScale=8)\n"
		"   - \"linux\" (MSS + SACK + Timestamps + WindowScale=7)\n"
		"   - \"bsd\" (MSS + NOP + WindowScale=6 + Timestamps + SACK)\n"
		"   - \"smallest-probes\" (MSS only, fits minimum Ethernet payload, gives a better hitrate than no options while retaining the same send performance)\n"
	        " 2. Add \"rtt\" to enable RTT measurement to reports RTT in ms to 0.1 ms granularity (max ~28 min RTT).\n"
	"Examples: --probe-args=windows, --probe-args=rtt (windows + RTT), "
	"--probe-args=linux,rtt. RTT works best with --batch 1. ",
    .output_type = OUTPUT_TYPE_STATIC,
    .fields = fields,
    .numfields = sizeof(fields) / sizeof(fields[0])};
