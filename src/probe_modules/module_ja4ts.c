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
#include <math.h>

#include "cachehash.h"

#include "../../lib/includes.h"
#include "../../lib/logger.h"
#include "../../lib/blocklist.h"
#include "../fieldset.h"
#include "probe_modules.h"
#include "packet.h"
#include "validate.h"
#include "module_tcp_synscan.h"

#define ZMAP_JA4TS_TCP_HEADER_LEN 40
#define ZMAP_JA4TS_PACKET_LEN 74

// TCP Option Kind Values
#define TCP_OPTION_KIND_MSS 2
#define TCP_OPTION_KIND_WINDOW_SCALE 3
#define TCP_OPTION_KIND_NO_OP 1
#define TCP_OPTION_END 0

static uint16_t num_source_ports;
static cachehash *ch = NULL;
static char *iptables_check = "iptables -C OUTPUT -p tcp -d %s --tcp-flags RST RST -j DROP"; 
static char *iptables_add = "iptables -A OUTPUT -p tcp -d %s --tcp-flags RST RST -j DROP"; 
static char *iptables_delete = "iptables -D OUTPUT -p tcp -d %s --tcp-flags RST RST -j DROP"; 

typedef struct ja4t_tuple {
        int saddr;
        int daddr;
        int sport;
        int dport;
} ja4t_tuple_t;

typedef struct ja4t_timedata {
	struct timespec ts;
	uint16_t window_size;
	uint16_t mss_value;
	uint8_t scaling_factor;
	char *options;
	char retransmits[256];
} ja4t_timedata_t;

static int num_of_digits(int n)
{
	return ( n==0 ) ? 1 : (int) log10(n)+1;
}

static int timediff(const struct timespec *time1, const struct timespec *time0) {
  	return (int) (((time1->tv_sec - time0->tv_sec)
            + (time1->tv_nsec - time0->tv_nsec) / 1000000000.0) * 10);
}

static install_iptable_rules() {
        char cidr[50];
	char command[500];
        bl_cidr_node_t *b = get_allowlisted_cidrs();
        if (b) {
                do {
			memset(command, 0, 500);
			cidr[0] = '\0';

                        struct in_addr addr;
                        addr.s_addr = b->ip_address;
                        sprintf(cidr, "%s/%i", inet_ntoa(addr), b->prefix_len);
			sprintf(command, iptables_check, cidr);

			int ret = system(command);
			printf("%s - %d \n", command, ret);
			if (ret == 256) {
			        memset(command, 0, 500);
			    	sprintf(command, iptables_add, cidr);
			        ret = system(command);
			}
                } while (b && (b = b->next));
        }
}

static remove_iptable_rules() {
        char cidr[50];
	char command[500];
        bl_cidr_node_t *b = get_allowlisted_cidrs();
        if (b) {
                do {
			memset(command, 0, 500);
			cidr[0] = '\0';

                        struct in_addr addr;
                        addr.s_addr = b->ip_address;
                        sprintf(cidr, "%s/%i", inet_ntoa(addr), b->prefix_len);
			sprintf(command, iptables_delete, cidr);
			int ret = system(command);
                } while (b && (b = b->next));
        }
}

static int ja4tscan_global_initialize(struct state_conf *state)
{
	num_source_ports =
	    state->source_port_last - state->source_port_first + 1;

	if (state->dedup_method == DEDUP_METHOD_NONE) 
	    install_iptable_rules();
	return EXIT_SUCCESS;
}

static int ja4tscan_global_cleanup(UNUSED struct state_conf *zconf,
                              UNUSED struct state_send *zsend,
                              UNUSED struct state_recv *zrecv)
{
	if (zconf->dedup_method == DEDUP_METHOD_NONE) 
	    remove_iptable_rules();
	return EXIT_SUCCESS;
}

static int ja4tscan_init_perthread(void *buf, macaddr_t *src, macaddr_t *gw,
				   UNUSED void **arg_ptr)
{
        ch = cachehash_init(10000, NULL);
	struct ether_header *eth_header = (struct ether_header *)buf;
	make_eth_header(eth_header, src, gw);
	struct ip *ip_header = (struct ip *)(&eth_header[1]);
	uint16_t len = htons(sizeof(struct ip) + ZMAP_JA4TS_TCP_HEADER_LEN);
	make_ip_header(ip_header, IPPROTO_TCP, len);
	struct tcphdr *tcp_header = (struct tcphdr *)(&ip_header[1]);
	make_tcp_header(tcp_header, TH_SYN);
	set_mss_option(tcp_header);
	set_additional_options(tcp_header);
	return EXIT_SUCCESS;
}

static int ja4tscan_make_packet(void *buf, size_t *buf_len, ipaddr_n_t src_ip,
				ipaddr_n_t dst_ip, port_n_t dport, uint8_t ttl,
				uint32_t *validation, int probe_num,
				UNUSED void *arg)
{

	struct ether_header *eth_header = (struct ether_header *)buf;
	struct ip *ip_header = (struct ip *)(&eth_header[1]);
	struct tcphdr *tcp_header = (struct tcphdr *)(&ip_header[1]);
	uint32_t tcp_seq = validation[0];

	//uint8_t *tcp_options =
	//    (uint8_t *)(&tcp_header[1]); // Points to the start of TCP options

	ip_header->ip_src.s_addr = src_ip;
	ip_header->ip_dst.s_addr = dst_ip;
	ip_header->ip_ttl = ttl;

	port_h_t sport = get_src_port(num_source_ports, probe_num, validation);
	tcp_header->th_sport = htons(sport);
	tcp_header->th_dport = dport;
	tcp_header->th_seq = tcp_seq;

	// checksum value must be zero when calculating packet's checksum
	tcp_header->th_sum = 0;
	tcp_header->th_sum =
	    tcp_checksum(ZMAP_JA4TS_TCP_HEADER_LEN, ip_header->ip_src.s_addr,
			 ip_header->ip_dst.s_addr, tcp_header);
	// checksum value must be zero when calculating packet's checksum
	ip_header->ip_sum = 0;
	ip_header->ip_sum = zmap_ip_checksum((unsigned short *)ip_header);

	*buf_len = ZMAP_JA4TS_PACKET_LEN;
	return EXIT_SUCCESS;
}

static int ja4tscan_validate_packet(const struct ip *ip_hdr, uint32_t len,
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

static void ja4tscan_process_packet(const u_char *packet, UNUSED uint32_t len,
				    fieldset_t *fs, UNUSED uint32_t *validation,
				    struct timespec ts)
{
	struct ip *ip_hdr = get_ip_header(packet, len);
	assert(ip_hdr);
	if (ip_hdr->ip_p == IPPROTO_TCP) {
		struct tcphdr *tcp = get_tcp_header(ip_hdr, len);
		assert(tcp);

		ja4t_tuple_t t = {.saddr = ip_hdr->ip_src.s_addr, .daddr = ip_hdr->ip_dst.s_addr, .sport = tcp->th_sport, .dport = tcp->th_dport };
		ja4t_timedata_t *timedata = cachehash_get(ch, &t, sizeof(ja4t_tuple_t));

		if (timedata != NULL) {
		    int diff = timediff(&ts, &timedata->ts);
		    if (tcp->th_flags & TH_RST) { 
		        snprintf(timedata->retransmits + strlen(timedata->retransmits), num_of_digits(diff)+3, "R%d-", diff);
		    } else {
		        snprintf(timedata->retransmits + strlen(timedata->retransmits), num_of_digits(diff)+2, "%d-", diff);
	 	    }
		    timedata->ts.tv_sec = ts.tv_sec;
		    timedata->ts.tv_nsec = ts.tv_nsec;
		} else {
		    timedata = malloc(sizeof(ja4t_timedata_t));
	            timedata->ts.tv_sec = ts.tv_sec;
	            timedata->ts.tv_nsec = ts.tv_nsec;
		    timedata->retransmits[0] = '\0';
		    timedata->options = malloc(sizeof(char) * 100);
		    timedata->options[0] = '\0';
		    timedata->window_size = 0;
		    timedata->scaling_factor = 0;
		    timedata->mss_value = 0;
		    cachehash_put(ch, &t, sizeof(ja4t_tuple_t), (void *)timedata);
		}

		// JA4TS IMPLEMENTATION
		// Pointer to the start of TCP options
		// +1 because the 'tcp' variable points to the TCP header
		uint8_t *tcp_options = (uint8_t *)(tcp + 1);

		// Length of TCP options field in 32-bit words (DWORDs)
		// th_off is the offset in 32-bit words
		int options_length = (tcp->th_off - 5) * 4;
		int buffer_size = options_length;

		// PARSE OPTIONS
		uint8_t remaining_length = options_length;
		int offset = 0;

		// initialize variables
		uint16_t mss_value = 0;
		uint8_t scaling_factor = 0;
		uint8_t option_kinds[100];
		int num_option_kinds = 0;

		while (remaining_length > 0) {
			if (remaining_length < sizeof(uint8_t)) {
				// Not enough bytes left for any more options
				break;
			}

			uint8_t option_kind = tcp_options[offset];
			uint8_t option_length =
			    (option_kind == TCP_OPTION_KIND_NO_OP ||
			     option_kind == TCP_OPTION_END)
				? 1
				: tcp_options[offset + 1];

			// Check for malformed packet (option_length too small or beyond remaining_length)
			if (option_length < 1 ||
			    option_length > remaining_length) {
				break;
			}

			option_kinds[num_option_kinds] = option_kind;
			num_option_kinds++;

			switch (option_kind) {
			case TCP_OPTION_KIND_MSS:
				// The MSS value is 2 bytes following the Kind and Length fields
				mss_value = ntohs(
				    *(uint16_t *)(tcp_options + offset + 2));
				break;

			case TCP_OPTION_KIND_WINDOW_SCALE:
				// The scaling factor is 1 byte following the Kind and Length fields
				scaling_factor = tcp_options[offset + 2];
				break;

			case TCP_OPTION_KIND_NO_OP:
				// has no option length, decrement remaining_length by 1
				remaining_length--;
				break;

			case TCP_OPTION_END:
				// end of options, set remaining_length to 0
				remaining_length = 0;
				break;

			default:
				break;
			}

			// Update the remaining length and offset for the next option
			remaining_length -= option_length;
			offset += option_length;
			// Check if offset has exceeded buffer bounds (consider buffer_size as the size of tcp_options)
			if (offset > buffer_size) {
				break;
			}
		}

		// b: TCP Parameters
		// Options are processed only for the first SYN-ACK
		// For retransmissions and RST, we use the cached value
		if (strlen(timedata->options) == 0) {
		    for (int i = 0; i < num_option_kinds; i++) {
			// Convert the current option kind to a string
			char option_kind_str[5];
			snprintf(option_kind_str, sizeof(option_kind_str), "%d",
				 option_kinds[i]);

			// If the option_kinds_str is not empty, append a hyphen separator
			if (timedata->options[0] != '\0') {
				strncat(timedata->options, "-", 1);
			}

			// Append the current sorted option kind
			strncat(timedata->options, option_kind_str, strlen(option_kind_str));
		    }

		    if (strlen(timedata->options) == 0)
		        snprintf(timedata->options, 3, "%s", "00");
	 	}

		// a: window size
		// Window size is processed from the first SYN-ACK
		if (timedata->window_size == 0) 
		    timedata->window_size = ntohs(tcp->th_win);
		if (timedata->mss_value == 0) 
		    timedata->mss_value = mss_value;
		if (timedata->scaling_factor == 0) 
		    timedata->scaling_factor = scaling_factor;

		// Calculate the required size for ja4ts_str
		int required_size =
		    snprintf(NULL, 0, "%u", timedata->window_size) +
		    strlen(timedata->options) + // For b: TCP Parameters
		    strlen("_") +		   // Separator between b and c
		    num_of_digits(timedata->mss_value) +		   // For c: MSS mss_value
		    strlen("_") +		   // Separator between c and d
		    num_of_digits(timedata->scaling_factor) + 2;  // For d: Window Scale
		
		int extra_room = 0;		
		if ((timedata != NULL) && (strlen(timedata->retransmits) > 0))
		    extra_room = strlen(timedata->retransmits);

		// Allocate memory for ja4ts_str
		char *ja4ts_str = (char *)malloc(required_size + extra_room);

		// Construct ja4ts_str
		snprintf(ja4ts_str, required_size, "%u_%s_%02u_%d",
			 timedata->window_size, timedata->options, timedata->mss_value,
			 timedata->scaling_factor);
	
		// Allocate extra space to include retransmits
		if (extra_room > 0) {
		    printf ("adding @:%d, extra_room:%d, retransmit:%s\n", required_size, extra_room, timedata->retransmits);
		    snprintf(ja4ts_str + strlen(ja4ts_str), extra_room+1, "_%s", timedata->retransmits);
		}

		log_debug("ja4ts", "JA4TS: %s", ja4ts_str);
		log_debug("ja4ts", "IP: %s",
			  make_ip_str(ip_hdr->ip_src.s_addr));

		fs_add_uint64(fs, "sport", (uint64_t)ntohs(tcp->th_sport));
		fs_add_uint64(fs, "dport", (uint64_t)ntohs(tcp->th_dport));
		fs_add_uint64(fs, "seqnum", (uint64_t)ntohl(tcp->th_seq));
		fs_add_uint64(fs, "acknum", (uint64_t)ntohl(tcp->th_ack));
		fs_add_uint64(fs, "window", (uint64_t)ntohs(tcp->th_win));
		fs_add_string(fs, "ja4ts", (char *)ja4ts_str, 0);
		fs_add_uint64(fs, "timestamp", (uint64_t)ts.tv_sec);
		fs_add_uint64(fs, "ip_src_num",
			      (uint64_t)ntohl(ip_hdr->ip_src.s_addr));

		if (tcp->th_flags & TH_RST) { // RST packet
			fs_add_constchar(fs, "classification", "rst");
			fs_add_bool(fs, "success", 0);
		} else { // SYNACK packet
			fs_add_constchar(fs, "classification", "synack");
			fs_add_bool(fs, "success", 1);
		}
		fs_add_null_icmp(fs);
	} else if (ip_hdr->ip_p == IPPROTO_ICMP) {
		log_debug("ja4ts", "ICMP packet");
		// tcp
		fs_add_null(fs, "sport");
		fs_add_null(fs, "dport");
		fs_add_null(fs, "seqnum");
		fs_add_null(fs, "acknum");
		fs_add_null(fs, "window");
		fs_add_null(fs, "ja4ts");
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
    {.name = "ja4ts", .type = "string", .desc = "TCP JA3 hash"},
    {.name = "timestamp", .type = "int", .desc = "Unix Epoch timestamp"},
    {.name = "ip_src_num", .type = "int", .desc = "Source IP address"},

    CLASSIFICATION_SUCCESS_FIELDSET_FIELDS,
    ICMP_FIELDSET_FIELDS,
};

probe_module_t module_ja4ts = {
    .name = "ja4ts",
    .max_packet_length = ZMAP_JA4TS_PACKET_LEN,
    .pcap_filter = "tcp",
    .pcap_snaplen = 256,
    .port_args = 1,
    .global_initialize = &ja4tscan_global_initialize,
    .thread_initialize = &ja4tscan_init_perthread,
    .make_packet = &ja4tscan_make_packet,
    .print_packet = &synscan_print_packet,
    .process_packet = &ja4tscan_process_packet,
    .validate_packet = &ja4tscan_validate_packet,
    .close = &ja4tscan_global_cleanup,
    .helptext = "Probe module that sends a TCP SYN packet to a specific "
		"port. Possible classifications are: synack and rst. A "
		"SYN-ACK packet is considered a success and a reset packet "
		"is considered a failed response.",
    .output_type = OUTPUT_TYPE_STATIC,
    .fields = fields,
    .numfields = sizeof(fields) / sizeof(fields[0])};
