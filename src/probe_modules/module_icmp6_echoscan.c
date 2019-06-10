/*
 * ZMapv6 Copyright 2016 Chair of Network Architectures and Services
 * Technical University of Munich
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

// probe module for performing ICMP echo request (ping) scans

// Needed for asprintf
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

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

#define ICMP_SMALLEST_SIZE 5
#define ICMP_TIMXCEED_UNREACH_HEADER_SIZE 8

probe_module_t module_icmp6_echoscan;

int icmp6_echo_global_initialize(struct state_conf *conf)
{
	// Only look at received packets destined to the specified scanning address (useful for parallel zmap scans)
	if (asprintf((char ** restrict) &module_icmp6_echoscan.pcap_filter, "%s && ip6 dst host %s", module_icmp6_echoscan.pcap_filter, conf->ipv6_source_ip) == -1) {
		return 1;
	}

	return EXIT_SUCCESS;
}

static int icmp6_echo_init_perthread(void* buf, macaddr_t *src,
		macaddr_t *gw, __attribute__((unused)) port_h_t dst_port,
		__attribute__((unused)) void **arg_ptr)
{
	memset(buf, 0, MAX_PACKET_SIZE);

	struct ether_header *eth_header = (struct ether_header *) buf;
	make_eth_header_ethertype(eth_header, src, gw, ETHERTYPE_IPV6);

    struct ip6_hdr *ip6_header = (struct ip6_hdr *) (&eth_header[1]);
	// ICMPv6 header plus 8 bytes of data (validation)
	uint16_t payload_len = sizeof(struct icmp6_hdr) + 2*sizeof(uint32_t);
    make_ip6_header(ip6_header, IPPROTO_ICMPV6, payload_len);

	struct icmp6_hdr *icmp6_header = (struct icmp6_hdr*)(&ip6_header[1]);
	make_icmp6_header(icmp6_header);

	return EXIT_SUCCESS;
}

static int icmp6_echo_make_packet(void *buf, UNUSED size_t *buf_len, UNUSED ipaddr_n_t src_ip,  UNUSED ipaddr_n_t dst_ip, uint8_t ttl, uint32_t *validation, UNUSED int probe_num, UNUSED void *arg)
{
	struct ether_header *eth_header = (struct ether_header *) buf;
	struct ip6_hdr *ip6_header = (struct ip6_hdr *)(&eth_header[1]);
	struct icmp6_hdr *icmp6_header = (struct icmp6_hdr*)(&ip6_header[1]);
	uint16_t icmp_idnum = validation[2] & 0xFFFF;

	// Include validation in ICMPv6 payload data
	icmp6_header->icmp6_data32[1] = validation[0];
	icmp6_header->icmp6_data32[2] = validation[1];

	ip6_header->ip6_src = ((struct in6_addr *) arg)[0];
	ip6_header->ip6_dst = ((struct in6_addr *) arg)[1];
	ip6_header->ip6_ctlun.ip6_un1.ip6_un1_hlim = ttl;

	icmp6_header->icmp6_id= icmp_idnum;
	icmp6_header->icmp6_cksum = 0;
	icmp6_header->icmp6_cksum= (uint16_t) icmp6_checksum(
                &ip6_header->ip6_src,
		        &ip6_header->ip6_dst,
				icmp6_header,
				2*sizeof(uint32_t)
                );

	return EXIT_SUCCESS;
}

static void icmp6_echo_print_packet(FILE *fp, void* packet)
{
	struct ether_header *ethh = (struct ether_header *) packet;
	struct ip6_hdr *iph = (struct ip6_hdr *) &ethh[1];
	struct icmp6_hdr *icmp6_header = (struct icmp6_hdr*) (&iph[1]);

	fprintf(fp, "icmp { type: %u | code: %u "
			"| checksum: %#04X | id: %u | seq: %u }\n",
			icmp6_header->icmp6_type,
			icmp6_header->icmp6_code,
			ntohs(icmp6_header->icmp6_cksum),
			ntohs(icmp6_header->icmp6_id),
			ntohs(icmp6_header->icmp6_seq)
		);
	fprintf_ipv6_header(fp, iph);
	fprintf_eth_header(fp, ethh);
	fprintf(fp, "------------------------------------------------------\n");
}


static int icmp6_validate_packet(const struct ip *ip_hdr,
		uint32_t len, __attribute__((unused)) uint32_t *src_ip, uint32_t *validation)
{
    struct ip6_hdr *ip6_hdr = (struct ip6_hdr*) ip_hdr;

	if (ip6_hdr->ip6_nxt != IPPROTO_ICMPV6) {
		return 0;
	}

    // IPv6 header is fixed length at 40 bytes + ICMPv6 header + 8 bytes of ICMPv6 data
	if ( ( sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) + 2 * sizeof(uint32_t)) > len) {
		// buffer not large enough to contain expected icmp header
		return 0;
	}

    // offset iphdr by ip header length of 40 bytes to shift pointer to ICMP6 header
	struct icmp6_hdr *icmp6_h = (struct icmp6_hdr *) (&ip6_hdr[1]);

	// ICMP validation is tricky: for some packet types, we must look inside
	// the payload
	if (icmp6_h->icmp6_type == ICMP6_TIME_EXCEEDED || icmp6_h->icmp6_type == ICMP6_DST_UNREACH
        || icmp6_h->icmp6_type == ICMP6_PACKET_TOO_BIG || icmp6_h->icmp6_type == ICMP6_PARAM_PROB) {

        // IP6 + ICMP6 headers + inner headers + 8 byte payload (validation)
        if (2*sizeof(struct ip6_hdr) + 2*sizeof(struct icmp6_hdr) + 2*sizeof(uint32_t) > len) {
			return 0;
		}

		// Use inner headers for validation
		ip6_hdr = (struct ip6_hdr *) &icmp6_h[1];
		icmp6_h = (struct icmp6_hdr *) &ip6_hdr[1];

		// Send original src and dst IP as data in ICMPv6 payload and regenerate the validation here
        validate_gen_ipv6(&ip6_hdr->ip6_dst, &ip6_hdr->ip6_src,
			     (uint8_t *) validation);
	}
	// validate icmp id
	if (icmp6_h->icmp6_id != (validation[2] & 0xFFFF)) {
		return 0;
	}

	// Validate ICMPv6 data
	if (icmp6_h->icmp6_data32[1] != validation[0] || icmp6_h->icmp6_data32[2] != validation[1]) {
		return 0;
	}

	return 1;
}

static void icmp6_echo_process_packet(const u_char *packet,
		__attribute__((unused)) uint32_t len, fieldset_t *fs,
		__attribute__((unused)) uint32_t *validation)
{
	struct ip6_hdr *ip6_hdr = (struct ip6_hdr *) &packet[sizeof(struct ether_header)];
	struct icmp6_hdr *icmp6_hdr = (struct icmp6_hdr *) (&ip6_hdr[1]);
	fs_add_uint64(fs, "type", icmp6_hdr->icmp6_type);
	fs_add_uint64(fs, "code", icmp6_hdr->icmp6_code);
	fs_add_uint64(fs, "icmp-id", ntohs(icmp6_hdr->icmp6_id));
	fs_add_uint64(fs, "seq", ntohs(icmp6_hdr->icmp6_seq));
        fs_add_string(fs, "outersaddr", make_ipv6_str(&(ip6_hdr->ip6_src)), 1);
	if (icmp6_hdr->icmp6_type == ICMP6_ECHO_REPLY) {
		fs_add_string(fs, "classification", (char*) "echoreply", 0);
		fs_add_uint64(fs, "success", 1);
	} else {
		// Use inner IP header values for unsuccessful ICMP replies
		struct ip6_hdr *ip6_inner_hdr = (struct ip6_hdr *) &icmp6_hdr[1];
		fs_modify_string(fs, "saddr", make_ipv6_str(&(ip6_inner_hdr->ip6_dst)), 1);
		fs_modify_string(fs, "daddr", make_ipv6_str(&(ip6_inner_hdr->ip6_src)), 1);

		switch(icmp6_hdr->icmp6_type) {
			case ICMP6_DST_UNREACH:
                switch(icmp6_hdr->icmp6_code) {
                    case ICMP6_DST_UNREACH_NOROUTE:
                        fs_add_string(fs, "classification", (char*) "unreach_noroute", 0);
                        break;
                    case ICMP6_DST_UNREACH_ADMIN:
                        fs_add_string(fs, "classification", (char*) "unreach_admin", 0);
                        break;
                    case ICMP6_DST_UNREACH_BEYONDSCOPE:
                        fs_add_string(fs, "classification", (char*) "unreach_beyondscope", 0);
                        break;
                    case ICMP6_DST_UNREACH_ADDR:
                        fs_add_string(fs, "classification", (char*) "unreach_addr", 0);
                        break;
                    case ICMP6_DST_UNREACH_NOPORT:
                        fs_add_string(fs, "classification", (char*) "unreach_noport", 0);
                        break;
                    case 5:
                        fs_add_string(fs, "classification", (char*) "unreach_policy", 0);
                        break;
                    case 6:
                        fs_add_string(fs, "classification", (char*) "unreach_rejectroute", 0);
                        break;
                    case 7:
                        fs_add_string(fs, "classification", (char*) "unreach_err_src_route", 0);
                        break;
                    default:
                        fs_add_string(fs, "classification", (char*) "unreach", 0);
                        break;
                }
                break;
			case ICMP6_PACKET_TOO_BIG:
				fs_add_string(fs, "classification", (char*) "toobig", 0);
				break;
			case ICMP6_PARAM_PROB:
				fs_add_string(fs, "classification", (char*) "paramprob", 0);
				break;
			case ICMP6_TIME_EXCEEDED:
				fs_add_string(fs, "classification", (char*) "timxceed", 0);
				break;
			default:
				fs_add_string(fs, "classification", (char*) "other", 0);
				break;
		}
		fs_add_uint64(fs, "success", 0);
	}
}

static fielddef_t fields[] = {
	{.name="type", .type="int", .desc="icmp message type"},
	{.name="code", .type="int", .desc="icmp message sub type code"},
	{.name="icmp-id", .type="int", .desc="icmp id number"},
	{.name="seq", .type="int", .desc="icmp sequence number"},
	{.name="outersaddr", .type="string", .desc="outer src address of icmp reply packet"},
    {.name="classification", .type="string", .desc="probe module classification"},
	{.name="success", .type="int", .desc="did probe module classify response as success"}
};


probe_module_t module_icmp6_echoscan = {
	.name = "icmp6_echoscan",
	.packet_length = 70, // 62, // ICMPv4: 64 bit --> Why 62? ICMPv6 also 64 bit --> Leave 64
	.pcap_filter = "icmp6 && (ip6[40] == 129 || ip6[40] == 3 || ip6[40] == 1 || ip6[40] == 2 || ip6[40] == 4)", // and icmp6[0]=!8",
	.pcap_snaplen =  118, // 14 ethernet header + 40 IPv6 header + 8 ICMPv6 header + 40 inner IPv6 header + 8 inner ICMPv6 header + 8 payload
	.port_args = 0,
	.global_initialize = &icmp6_echo_global_initialize,
	.thread_initialize = &icmp6_echo_init_perthread,
	.make_packet = &icmp6_echo_make_packet,
	.print_packet = &icmp6_echo_print_packet,
	.process_packet = &icmp6_echo_process_packet,
	.validate_packet = &icmp6_validate_packet,
	.close = NULL,
	.fields = fields,
	.numfields = 7};

