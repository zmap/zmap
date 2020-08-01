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
#include <assert.h>

#include "../../lib/includes.h"
#include "../../lib/xalloc.h"
#include "probe_modules.h"
#include "../fieldset.h"
#include "packet.h"
#include "logger.h"
#include "validate.h"

#define ICMP_SMALLEST_SIZE 5
#define ICMP_MAX_PAYLOAD_LEN 1458
#define ICMP_TIMXCEED_UNREACH_HEADER_SIZE 8

probe_module_t module_icmp_echo;

const char *icmp_usage_error =
		"unknown ICMP probe specification (expected file:/path or text:STRING or hex:01020304)";

static size_t icmp_payload_len = 0;
static const size_t icmp_payload_default_len = 20;
static char *icmp_payload = NULL;

int icmp_global_initialize(struct state_conf *conf)
{
	if (!(conf->probe_args && strlen(conf->probe_args) > 0)) {
		icmp_payload = xmalloc(icmp_payload_default_len);
		icmp_payload_len = icmp_payload_default_len;
		return EXIT_SUCCESS;
	}

	char *c = strchr(conf->probe_args, ':');
	if (!c) {
		log_error("icmp", icmp_usage_error);
		return EXIT_FAILURE;
	}
	++c;

	if (strncmp(conf->probe_args, "text", 4) == 0) {
		icmp_payload = strdup(c);
		icmp_payload_len = strlen(icmp_payload);
	} else if (strncmp(conf->probe_args, "file", 4) == 0) {
		FILE *inp = fopen(c, "rb");
		if (!inp) {
			log_error("icmp", "could not open ICMP data file '%s'", c);
			return EXIT_FAILURE;
		}
		if (fseek(inp, 0, SEEK_END)) {
			log_error("icmp", "unable to get size of ICMP data file '%s'", c);
			return EXIT_FAILURE;
		}
		size_t input_size = ftell(inp);
		if (input_size > ICMP_MAX_PAYLOAD_LEN) {
			log_error("icmp", "input file larger than %d bytes and will not fit on the wire (%llu bytes provided)",
					ICMP_MAX_PAYLOAD_LEN, input_size);
			return EXIT_FAILURE;
		}
		if (fseek(inp, 0, SEEK_SET)) {
			log_error("icmp", "unable to read ICMP data file '%s'", c);
			return EXIT_FAILURE;
		}
		icmp_payload = xmalloc(ICMP_MAX_PAYLOAD_LEN);
		icmp_payload_len =
				fread(icmp_payload, 1, ICMP_MAX_PAYLOAD_LEN, inp);
		fclose(inp);
	} else if (strcmp(c, "hex") == 0) {
		if (strlen(c) % 2 != 0) {
			log_error("icmp", "invalid hex input (length must be a multiple of 2)");
			return EXIT_FAILURE;
		}
		icmp_payload_len = strlen(c) / 2;
		icmp_payload = xmalloc(icmp_payload_len);

		unsigned int n;
		for (size_t i = 0; i < icmp_payload_len; i++) {
			if (sscanf(c + (i * 2), "%2x", &n) != 1) {
				free(icmp_payload);
				log_error("icmp", "non-hex character: '%c'", c[i * 2]);
				return EXIT_FAILURE;
			}
			icmp_payload[i] = (char) (n & 0xff);
		}
	} else {
		log_error("icmp", icmp_usage_error);
		return EXIT_FAILURE;
	}

	if (icmp_payload_len > ICMP_MAX_PAYLOAD_LEN) {
		log_error("icmp", "reducing ICMP payload must be at most %d bytes to fit on the wire (%d were provided)\n",
				 ICMP_MAX_PAYLOAD_LEN, icmp_payload_len);
		return EXIT_FAILURE;
	}

	module_icmp_echo.packet_length = sizeof(struct ether_header) +
							   sizeof(struct ip) + ICMP_MINLEN + icmp_payload_len;
	assert(module_icmp_echo.packet_length <= 1500);
	return EXIT_SUCCESS;
}


int icmp_global_cleanup(__attribute__((unused)) struct state_conf *zconf,
					    __attribute__((unused)) struct state_send *zsend,
					    __attribute__((unused)) struct state_recv *zrecv)
{
	if (icmp_payload) {
		free(icmp_payload);
		icmp_payload = NULL;
	}

	return EXIT_SUCCESS;
}


static int icmp_echo_init_perthread(void *buf, macaddr_t *src, macaddr_t *gw,
				    __attribute__((unused)) port_h_t dst_port,
				    __attribute__((unused)) void **arg_ptr)
{
	memset(buf, 0, MAX_PACKET_SIZE);

	struct ether_header *eth_header = (struct ether_header *)buf;
	make_eth_header(eth_header, src, gw);

	struct ip *ip_header = (struct ip *)(&eth_header[1]);
	uint16_t len = htons(sizeof(struct ip) + ICMP_MINLEN + icmp_payload_len);
	make_ip_header(ip_header, IPPROTO_ICMP, len);

	struct icmp *icmp_header = (struct icmp *)(&ip_header[1]);
	make_icmp_header(icmp_header);

	char *payload = (char *)icmp_header + ICMP_MINLEN;

	memcpy(payload, icmp_payload, icmp_payload_len);

	return EXIT_SUCCESS;
}

static int icmp_echo_make_packet(void *buf, UNUSED size_t *buf_len,
				 ipaddr_n_t src_ip, ipaddr_n_t dst_ip, uint8_t ttl,
				 uint32_t *validation, UNUSED int probe_num,
				 UNUSED void *arg)
{
	struct ether_header *eth_header = (struct ether_header *)buf;
	struct ip *ip_header = (struct ip *)(&eth_header[1]);
	struct icmp *icmp_header = (struct icmp *)(&ip_header[1]);

	uint16_t icmp_idnum = validation[1] & 0xFFFF;
	uint16_t icmp_seqnum = validation[2] & 0xFFFF;

	ip_header->ip_src.s_addr = src_ip;
	ip_header->ip_dst.s_addr = dst_ip;
	ip_header->ip_ttl = ttl;

	icmp_header->icmp_id = icmp_idnum;
	icmp_header->icmp_seq = icmp_seqnum;

	icmp_header->icmp_cksum = 0;
	icmp_header->icmp_cksum = icmp_checksum((unsigned short *)icmp_header, ICMP_MINLEN + icmp_payload_len);

	// Update the IP and UDP headers to match the new payload length
	size_t ip_len = sizeof(struct ip) + ICMP_MINLEN + icmp_payload_len;
	ip_header->ip_len = htons(ip_len);

	ip_header->ip_sum = 0;
	ip_header->ip_sum = zmap_ip_checksum((unsigned short *)ip_header);
	*buf_len = ip_len + sizeof(struct ether_header);

	return EXIT_SUCCESS;
}

static void icmp_echo_print_packet(FILE *fp, void *packet)
{
	struct ether_header *ethh = (struct ether_header *)packet;
	struct ip *iph = (struct ip *)&ethh[1];
	struct icmp *icmp_header = (struct icmp *)(&iph[1]);

	fprintf(fp,
		"icmp { type: %u | code: %u "
		"| checksum: %#04X | id: %u | seq: %u }\n",
		icmp_header->icmp_type, icmp_header->icmp_code,
		ntohs(icmp_header->icmp_cksum), ntohs(icmp_header->icmp_id),
		ntohs(icmp_header->icmp_seq));
	fprintf_ip_header(fp, iph);
	fprintf_eth_header(fp, ethh);
	fprintf(fp, "------------------------------------------------------\n");
}

static int icmp_validate_packet(const struct ip *ip_hdr, uint32_t len,
				uint32_t *src_ip, uint32_t *validation)
{
	if (ip_hdr->ip_p != IPPROTO_ICMP) {
		return 0;
	}
	// check if buffer is large enough to contain expected icmp header
	if (((uint32_t)4 * ip_hdr->ip_hl + ICMP_SMALLEST_SIZE) > len) {
		return 0;
	}
	struct icmp *icmp_h =
	    (struct icmp *)((char *)ip_hdr + 4 * ip_hdr->ip_hl);
	uint16_t icmp_idnum = icmp_h->icmp_id;
	uint16_t icmp_seqnum = icmp_h->icmp_seq;
	// ICMP validation is tricky: for some packet types, we must look inside
	// the payload
	if (icmp_h->icmp_type == ICMP_TIMXCEED ||
	    icmp_h->icmp_type == ICMP_UNREACH) {
		// Should have 16B TimeExceeded/Dest_Unreachable header +
		// original IP header + 1st 8B of original ICMP frame
		if ((4 * ip_hdr->ip_hl + ICMP_TIMXCEED_UNREACH_HEADER_SIZE +
		     sizeof(struct ip)) > len) {
			return 0;
		}
		struct ip *ip_inner = (struct ip *)((char *)icmp_h + 8);
		if (((uint32_t)4 * ip_hdr->ip_hl +
		     ICMP_TIMXCEED_UNREACH_HEADER_SIZE + 4 * ip_inner->ip_hl +
		     8 /*1st 8 bytes of original*/) > len) {
			return 0;
		}
		struct icmp *icmp_inner =
		    (struct icmp *)((char *)ip_inner + 4 * ip_hdr->ip_hl);
		// Regenerate validation and icmp id based off inner payload
		icmp_idnum = icmp_inner->icmp_id;
		icmp_seqnum = icmp_inner->icmp_seq;
		*src_ip = ip_inner->ip_dst.s_addr;
		validate_gen(ip_hdr->ip_dst.s_addr, ip_inner->ip_dst.s_addr,
			     (uint8_t *)validation);
	}
	// validate icmp id and seqnum
	if (icmp_idnum != (validation[1] & 0xFFFF)) {
		return 0;
	}
	if (icmp_seqnum != (validation[2] & 0xFFFF)) {
		return 0;
	}
	return 1;
}

static void icmp_echo_process_packet(const u_char *packet,
				     uint32_t len,
				     fieldset_t *fs,
				     __attribute__((unused))
				     uint32_t *validation,
				     __attribute__((unused)) struct timespec ts)
{
	struct ip *ip_hdr = (struct ip *)&packet[sizeof(struct ether_header)];
	struct icmp *icmp_hdr =
	    (struct icmp *)((char *)ip_hdr + 4 * ip_hdr->ip_hl);
	fs_add_uint64(fs, "type", icmp_hdr->icmp_type);
	fs_add_uint64(fs, "code", icmp_hdr->icmp_code);
	fs_add_uint64(fs, "icmp_id", ntohs(icmp_hdr->icmp_id));
	fs_add_uint64(fs, "seq", ntohs(icmp_hdr->icmp_seq));

	uint32_t hdrlen = sizeof(struct ether_header) + 4 * ip_hdr->ip_hl + 4;

	switch (icmp_hdr->icmp_type) {
	case ICMP_ECHOREPLY:
		fs_add_string(fs, "classification", (char *)"echoreply", 0);
		fs_add_uint64(fs, "success", 1);
		break;
	case ICMP_UNREACH:
		fs_add_string(fs, "classification", (char *)"unreach", 0);
		fs_add_bool(fs, "success", 0);
		break;
	case ICMP_SOURCEQUENCH:
		fs_add_string(fs, "classification", (char *)"sourcequench", 0);
		fs_add_bool(fs, "success", 0);
		break;
	case ICMP_REDIRECT:
		fs_add_string(fs, "classification", (char *)"redirect", 0);
		fs_add_bool(fs, "success", 0);
		break;
	case ICMP_TIMXCEED:
		fs_add_string(fs, "classification", (char *)"timxceed", 0);
		fs_add_bool(fs, "success", 0);
		break;
	default:
		fs_add_string(fs, "classification", (char *)"other", 0);
		fs_add_bool(fs, "success", 0);
		break;
	}

	int datalen = len - hdrlen;

	if(datalen > 0) {
		const uint8_t *data = (uint8_t *)&packet[hdrlen];
		fs_add_binary(fs, "data", (size_t)datalen, (void *)data, 0);
	} else {
		fs_add_null(fs, "data");
	}

}

static fielddef_t fields[] = {
	{.name = "type", .type = "int", .desc = "icmp message type"},
	{.name = "code", .type = "int", .desc = "icmp message sub type code"},
	{.name = "icmp-id", .type = "int", .desc = "icmp id number"},
	{.name = "seq", .type = "int", .desc = "icmp sequence number"},
	{.name = "classification",
	 .type = "string",
	 .desc = "probe module classification"},
	{.name = "success",
	 .type = "bool",
	 .desc = "did probe module classify response as success"},
	{.name = "data", .type = "binary", .desc = "ICMP payload"}};

probe_module_t module_icmp_echo = {.name = "icmp_echoscan",
				   .packet_length = 48,
				   .pcap_filter = "icmp and icmp[0]!=8",
				   .pcap_snaplen = 96,
				   .port_args = 0,
				   .global_initialize = &icmp_global_initialize,
				   .close = &icmp_global_cleanup,
				   .thread_initialize =
				       &icmp_echo_init_perthread,
				   .make_packet = &icmp_echo_make_packet,
				   .print_packet = &icmp_echo_print_packet,
				   .process_packet = &icmp_echo_process_packet,
				   .validate_packet = &icmp_validate_packet,
				   .helptext = "Probe module that sends ICMP echo requests to hosts.\n"
					   "Payload of ICMP packets will consist of zeroes unless you customize it with\n"
					   " --probe-args=file:/path_to_payload_file\n"
					   " --probe-args=text:SomeText\n"
					   " --probe-args=hex:5061796c6f6164",
				   .output_type = OUTPUT_TYPE_STATIC,
				   .fields = fields,
				   .numfields = 7};
