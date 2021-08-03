/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include "../../lib/includes.h"
#include "../../lib/logger.h"
#include "../../lib/xalloc.h"
#include "../fieldset.h"
#include "probe_modules.h"
#include "packet.h"
#include "module_udp.h"

#define ICMP_UNREACH_HEADER_SIZE 8

static const char *upnp_query = "M-SEARCH * HTTP/1.1\r\n"
				"Host:239.255.255.250:1900\r\n"
				"ST:upnp:rootdevice\r\n"
				"Man:\"ssdp:discover\"\r\nMX:3\r\n\r\n";

probe_module_t module_upnp;

static int num_ports;

int upnp_global_initialize(struct state_conf *state)
{
	num_ports = state->source_port_last - state->source_port_first + 1;
	udp_set_num_ports(num_ports);
	return EXIT_SUCCESS;
}

int upnp_init_perthread(void *buf, macaddr_t *src, macaddr_t *gw,
			port_h_t dst_port,
			UNUSED void **arg_ptr)
{
	memset(buf, 0, MAX_PACKET_SIZE);
	struct ether_header *eth_header = (struct ether_header *)buf;
	make_eth_header(eth_header, src, gw);
	struct ip *ip_header = (struct ip *)(&eth_header[1]);

	uint16_t len = htons(sizeof(struct ip) + sizeof(struct udphdr) +
			     strlen(upnp_query));
	make_ip_header(ip_header, IPPROTO_UDP, len);

	struct udphdr *udp_header = (struct udphdr *)(&ip_header[1]);
	len = sizeof(struct udphdr) + strlen(upnp_query);
	make_udp_header(udp_header, dst_port, len);

	char *payload = (char *)(&udp_header[1]);

	assert(sizeof(struct ether_header) + sizeof(struct ip) +
		   sizeof(struct udphdr) + strlen(upnp_query) <=
	       MAX_PACKET_SIZE);

	assert(MAX_PACKET_SIZE - ((char *)payload - (char *)buf) >
	       (int)strlen(upnp_query));
	strcpy(payload, upnp_query);

	return EXIT_SUCCESS;
}

int upnp_validate_packet(const struct ip *ip_hdr, uint32_t len,
			 uint32_t *src_ip, uint32_t *validation)
{
	return udp_do_validate_packet(ip_hdr, len, src_ip, validation,
				      num_ports, zconf.target_port);
}


void upnp_process_packet(const u_char *packet,
			 UNUSED uint32_t len, fieldset_t *fs,
			 UNUSED uint32_t *validation,
			 UNUSED struct timespec ts)
{
	struct ip *ip_hdr = (struct ip *)&packet[sizeof(struct ether_header)];
	if (ip_hdr->ip_p == IPPROTO_UDP) {
		struct udphdr *udp =
		    (struct udphdr *)((char *)ip_hdr + ip_hdr->ip_hl * 4);

		char *payload = (char *)(&udp[1]);
		uint16_t plen = udp->uh_ulen - 8;

		char *s = xmalloc(plen + 1);
		strncpy(s, payload, plen);
		s[plen] = 0;

		int is_first = 1;
		const char *classification = "none";
		uint64_t is_success = 0;

		char *server = NULL, *location = NULL, *usn = NULL, *st = NULL,
		     *cachecontrol = NULL, *ext = NULL, *xusragent = NULL,
		     *date = NULL, *agent = NULL;

		char *pch = strtok(s, "\n");
		while (pch != NULL) {
			if (pch[strlen(pch) - 1] == '\r') {
				pch[strlen(pch) - 1] = '\0';
			}
			if (strlen(pch) == 0) {
				pch = strtok(NULL, "\n");
				continue;
			}
			// the first pch is always supposed to be an HTTP
			// response
			if (is_first) {
				if (strcmp(pch, "HTTP/1.1 200 OK")) {
					classification = "no-http-header";
					is_success = 0;
					goto cleanup;
				}
				is_first = 0;
				is_success = 1;
				classification = "upnp";
				pch = strtok(NULL, "\n");
				continue;
			}
			char *value = pch;
			char *key = strsep(&value, ":");
			if (!key) {
				pch = strtok(NULL, "\n");
				continue;
			}
			if (!value) {
				pch = strtok(NULL, "\n");
				continue;
			}
			if (value[0] == ' ') {
				value += (size_t)1;
			}
			if (!strcasecmp(key, "server")) {
				server = strdup(value);
			} else if (!strcasecmp(key, "location")) {
				location = strdup(value);
			} else if (!strcasecmp(key, "USN")) {
				usn = strdup(value);
			} else if (!strcasecmp(key, "EXT")) {
				ext = strdup(value);
			} else if (!strcasecmp(key, "ST")) {
				st = strdup(value);
			} else if (!strcasecmp(key, "Agent")) {
				agent = strdup(value);
			} else if (!strcasecmp(key, "X-User-Agent")) {
				xusragent = strdup(value);
			} else if (!strcasecmp(key, "date")) {
				date = strdup(value);
			} else if (!strcasecmp(key, "Cache-Control")) {
				cachecontrol = strdup(value);
			} else {
				// log_debug("upnp-module", "new key: %s", key);
			}
			pch = strtok(NULL, "\n");
		}

	cleanup:
		fs_add_string(fs, "classification", (char *)classification, 0);
		fs_add_bool(fs, "success", is_success);
		fs_chkadd_unsafe_string(fs, "server", server, 1);
		fs_chkadd_unsafe_string(fs, "location", location, 1);
		fs_chkadd_unsafe_string(fs, "usn", usn, 1);
		fs_chkadd_unsafe_string(fs, "st", st, 1);
		fs_chkadd_unsafe_string(fs, "ext", ext, 1);
		fs_chkadd_unsafe_string(fs, "cache_control", cachecontrol, 1);
		fs_chkadd_unsafe_string(fs, "x_user_agent", xusragent, 1);
		fs_chkadd_unsafe_string(fs, "agent", agent, 1);
		fs_chkadd_unsafe_string(fs, "date", date, 1);
		fs_add_uint64(fs, "sport", ntohs(udp->uh_sport));
		fs_add_uint64(fs, "dport", ntohs(udp->uh_dport));
		fs_add_null(fs, "icmp_responder");
		fs_add_null(fs, "icmp_type");
		fs_add_null(fs, "icmp_code");
		fs_add_null(fs, "icmp_unreach_str");

		fs_add_binary(fs, "data",
			      (ntohs(udp->uh_ulen) - sizeof(struct udphdr)),
			      (void *)&udp[1], 0);

		free(s);
	} else if (ip_hdr->ip_p == IPPROTO_ICMP) {
		fs_add_constchar(fs, "classification", "icmp");
		fs_add_uint64(fs, "success", 0);

		fs_add_null(fs, "server");
		fs_add_null(fs, "location");
		fs_add_null(fs, "usn");
		fs_add_null(fs, "st");
		fs_add_null(fs, "ext");
		fs_add_null(fs, "cache_control");
		fs_add_null(fs, "x_user_agent");
		fs_add_null(fs, "agent");
		fs_add_null(fs, "date");

		fs_add_null(fs, "sport");
		fs_add_null(fs, "dport");

		fs_populate_icmp_from_iphdr(ip_hdr, len, fs);
		fs_add_null(fs, "data");
	} else {
		fs_add_constchar(fs, "classification", "other");
		fs_add_bool(fs, "success", 0);
		fs_add_null(fs, "server");
		fs_add_null(fs, "location");
		fs_add_null(fs, "usn");
		fs_add_null(fs, "st");
		fs_add_null(fs, "ext");
		fs_add_null(fs, "cache_control");
		fs_add_null(fs, "x_user_agent");
		fs_add_null(fs, "agent");
		fs_add_null(fs, "date");
		fs_add_null(fs, "sport");
		fs_add_null(fs, "dport");
		fs_add_null(fs, "icmp_responder");
		fs_add_null(fs, "icmp_type");
		fs_add_null(fs, "icmp_code");
		fs_add_null(fs, "icmp_unreach_str");
		fs_add_null(fs, "data");
	}
}

static fielddef_t fields[] = {
    {.name = "classification",
     .type = "string",
     .desc = "packet classification"},
    {.name = "success",
     .type = "bool",
     .desc = "is response considered success"},

    {.name = "server", .type = "string", .desc = "UPnP server"},
    {.name = "location", .type = "string", .desc = "UPnP location"},
    {.name = "usn", .type = "string", .desc = "UPnP usn"},
    {.name = "st", .type = "string", .desc = "UPnP st"},
    {.name = "ext", .type = "string", .desc = "UPnP ext"},
    {.name = "cache_control", .type = "string", .desc = "UPnP cache-control"},
    {.name = "x_user_agent", .type = "string", .desc = "UPnP x-user-agent"},
    {.name = "agent", .type = "string", .desc = "UPnP agent"},
    {.name = "date", .type = "string", .desc = "UPnP date"},

    {.name = "sport", .type = "int", .desc = "UDP source port"},
    {.name = "dport", .type = "int", .desc = "UDP destination port"},
    ICMP_FIELDSET_FIELDS,
    {.name = "data", .type = "binary", .desc = "UDP payload"}};

probe_module_t module_upnp = {
    .name = "upnp",
    .max_packet_length = 139,
    .pcap_filter = "udp || icmp",
    .pcap_snaplen = 2048,
    .port_args = 1,
    .global_initialize = &upnp_global_initialize,
    .thread_initialize = &upnp_init_perthread,
    .make_packet = &udp_make_packet,
    .print_packet = &udp_print_packet,
    .process_packet = &upnp_process_packet,
    .validate_packet = &upnp_validate_packet,
    // UPnP isn't actually dynamic, however, we don't handle escaping
    // properly in the CSV module and this will force users to use JSON.
    .output_type = OUTPUT_TYPE_DYNAMIC,
    .close = NULL,
    .helptext = "Probe module that sends a TCP SYN packet to a specific "
		"port. Possible classifications are: synack and rst. A "
		"SYN-ACK packet is considered a success and a reset packet "
		"is considered a failed response.",
    .fields = fields,
    .numfields = 18};
