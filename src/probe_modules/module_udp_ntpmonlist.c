/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

/* send module for performing massive UDP NTP cmd monlist scans
 * default will send command monlist
 * SUCCESS only for response that  */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include "../../lib/includes.h"
#include "../../lib/random.h"
#include "probe_modules.h"
#include "packet.h"
#include "logger.h"
#include "module_udp_ntpmonlist.h"

#define MAX_UDP_PAYLOAD_LEN 1472
#define UNUSED __attribute__((unused))

static char *udp_send_msg = NULL;
static int udp_send_msg_len = 0;

static const char udp_send_msg_default[14] =	"\x17\x00\x03\x2a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";/*\x00\x00" \
						"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
						"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
						"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
						"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
						"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
						"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
						"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
						"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
						"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
						"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
						"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";*/

/* defined in module_udp.c
const char *udp_unreach_strings[] */

const char *udp_ntpmonlist_response_strings[] = {
        "NTP ERR invalid monlist response",
        "NTP NOERR valid monlist response"
};

static int num_ports;

probe_module_t module_udp_ntpmonlist;

void udp_ntpmonlist_set_num_ports(int x)
{
	num_ports = x;
}

static int udp_ntpmonlist_global_initialize(struct state_conf *conf) {
	char *args, *c;
	int i;
	unsigned int n;
	FILE *inp;

	num_ports = conf->source_port_last - conf->source_port_first + 1;

	udp_send_msg_len = sizeof (udp_send_msg_default);
	udp_send_msg = malloc(udp_send_msg_len);
	memcpy(udp_send_msg, udp_send_msg_default, udp_send_msg_len);

	if (!(conf->probe_args && strlen(conf->probe_args) > 0))
		return(0);

	args = strdup(conf->probe_args);
	if (! args) exit(1);

	c = strchr(args, ':');
	if (! c) {
		free(args);
		free(udp_send_msg);
		log_fatal("udp_ntpmonlist", "unknown UDP NTP probe command (expected "
				"full-udp-payload with file:/path or hex:01020304 or text:payload)");
		exit(1);
	}

	*c++ = 0;

	if (strcmp(args, "text") == 0) {
		free(udp_send_msg);

		udp_send_msg_len=strlen(c);
		udp_send_msg = malloc(udp_send_msg_len);
		memcpy(udp_send_msg, c, udp_send_msg_len);

	} else if (strcmp(args, "file") == 0) {
		inp = fopen(c, "rb");
		if (!inp) {
			free(args);
			free(udp_send_msg);
			log_fatal("udp_ntpmonlist", "could not open UDP NTP monlist data file '%s'\n", c);
			exit(1);
		}
		free(udp_send_msg);
		udp_send_msg = malloc(MAX_UDP_PAYLOAD_LEN);
		if (! udp_send_msg) {
			free(args);
			log_fatal("udp_ntpmonlist", "failed to malloc payload buffer");
			exit(1);
		}
		udp_send_msg_len = fread(udp_send_msg, 1, MAX_UDP_PAYLOAD_LEN, inp);
		fclose(inp);

	} else if (strcmp(args, "hex") == 0) {
		udp_send_msg_len = strlen(c) / 2;
		free(udp_send_msg);
		udp_send_msg = malloc(udp_send_msg_len);
		if (! udp_send_msg) {
			free(args);
			log_fatal("udp_ntpmonlist", "failed to malloc payload buffer");
			exit(1);
		}

		for (i=0; i < udp_send_msg_len; i++) {
			if (sscanf(c + (i*2), "%2x", &n) != 1) {
				free(args);
				free(udp_send_msg);
				log_fatal("udp_ntpmonlist", "non-hex character: '%c'", c[i*2]);
				exit(1);
			}
			udp_send_msg[i] = (n & 0xff);
		}
	} else {
		log_fatal("udp_ntpmonlist", "unknown UDP NTP monlist probe specification (expected "
				"full-udp-payload with file:/path or hex:01020304 or text:payload)");
		free(udp_send_msg);
		free(args);
		exit(1);
	}

	if (udp_send_msg_len > MAX_UDP_PAYLOAD_LEN) {
		log_warn("udp_ntpmonlist", "warning: reducing UDP payload to %d "
			        "bytes (from %d) to fit on the wire\n", 
				MAX_UDP_PAYLOAD_LEN, udp_send_msg_len);
		udp_send_msg_len = MAX_UDP_PAYLOAD_LEN;
	}
	free(args);
	return EXIT_SUCCESS;
}

int udp_ntpmonlist_global_cleanup(__attribute__((unused)) struct state_conf *zconf,
		__attribute__((unused)) struct state_send *zsend,
		__attribute__((unused)) struct state_recv *zrecv)
{
	if (udp_send_msg) {
		free(udp_send_msg);
	}
	udp_send_msg = NULL;
	return EXIT_SUCCESS;
}

int udp_ntpmonlist_init_perthread(void* buf, macaddr_t *src,
		macaddr_t *gw, __attribute__((unused)) port_h_t dst_port)
{
	memset(buf, 0, MAX_PACKET_SIZE);
	struct ether_header *eth_header = (struct ether_header *) buf;
	make_eth_header(eth_header, src, gw);
	struct ip *ip_header = (struct ip*)(&eth_header[1]);
	uint16_t len = htons(sizeof(struct ip) + sizeof(struct udphdr) + udp_send_msg_len);
	make_ip_header(ip_header, IPPROTO_UDP, len);

	struct udphdr *udp_header = (struct udphdr*)(&ip_header[1]);
	len = sizeof(struct udphdr) + udp_send_msg_len;
	make_udp_header(udp_header, zconf.target_port, len);

	char* payload = (char*)(&udp_header[1]);

	module_udp_ntpmonlist.packet_length = sizeof(struct ether_header) + sizeof(struct ip) 
				+ sizeof(struct udphdr) + udp_send_msg_len;
	assert(module_udp_ntpmonlist.packet_length <= MAX_PACKET_SIZE);

	memcpy(payload, udp_send_msg, udp_send_msg_len);

	return EXIT_SUCCESS;
}

int udp_ntpmonlist_make_packet(void *buf, ipaddr_n_t src_ip, ipaddr_n_t dst_ip, 
		uint32_t *validation, int probe_num)
{
	struct ether_header *eth_header = (struct ether_header *) buf;
	struct ip *ip_header = (struct ip*) (&eth_header[1]);
	struct udphdr *udp_header= (struct udphdr *) &ip_header[1];
	//struct = (struct udphdr*) (&ip_header[1]);

	ip_header->ip_src.s_addr = src_ip;
	ip_header->ip_dst.s_addr = dst_ip;
	udp_header->uh_sport = htons(get_src_port(num_ports, probe_num,
				     validation));
	ip_header->ip_sum = 0;
	ip_header->ip_sum = zmap_ip_checksum((unsigned short *) ip_header);

	return EXIT_SUCCESS;
}

void udp_ntpmonlist_print_packet(FILE *fp, void* packet)
{
	struct ether_header *ethh = (struct ether_header *) packet;
	struct ip *iph = (struct ip *) &ethh[1];
	struct udphdr *udph  = (struct udphdr*) (iph + 4*iph->ip_hl);
	fprintf(fp, "udp_ntpmonlist { source: %u | dest: %u | checksum: %u }\n",
		ntohs(udph->uh_sport),
		ntohs(udph->uh_dport),
		ntohl(udph->uh_sum));
	fprintf_ip_header(fp, iph);
	fprintf_eth_header(fp, ethh);
	fprintf(fp, "------------------------------------------------------\n");
}

void udp_ntpmonlist_process_packet(const u_char *packet, UNUSED uint32_t len, fieldset_t *fs)
{
	int app_success;
	// log_debug("udp_ntpmonlist", "ntpmonlist_process_packet");
	struct ip *ip_hdr = (struct ip *) &packet[sizeof(struct ether_header)];
	if (ip_hdr->ip_p == IPPROTO_UDP) {
		struct udphdr *udp_hdr = (struct udphdr *) ((char *) ip_hdr + ip_hdr->ip_hl * 4);
		char *payload = (char *) udp_hdr + 8;
		// success is 1 if first 4 bytes of payload sequence are a valid NTP monlist answer (usually 0xd7-0x00-0x03-0x2a)
		app_success = (  ((unsigned char)payload[0] == 0xd7) && ((unsigned char)payload[1] == 0) && ((unsigned char)payload[2] == 3) && ((unsigned char)payload[3] == 0x2a) );

		fs_add_string(fs, "classification", (char*) "udp_ntpmonlist", 0);
		fs_add_uint64(fs, "success", 1);
		fs_add_uint64(fs, "sport", ntohs(udp_hdr->uh_sport));
		fs_add_uint64(fs, "dport", ntohs(udp_hdr->uh_dport));
		fs_add_null(fs, "icmp_responder");
		fs_add_null(fs, "icmp_type");
		fs_add_null(fs, "icmp_code");
		fs_add_null(fs, "icmp_unreach_str");
		fs_add_uint64(fs, "app_success", app_success);
		fs_add_uint64(fs, "app_rcode",app_success);
		fs_add_string(fs, "app_rcode_str", (char *) udp_ntpmonlist_response_strings[app_success], 0);
		fs_add_uint64(fs, "udp_pkt_size", ntohs(udp_hdr->uh_ulen));
		fs_add_binary(fs, "data", (ntohs(udp_hdr->uh_ulen) - sizeof(struct udphdr)), (void*) &udp_hdr[1], 0);

	} else if (ip_hdr->ip_p == IPPROTO_ICMP) {
		struct icmp *icmp = (struct icmp *) ((char *) ip_hdr + ip_hdr->ip_hl * 4);
		struct ip *ip_inner = (struct ip *) &icmp[1];
		// ICMP unreach comes from another server (not the one we sent a probe to);
		// But we will fix up saddr to be who we sent the probe to, in case you care.
		fs_modify_string(fs, "saddr", make_ip_str(ip_inner->ip_dst.s_addr), 1);
		fs_add_string(fs, "classification", (char*) "icmp-unreach", 0);
		fs_add_uint64(fs, "success", 0);
		fs_add_null(fs, "sport");
		fs_add_null(fs, "dport");
		fs_add_string(fs, "icmp_responder", make_ip_str(ip_hdr->ip_src.s_addr), 1);
		fs_add_uint64(fs, "icmp_type", icmp->icmp_type);
		fs_add_uint64(fs, "icmp_code", icmp->icmp_code);
		if (icmp->icmp_code <= ICMP_UNREACH_PRECEDENCE_CUTOFF) {
			fs_add_string(fs, "icmp_unreach_str", 
				(char *) udp_unreach_strings[icmp->icmp_code], 0);
		} else {
			fs_add_string(fs, "icmp_unreach_str", (char *) "unknown", 0);
		}
		fs_add_uint64(fs, "app_success", 0);
		fs_add_null(fs, "app_rcode");
		fs_add_null(fs, "app_rcode_str");
		fs_add_null(fs, "udp_pkt_size");
		fs_add_null(fs, "data");
	} else {
		fs_add_string(fs, "classification", (char *) "other", 0);
		fs_add_uint64(fs, "success", 0);
		fs_add_null(fs, "sport");
		fs_add_null(fs, "dport");
		fs_add_null(fs, "icmp_responder");
		fs_add_null(fs, "icmp_type");
		fs_add_null(fs, "icmp_code");
		fs_add_null(fs, "icmp_unreach_str");
		fs_add_uint64(fs, "app_success", 0);
		fs_add_null(fs, "app_rcode");
		fs_add_null(fs, "app_rcode_str");
		fs_add_null(fs, "udp_pkt_size");
		fs_add_null(fs, "data");
	}
}

int udp_ntpmonlist_validate_packet(const struct ip *ip_hdr, uint32_t len,
                __attribute__((unused))uint32_t *src_ip, uint32_t *validation)
{
        uint16_t dport, sport;
	// log_debug("udp_ntpmonlist", "ntpmonlist_validate_packet");
        if (ip_hdr->ip_p == IPPROTO_UDP) {
                if ((4*ip_hdr->ip_hl + sizeof(struct udphdr)) > len) {
                        // buffer not large enough to contain expected udp header
                        return 0;
                }
                struct udphdr *udp = (struct udphdr*) ((char *) ip_hdr + 4*ip_hdr->ip_hl);

                sport = ntohs(udp->uh_dport);
                dport = ntohs(udp->uh_sport);
        } else if (ip_hdr->ip_p == IPPROTO_ICMP) {
                // UDP can return ICMP Destination unreach
                // IP( ICMP( IP( UDP ) ) ) for a destination unreach
                uint32_t min_len = 4*ip_hdr->ip_hl + sizeof(struct icmp)
                                + sizeof(struct ip) + sizeof(struct udphdr);
                if (len < min_len) {
                        // Not enough information for us to validate
                        return 0;
                }

                struct icmp *icmp = (struct icmp*) ((char *) ip_hdr + 4*ip_hdr->ip_hl);
                if (icmp->icmp_type != ICMP_UNREACH) {
                        return 0;
                }

                struct ip *ip_inner = (struct ip*) &icmp[1];
                // Now we know the actual inner ip length, we should recheck the buffer
                if (len < 4*ip_inner->ip_hl - sizeof(struct ip) + min_len) {
                        return 0;
                }
                // This is the packet we sent
                struct udphdr *udp = (struct udphdr *) ((char*) ip_inner + 4*ip_inner->ip_hl);

                sport = ntohs(udp->uh_sport);
                dport = ntohs(udp->uh_dport);
        } else {
                return 0;
        }
        if (dport != zconf.target_port) {
                return 0;
        }
	if (!check_dst_port(sport, num_ports, validation)) {
		return 0;
	}
	return 1;
}

static fielddef_t fields[] = {
	{.name = "classification", .type="string", .desc = "packet classification"},
	{.name = "success", .type="int", .desc = "is response considered success"},
	{.name = "sport",  .type = "int", .desc = "UDP source port"},
	{.name = "dport",  .type = "int", .desc = "UDP destination port"},
	{.name = "icmp_responder", .type = "string", .desc = "Source IP of ICMP_UNREACH message"},
	{.name = "icmp_type", .type = "int", .desc = "icmp message type"},
	{.name = "icmp_code", .type = "int", .desc = "icmp message sub type code"},
	{.name = "icmp_unreach_str", .type = "string", .desc = "for icmp_unreach responses, the string version of icmp_code (e.g. network-unreach)"},
	{.name = "app_success", .type="int", .desc = "is response considered APPLICATION success"},
	{.name = "app_rcode", .type = "int", .desc = "for udp_ntpmonlist module:, 0 invalid sequence - 1 valid sequence"},
	{.name = "app_rcode_str", .type = "string", .desc = "for udp_ntpmonlist module: NTP ERR invalid monlist response - NTP NOERR valid monlist response"},
	{.name = "udp_pkt_size", .type="int", .desc = "UDP packet lenght"},
	{.name = "data", .type="binary", .desc = "UDP payload"}
};

probe_module_t module_udp_ntpmonlist = {
	.name = "udp_ntpmonlist",
	.packet_length = 1,
	.pcap_filter = "udp || icmp",
	.pcap_snaplen = 8192,				// TO BE CHANGED FOR EXSTIMATE REFLECTION SIZE
	.port_args = 1,
	.thread_initialize = &udp_ntpmonlist_init_perthread,
	.global_initialize = &udp_ntpmonlist_global_initialize,
	.make_packet = &udp_ntpmonlist_make_packet,
	.print_packet = &udp_ntpmonlist_print_packet,
	.validate_packet = &udp_ntpmonlist_validate_packet,
	.process_packet = &udp_ntpmonlist_process_packet,
	.close = &udp_ntpmonlist_global_cleanup,
	.fields = fields,
	.numfields = sizeof(fields)/sizeof(fields[0])
};

