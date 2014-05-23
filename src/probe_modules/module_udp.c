/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

/* send module for performing arbitrary UDP scans */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include "../../lib/includes.h"
#include "../../lib/xalloc.h"
#include "probe_modules.h"
#include "packet.h"
#include "logger.h"
#include "module_udp.h"

#define MAX_UDP_PAYLOAD_LEN 1472
#define UNUSED __attribute__((unused))

static char *udp_send_msg = NULL;
static int udp_send_msg_len = 0;
static int udp_send_substitutions = 0;
static udp_payload_template_t *udp_template;

static const char *udp_send_msg_default = "GET / HTTP/1.1\r\nHost: www\r\n\r\n";

const char *udp_unreach_strings[] = {
	"network unreachable",
	"host unreachable",
	"protocol unreachable",
	"port unreachable",
	"fragments required",
	"source route failed",
	"network unknown",
	"host unknown",
	"source host isolated",
	"network admin. prohibited",
	"host admin. prohibited",
	"network unreachable TOS",
	"host unreachable TOS",
	"communication admin. prohibited",
	"host presdence violation",
	"precedence cutoff"
};

const char *udp_usage_error = 
	"unknown UDP probe specification (expected file:/path or text:STRING or hex:01020304 or template:/path)";

const char *charset_alphanum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const char *charset_alpha    = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const char *charset_digit    = "0123456789";

static int num_ports;

probe_module_t module_udp;

// Field definitions for template parsing and displaying usage
static udp_payload_field_type_def_t udp_payload_template_fields[] = {
	{.name = "SADDR_N", .ftype=UDP_SADDR_N, .desc = "Source IP address in network byte order"},
	{.name = "SADDR",   .ftype=UDP_SADDR_A, .desc = "Source IP address in dotted-quad format"},
	{.name = "DADDR_N", .ftype=UDP_DADDR_N, .desc = "Destination IP address in network byte order"},
	{.name = "DADDR",   .ftype=UDP_DADDR_A, .desc = "Destination IP address in dotted-quad format"},
	{.name = "SPORT_N", .ftype=UDP_SPORT_N, .desc = "UDP source port in netowrk byte order"},
	{.name = "SPORT",   .ftype=UDP_SPORT_A, .desc = "UDP source port in ascii format"},
	{.name = "DPORT_N", .ftype=UDP_DPORT_N, .desc = "UDP destination port in network byte order"}, 
	{.name = "DPORT",   .ftype=UDP_DPORT_A, .desc = "UDP destination port in ascii format"},
	{.name = "RAND_BYTE",	.ftype=UDP_RAND_BYTE,	.desc = "Random bytes from 0-255"},
	{.name = "RAND_DIGIT", .ftype=UDP_RAND_DIGIT, .desc = "Random digits from 0-9"},
	{.name = "RAND_ALPHA", .ftype=UDP_RAND_ALPHA, .desc = "Random uppercase letters from A-Z"}
};

void udp_set_num_ports(int x)
{
	num_ports = x;
}

static int udp_global_initialize(struct state_conf *conf) {
	char *args, *c;
	int i;
	unsigned int n;

	FILE *inp;

	num_ports = conf->source_port_last - conf->source_port_first + 1;

	udp_send_msg = strdup(udp_send_msg_default);
	udp_send_msg_len = strlen(udp_send_msg);

	if (!(conf->probe_args && strlen(conf->probe_args) > 0))
		return(0);

	args = strdup(conf->probe_args);
	if (! args) exit(1);

	c = strchr(args, ':');
	if (! c) {
		free(args);
		free(udp_send_msg);
		log_fatal("udp", udp_usage_error);
		exit(1);
	}

	*c++ = 0;

	if (strcmp(args, "text") == 0) {
		free(udp_send_msg);
		udp_send_msg = strdup(c);
		udp_send_msg_len = strlen(udp_send_msg);

	} else if (strcmp(args, "file") == 0 || strcmp(args, "template") == 0) {
		inp = fopen(c, "rb");
		if (!inp) {
			free(args);
			free(udp_send_msg);
			log_fatal("udp", "could not open UDP data file '%s'\n", c);
			exit(1);
		}
		free(udp_send_msg);
		udp_send_msg = xmalloc(MAX_UDP_PAYLOAD_LEN);
		udp_send_msg_len = fread(udp_send_msg, 1, MAX_UDP_PAYLOAD_LEN, inp);
		fclose(inp);

		if (strcmp(args, "template") == 0) {
			udp_send_substitutions = 1;
			udp_template = udp_template_load(udp_send_msg, udp_send_msg_len);
		}

	} else if (strcmp(args, "hex") == 0) {
		udp_send_msg_len = strlen(c) / 2;
		free(udp_send_msg);
		udp_send_msg = xmalloc(udp_send_msg_len);

		for (i=0; i < udp_send_msg_len; i++) {
			if (sscanf(c + (i*2), "%2x", &n) != 1) {
				free(args);
				free(udp_send_msg);
				log_fatal("udp", "non-hex character: '%c'", c[i*2]);
				exit(1);
			}
			udp_send_msg[i] = (n & 0xff);
		}
	} else {
		log_fatal("udp", udp_usage_error);
		free(udp_send_msg);
		free(args);
		exit(1);
	}

	if (udp_send_msg_len > MAX_UDP_PAYLOAD_LEN) {
		log_warn("udp", "warning: reducing UDP payload to %d "
				"bytes (from %d) to fit on the wire\n",
				MAX_UDP_PAYLOAD_LEN, udp_send_msg_len);
		udp_send_msg_len = MAX_UDP_PAYLOAD_LEN;
	}
	free(args);
	return EXIT_SUCCESS;
}

int udp_global_cleanup(__attribute__((unused)) struct state_conf *zconf,
		__attribute__((unused)) struct state_send *zsend,
		__attribute__((unused)) struct state_recv *zrecv)
{
	if (udp_send_msg) {
		free(udp_send_msg);
	}
	udp_send_msg = NULL;
	return EXIT_SUCCESS;
}

int udp_init_perthread(void* buf, macaddr_t *src,
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

	module_udp.packet_length = sizeof(struct ether_header) + sizeof(struct ip)
				+ sizeof(struct udphdr) + udp_send_msg_len;
	assert(module_udp.packet_length <= MAX_PACKET_SIZE);

	memcpy(payload, udp_send_msg, udp_send_msg_len);

	return EXIT_SUCCESS;
}

int udp_make_packet(void *buf, ipaddr_n_t src_ip, ipaddr_n_t dst_ip,
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
	
	if (udp_send_substitutions) {
		char *payload = (char *) &udp_header[1];
		int payload_len = 0;

		memset(payload, 0, MAX_UDP_PAYLOAD_LEN);

		// The buf is a stack var of our caller of size MAX_PACKET_SIZE
		// Recalculate the payload using the loaded template
		payload_len = udp_template_build(udp_template, payload, MAX_UDP_PAYLOAD_LEN, ip_header, udp_header);

		// If success is zero, the template output was truncated
		if (payload_len <= 0) {
			log_fatal("udp", "UDP payload template generated an empty payload");
			exit(1);			
		}

		// Update the IP and UDP headers to match the new length
		ip_header->ip_len   = htons(sizeof(struct ip) + sizeof(struct udphdr) + payload_len);
		udp_header->uh_ulen = ntohs(sizeof(struct udphdr) + payload_len);
		//printf("\n\n\n%s\n", payload);
		//exit(1);
	}

	ip_header->ip_sum = 0;
	ip_header->ip_sum = zmap_ip_checksum((unsigned short *) ip_header);

	return EXIT_SUCCESS;
}

void udp_print_packet(FILE *fp, void* packet)
{
	struct ether_header *ethh = (struct ether_header *) packet;
	struct ip *iph = (struct ip *) &ethh[1];
	struct udphdr *udph = (struct udphdr*) (iph + 4*iph->ip_hl);
	fprintf(fp, "udp { source: %u | dest: %u | checksum: %u }\n",
		ntohs(udph->uh_sport),
		ntohs(udph->uh_dport),
		ntohl(udph->uh_sum));
	fprintf_ip_header(fp, iph);
	fprintf_eth_header(fp, ethh);
	fprintf(fp, "------------------------------------------------------\n");
}

void udp_process_packet(const u_char *packet, UNUSED uint32_t len, fieldset_t *fs)
{
	struct ip *ip_hdr = (struct ip *) &packet[sizeof(struct ether_header)];
	if (ip_hdr->ip_p == IPPROTO_UDP) {
		struct udphdr *udp = (struct udphdr *) ((char *) ip_hdr + ip_hdr->ip_hl * 4);
		fs_add_string(fs, "classification", (char*) "udp", 0);
		fs_add_uint64(fs, "success", 1);
		fs_add_uint64(fs, "sport", ntohs(udp->uh_sport));
		fs_add_uint64(fs, "dport", ntohs(udp->uh_dport));
		fs_add_null(fs, "icmp_responder");
		fs_add_null(fs, "icmp_type");
		fs_add_null(fs, "icmp_code");
		fs_add_null(fs, "icmp_unreach_str");
		// Verify that the UDP length is big enough for the header and at least one byte
		if (ntohs(udp->uh_ulen) > sizeof(struct udphdr))
			fs_add_binary(fs, "data", (ntohs(udp->uh_ulen) - sizeof(struct udphdr)), (void*) &udp[1], 0);
		// Some devices reply with a zero UDP length but still return data, ignore these
		else fs_add_null(fs, "data");

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
		fs_add_null(fs, "data");
	}
}

int udp_validate_packet(const struct ip *ip_hdr, uint32_t len,
		__attribute__((unused))uint32_t *src_ip, uint32_t *validation)
{
	uint16_t dport, sport;
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

// Add a new field to the template
void udp_template_add_field(udp_payload_template_t *t, 
	udp_payload_field_type_t ftype, unsigned int length, char *data)
{
	udp_payload_field_t *c;

	t->fcount++;
	t->fields = xrealloc(t->fields, sizeof(udp_payload_field_t) * t->fcount);
	if (! t->fields) {
		exit(1);
	}
	
	t->fields[t->fcount - 1] = xmalloc(sizeof(udp_payload_field_t));
	c = t->fields[t->fcount - 1];
	
	if (! c) {
		exit(1);
	}
	
	c->ftype	= ftype;
	c->length = length;
	c->data	 = data;
}

// Free all buffers held by the payload template, including its own
void udp_template_free(udp_payload_template_t *t)
{
	unsigned int x;
	for (x=0; x < t->fcount; x++) {
		if (t->fields[x]->data) {
			free(t->fields[x]->data);
			t->fields[x]->data = NULL;
		}
		free(t->fields[x]);
		t->fields[x] = NULL;
	}
	free(t->fields);
	t->fields = NULL;
	t->fcount = 0;
	free(t);
}

int udp_random_lookup(int mod) {
	return (int)( (aesrand_getword() & 0xFFFFFFFF) % mod);
}

int udp_template_build(udp_payload_template_t *t, char *out, unsigned int len,
	struct ip *ip_hdr, struct udphdr *udp_hdr)
{
	udp_payload_field_t *c;
	char *p;
	char *max;
	char tmp[256];
	int full = 0;
	unsigned int x, y, z;
	uint32_t *u32;
	uint16_t *u16;

	max = out + len;
	p	 = out;

	for (x=0; x < t->fcount; x++) {
		c = t->fields[x];

		// Exit the processing loop if our packet buffer would overflow
		if (p+c->length >= max) {
			full = 1;
			return 0;
		}

		switch (c->ftype) {

		// These fields have a specified output length value

			case UDP_DATA:
				if (! c->data)
					break;
				memcpy(p, c->data, c->length);
				p += c->length;
				break;

			case UDP_RAND_DIGIT:
				for (y=0; y < c->length; y++)
					*p++ = charset_digit[ udp_random_lookup(sizeof charset_digit -1) ];
				break;

			case UDP_RAND_ALPHA:
				for (y=0; y < c->length; y++)
					*p++ = charset_alpha[ udp_random_lookup(sizeof charset_alpha -1) ];
				break;

			case UDP_RAND_ALPHANUMERIC:
				for (y=0; y < c->length; y++)
					*p++ = charset_alphanum[ udp_random_lookup(sizeof charset_alphanum -1) ];
				break;

			case UDP_RAND_BYTE:
				for (y=0; y < c->length; y++) {
					*p++ = udp_random_lookup(256);
				}
				break;

			// These fields need to calculate size on their own

			case UDP_SADDR_A:
				if ( p + 15 >= max) {
					full = 1;
					break;
				}
				// Write to stack and then memcpy in order to properly track length
				inet_ntop(AF_INET, (char *)&ip_hdr->ip_src, tmp, sizeof(tmp)-1);
				memcpy(p, tmp, strlen(tmp));
				p += strlen(tmp);
				break;
			
			case UDP_DADDR_A:
				if ( p + 15 >= max) {
					full = 1;
					break;
				}
				// Write to stack and then memcpy in order to properly track length
				inet_ntop(AF_INET, (char *)&ip_hdr->ip_dst, tmp, sizeof(tmp)-1);
				memcpy(p, tmp, strlen(tmp));
				p += strlen(tmp);				
				break;

			case UDP_SADDR_N:
				if ( p + 4 >= max) {
					full = 1;
					break;
				}

				u32 = (uint32_t *)p;
				*u32 = ip_hdr->ip_src.s_addr;
				p += 4;
				break;

			case UDP_DADDR_N:
				if ( p + 4 >= max) {
					full = 1;
					break;
				}
				u32 = (uint32_t *)p;
				*u32 = ip_hdr->ip_dst.s_addr;
				p += 4;
				break;

			case UDP_SPORT_N:
				if ( p + 2 >= max) {
					full = 1;
					break;
				}
				u16 = (uint16_t *)p;
				*u16 = udp_hdr->uh_sport;
				p += 2;
				break;

			case UDP_DPORT_N:
				if ( p + 2 >= max) {
					full = 1;
					break;
				}
				u16 = (uint16_t *)p;
				*u16 = udp_hdr->uh_sport;
				p += 2;
				break;

			case UDP_SPORT_A:
				if ( p + 5 >= max) {
					full = 1;
					break;
				}
				z = snprintf(tmp, 6, "%d", ntohs(udp_hdr->uh_sport));
				memcpy(p, tmp, z);
				p += z;
				break;
			
			case UDP_DPORT_A:
				if ( p + 5 >= max) {
					full = 1;
					break;
				}
				z = snprintf(tmp, 6, "%d", ntohs(udp_hdr->uh_sport));
				memcpy(p, tmp, z);
				p += z;
				break;
		}

		// Bail out if our packet buffer would overflow
		if (full == 1) {
			return 0;
		}
	}

	return p - out - 1;
}

// Convert a string field name to a field type, parsing any specified length value
int udp_template_field_lookup(char *vname, udp_payload_field_t *c) 
{
	char *param;
	unsigned int f;
	unsigned int olen = 0;
	unsigned int fcount = sizeof(udp_payload_template_fields)/sizeof(udp_payload_template_fields[0]);

	param = strstr((const char*)vname, "=");
	if (param) {
		*param = '\0';
		param++;
	}

	// Most field types treat their parameter as a generator output length
	// unless it is ignored (ADDR, PORT, etc).
	if (param) {
		olen = atoi((const char *)param);
	}
	
	// Find a field that matches the 
	for (f=0; f<fcount; f++) {
		
		if (strcmp((char *)vname, udp_payload_template_fields[f].name) == 0) {
			c->ftype	= udp_payload_template_fields[f].ftype;
			c->length = olen;
			c->data	 = NULL;
			return 1;
		}
	}

	// No match, skip and treat it as a data field
	return 0;
}

// Allocate a payload template and populate it by parsing a template file as a binary buffer
udp_payload_template_t * udp_template_load(char *buf, unsigned int len) 
{
	udp_payload_template_t *t = xmalloc(sizeof(udp_payload_template_t));
	
	// The last $ we encountered outside of a field specifier
	char *dollar = NULL;

	// The last { we encountered outside of a field specifier
	char *lbrack = NULL;

	// Track the start pointer of a data field (static)
	char *s = buf;

	// Track the index into the template
	char *p = buf;

	char *tmp;
	unsigned int tlen;

	udp_payload_field_t c;

	t->fcount = 0;
	t->fields = NULL;

	while (p < (buf+len)) 
	{
		switch(*p){

			case '$':
				if ( (dollar && !lbrack) || !dollar) {
					dollar = p;
				}
				p++;
				continue;

			case '{':
				if (dollar && !lbrack) {
					lbrack = p;
				}
				
				p++;
				continue;
				
			case '}':
				if (! (dollar && lbrack)) {
					p++;
					continue;
				}

				// Store the leading bytes before ${ as a data field
				tlen = dollar - s;
				if ( tlen > 0) {
					tmp = xmalloc(tlen);
					memcpy(tmp, s, tlen);
					udp_template_add_field(t, UDP_DATA, tlen, tmp);
				}

				tmp = xcalloc(1, p-lbrack);
				memcpy(tmp, lbrack+1, p-lbrack-1);

				if (udp_template_field_lookup(tmp, &c)) {
					udp_template_add_field(t, c.ftype, c.length, c.data);

					// Push the pointer past the } if this was a valid variable
					s = p + 1;
				} else {

					// Rewind back to the ${ sequence if this was an invalid variable
					s = dollar;
				}

				free(tmp);
				break;

			default:
				if (dollar && lbrack) {
					p++;
					continue;
				}
		}

		dollar = NULL;
		lbrack = NULL;

		p++;
	}

	// Store the trailing bytes as a final data field
	if ( s < p ) {
		tlen = p - s;
		tmp = xmalloc(tlen);
		memcpy(tmp, s, tlen);
		udp_template_add_field(t, UDP_DATA, tlen, tmp);
	}

	return t;
}

static fielddef_t fields[] = {
	{.name = "classification", .type="string", .desc = "packet classification"},
	{.name = "success", .type="int", .desc = "is response considered success"},
	{.name = "sport", .type = "int", .desc = "UDP source port"},
	{.name = "dport", .type = "int", .desc = "UDP destination port"},
	{.name = "icmp_responder", .type = "string", .desc = "Source IP of ICMP_UNREACH message"},
	{.name = "icmp_type", .type = "int", .desc = "icmp message type"},
	{.name = "icmp_code", .type = "int", .desc = "icmp message sub type code"},
	{.name = "icmp_unreach_str", .type = "string", .desc = "for icmp_unreach responses, the string version of icmp_code (e.g. network-unreach)"},
	{.name = "data", .type="binary", .desc = "UDP payload"}
};

probe_module_t module_udp = {
	.name = "udp",
	.packet_length = 1,
	.pcap_filter = "udp || icmp",
	.pcap_snaplen = 1500,
	.port_args = 1,
	.thread_initialize = &udp_init_perthread,
	.global_initialize = &udp_global_initialize,
	.make_packet = &udp_make_packet,
	.print_packet = &udp_print_packet,
	.validate_packet = &udp_validate_packet,
	.process_packet = &udp_process_packet,
	.close = &udp_global_cleanup,
	.fields = fields,
	.numfields = sizeof(fields)/sizeof(fields[0])
};
