/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

/* send module for performing massive UDP DNS OpenResolver scans
 * default will send type A query with Recursion Desired for www.google.com
 * SUCCESS only for response msg with noerr response code */

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
#include "module_udp_dns.h"

#define MAX_UDP_PAYLOAD_LEN 1472
#define UNUSED __attribute__((unused))

static char *udp_send_msg = NULL;
static int udp_send_msg_len = 0;

// std query recursive for www.google.com type A
// HEADER 12 bytes
// \xb0\x0b -> TransactionID
// \x01\x00 -> Flags: 0x0100 Standard query - Recursion desired
// \x00\x01 -> Questions: 1
// \x00\x00 -> Answer RRs: 0
// \x00\x00 -> Authority RRs: 0
// \x00\x00 -> Additional RRs: 0
// DOMAIN 16 bytes
// \x03\x77\x77\x77\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00 -> www.google.com
// TAILER 4 bytes
// \x00\x01 -> Type: A (Host address)
// \x00\x01 -> Class: IN (0x0001)
static const char udp_dns_msg_default [32] = "\xb0\x0b\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03\x77\x77\x77\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01";
static const char udp_dns_msg_default_head [12] = "\xb0\x0b\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00";
static const char udp_dns_msg_default_name [16] = "\x03\x77\x77\x77\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00";
static const char udp_dns_msg_default_tail [4]  = "\x00\x01\x00\x01";

/* defined in module_udp.c
const char *udp_unreach_strings[] */

const char *udp_dns_response_strings[] = {
        "DNS no error",
        "DNS format error",
        "DNS server failure",
        "DNS nxdomain",
        "DNS query type not implemented",
        "DNS query refused",
		"DNS invalid rcode"
};

static int num_ports;

probe_module_t module_udp_dns;

void udp_dns_set_num_ports(int x)
{
	num_ports = x;
}

//this will convert www.google.com to 3www6google3com
void CovertToDnsNameFormat(unsigned char* dns,unsigned char* host)
{
	int lock=0 , i;
	strcat((char*)host,".");
	for(i=0 ; i<(int)strlen((char*)host) ; i++) {
		if(host[i]=='.') {
			*dns++=i-lock;
			for(;lock<i;lock++) {
				*dns++=host[lock];
			}
			lock++; //or lock=i+1;
		}
	}
	*dns++='\0';
}

static int udp_dns_global_initialize(struct state_conf *conf) {
	char *args, *c;
	int i,dns_domain_len;
	unsigned int n;
	unsigned char* dns_domain;
	FILE *inp;

	num_ports = conf->source_port_last - conf->source_port_first + 1;

	udp_send_msg_len = sizeof(udp_dns_msg_default);
	udp_send_msg = malloc(udp_send_msg_len);
	memcpy(udp_send_msg, udp_dns_msg_default, udp_send_msg_len);

	if (!(conf->probe_args && strlen(conf->probe_args) > 0))
		return(0);

	args = strdup(conf->probe_args);
	if (! args) exit(1);

	c = strchr(args, ':');
	if (! c) {
		free(args);
		free(udp_send_msg);
		log_fatal("udp_dns", "unknown UDP DNS probe specification (expected "
				"full-payload with file:/path or hex:01020304, or domain name with name:www.domain.com)");
		exit(1);
	}

	*c++ = 0;

	if (strcmp(args, "name") == 0) {
		free(udp_send_msg);

		// prepare domain name
		dns_domain_len=strlen(c)+2; // head 1 byte + tail 1 byte \0
		dns_domain = malloc(dns_domain_len);
		CovertToDnsNameFormat(dns_domain, (unsigned char*)c);

		udp_send_msg_len=dns_domain_len + 12 + 4; // domain length +  header + tailer
		udp_send_msg = malloc(udp_send_msg_len);

		// create query packet

		memcpy(udp_send_msg, udp_dns_msg_default_head, sizeof(udp_dns_msg_default_head)); // header
		// patch for random Transaction ID
		random_bytes(udp_send_msg, 2);

		memcpy(udp_send_msg + sizeof(udp_dns_msg_default_head), dns_domain, dns_domain_len); // domain
		memcpy(udp_send_msg + sizeof(udp_dns_msg_default_head) + dns_domain_len, udp_dns_msg_default_tail, sizeof(udp_dns_msg_default_tail)); // trailer
		free(dns_domain);

	} else if (strcmp(args, "file") == 0) {
		inp = fopen(c, "rb");
		if (!inp) {
			free(args);
			free(udp_send_msg);
			log_fatal("udp_dns", "could not open UDP DNS data file '%s'\n", c);
			exit(1);
		}
		free(udp_send_msg);
		udp_send_msg = malloc(MAX_UDP_PAYLOAD_LEN);
		if (! udp_send_msg) {
			free(args);
			log_fatal("udp_dns", "failed to malloc payload buffer");
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
			log_fatal("udp_dns", "failed to malloc payload buffer");
			exit(1);
		}

		for (i=0; i < udp_send_msg_len; i++) {
			if (sscanf(c + (i*2), "%2x", &n) != 1) {
				free(args);
				free(udp_send_msg);
				log_fatal("udp_dns", "non-hex character: '%c'", c[i*2]);
				exit(1);
			}
			udp_send_msg[i] = (n & 0xff);
		}
	} else {
		log_fatal("udp_dns", "unknown UDP DNS probe specification (expected "
				"full-payload with file:/path or hex:01020304, or domain name with name:www.domain.com)");
		free(udp_send_msg);
		free(args);
		exit(1);
	}

	if (udp_send_msg_len > MAX_UDP_PAYLOAD_LEN) {
		log_warn("udp_dns", "warning: reducing UDP payload to %d "
			        "bytes (from %d) to fit on the wire\n", 
				MAX_UDP_PAYLOAD_LEN, udp_send_msg_len);
		udp_send_msg_len = MAX_UDP_PAYLOAD_LEN;
	}
	free(args);
	return EXIT_SUCCESS;
}

int udp_dns_global_cleanup(__attribute__((unused)) struct state_conf *zconf,
		__attribute__((unused)) struct state_send *zsend,
		__attribute__((unused)) struct state_recv *zrecv)
{
	if (udp_send_msg) {
		free(udp_send_msg);
	}
	udp_send_msg = NULL;
	return EXIT_SUCCESS;
}

int udp_dns_init_perthread(void* buf, macaddr_t *src,
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

	module_udp_dns.packet_length = sizeof(struct ether_header) + sizeof(struct ip) 
				+ sizeof(struct udphdr) + udp_send_msg_len;
	assert(module_udp_dns.packet_length <= MAX_PACKET_SIZE);

	memcpy(payload, udp_send_msg, udp_send_msg_len);

	return EXIT_SUCCESS;
}

int udp_dns_make_packet(void *buf, ipaddr_n_t src_ip, ipaddr_n_t dst_ip, 
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

void udp_dns_print_packet(FILE *fp, void* packet)
{
	struct ether_header *ethh = (struct ether_header *) packet;
	struct ip *iph = (struct ip *) &ethh[1];
	struct udphdr *udph  = (struct udphdr*) (iph + 4*iph->ip_hl);
	fprintf(fp, "udp_dns { source: %u | dest: %u | checksum: %u }\n",
		ntohs(udph->uh_sport),
		ntohs(udph->uh_dport),
		ntohl(udph->uh_sum));
	fprintf_ip_header(fp, iph);
	fprintf_eth_header(fp, ethh);
	fprintf(fp, "------------------------------------------------------\n");
}

void udp_dns_process_packet(const u_char *packet, UNUSED uint32_t len, fieldset_t *fs)
{
	int app_success;
	//log_debug("udp_dns", "dns_process_packet");
	struct ip *ip_hdr = (struct ip *) &packet[sizeof(struct ether_header)];
	if (ip_hdr->ip_p == IPPROTO_UDP) {
		//log_debug("udp_dns", "dns_process_packet - start udp pkt");
		struct udphdr *udp_hdr = (struct udphdr *) ((char *) ip_hdr + ip_hdr->ip_hl * 4);
		struct dnshdr *dns_hdr = (struct dnshdr *) ((char *) udp_hdr + 8);

		// app_success is 1 if is application level success
        // response pkt is an answer AND response code is no error AND tid=\xb0\x0b
        // added tid check for more result confidence with dns response from src port other than 53
        app_success = (dns_hdr->qr == DNS_QR_ANSWER) && (dns_hdr->rcode == DNS_RCODE_NOERR) && (dns_hdr->id == 0xb00b);

		fs_add_string(fs, "classification", (char*) "udp_dns", 0);
		fs_add_uint64(fs, "success", 1);
		fs_add_uint64(fs, "sport", ntohs(udp_hdr->uh_sport));
		fs_add_uint64(fs, "dport", ntohs(udp_hdr->uh_dport));
		fs_add_null(fs, "icmp_responder");
		fs_add_null(fs, "icmp_type");
		fs_add_null(fs, "icmp_code");
		fs_add_null(fs, "icmp_unreach_str");
		fs_add_uint64(fs, "app_success", app_success);
		if (dns_hdr->rcode >= 0  && dns_hdr->rcode < 7) {
			fs_add_uint64(fs, "app_rcode", dns_hdr->rcode);
			fs_add_string(fs, "app_rcode_str", (char *) udp_dns_response_strings[dns_hdr->rcode], 0);
		} else {
			fs_add_null(fs, "app_rcode");
			fs_add_null(fs, "app_rcode_str");
		}
		fs_add_uint64(fs, "udp_pkt_size", ntohs(udp_hdr->uh_ulen));
		fs_add_binary(fs, "data", (ntohs(udp_hdr->uh_ulen) - sizeof(struct udphdr)), (void*) &udp_hdr[1], 0);
		//log_debug("udp_dns", "dns_process_packet - end udp pkt");

	} else if (ip_hdr->ip_p == IPPROTO_ICMP) {
		//log_debug("udp_dns", "dns_process_packet - start icmp pkt");
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
		//log_debug("udp_dns", "dns_process_packet - end icmp pkt");

	} else {
		//log_debug("udp_dns", "dns_process_packet - start other pkt");
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
		//log_debug("udp_dns", "dns_process_packet - end other pkt");
	}
}

int udp_dns_validate_packet(const struct ip *ip_hdr, uint32_t len,
                __attribute__((unused))uint32_t *src_ip, uint32_t *validation)
{
        uint16_t dport, sport;
	// log_debug("udp_dns", "dns_validate_packet");
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
		// remember sent perspective, switched sport/dport
		// for dns answering from src port other than 53 following check is always true, so remove it
		/*if (dport != zconf.target_port) {
			return 0;
		}*/

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
	{.name = "app_success", .type = "int", .desc = "for udp_dns module: 1 for valid DNS response msg with NOERR response code - otherwise 0"},
	{.name = "app_rcode", .type = "int", .desc = "for udp_dns module: the RCODE of dns answer pkt"},
	{.name = "app_rcode_str", .type = "string", .desc = "for udp_dns module: the response code meaning of dns answer pkt"},
	{.name = "udp_pkt_size", .type="int", .desc = "UDP packet lenght"},
	{.name = "data", .type="binary", .desc = "UDP payload"}
};

probe_module_t module_udp_dns = {
	.name = "udp_dns",
	.packet_length = 1,
//	.pcap_filter = "udp || icmp",
	.pcap_filter = "\(udp && not dst port 53\) || icmp", // only received pkt
	.pcap_snaplen = 1500,			// TO BE CHANGED FOR EXSTIMATE REFLECTION SIZE
	.port_args = 1,
	.thread_initialize = &udp_dns_init_perthread,
	.global_initialize = &udp_dns_global_initialize,
	.make_packet = &udp_dns_make_packet,
	.print_packet = &udp_dns_print_packet,
	.validate_packet = &udp_dns_validate_packet,
	.process_packet = &udp_dns_process_packet,
	.close = &udp_dns_global_cleanup,
	.fields = fields,
	.numfields = sizeof(fields)/sizeof(fields[0])
};

