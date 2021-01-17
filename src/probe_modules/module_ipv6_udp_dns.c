/*
 * ZMapv6 Copyright 2016 Chair of Network Architectures and Services
 * Technical University of Munich
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

/* send module for performing massive UDP DNS OpenResolver scans over IPv6
 * default will send type A query with Recursion Desired for www.google.com
 * SUCCESS only for response msg with noerr response code */

// Needed for asprintf
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

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
#include "module_dns.h"
#include "module_udp.h"

#define MAX_UDP_PAYLOAD_LEN 1472
#define UNUSED __attribute__((unused))
#define DNS_HEAD_LEN 12
#define DNS_TAIL_LEN 4
#define DNS_QR_ANSWER	1

// std query recursive for www.google.com type A
// HEADER 12 bytes
// \xb0\x0b -> TransactionID
// \x01\x00 -> Flags: 0x0100 Standard query - Recursion desired
// \x00\x01 -> Questions: 1
// \x00\x00 -> Answer RRs: 0
// \x00\x00 -> Authority RRs: 0
// \x00\x00 -> Additional RRs: 0
// DOMAIN NAME 16 bytes
// default will be replaced by passed in argument
// \x03\x77\x77\x77\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00 -> www.google.com
// TAILER 4 bytes
// \x00\x01 -> Type: A (Host address)
// \x00\x01 -> Class: IN (0x0001)

static const char *udp_dns_response_strings[] = {
        "DNS no error",
        "DNS format error",
        "DNS server failure",
        "DNS domain name error",
        "DNS query type not implemented",
        "DNS query refused",
	"DNS Reserved 6",
	"DNS Reserved 7",
	"DNS Reserved 8",
	"DNS Reserved 9",
	"DNS Reserved 10",
	"DNS Reserved 11",
	"DNS Resevered 12",
	"DNS Resevered 13",
	"DNS Resevered 14",
	"DNS Resevered 15"
};


static const char udp_dns_msg_default[32] = "\x0b\x0b\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x03\x77\x77\x77\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01";
static const char udp_dns_msg_default_head[DNS_HEAD_LEN] = "\xb0\x0b\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00";
// static const char udp_dns_msg_default_name [16] = "\x03\x77\x77\x77\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00";
static const char udp_dns_msg_default_tail[DNS_TAIL_LEN]  = "\x00\x01\x00\x01";

// google packet from wireshark
// static const char udp_dns_msg_default[36] = "\xf5\x07\x00\x35\x00\x24\x04\x51\x10\xf5\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01";

/* defined in module_udp.c
const char *udp_unreach_strings[] */

static char *udp_send_msg = NULL;
static int udp_send_msg_len = 0;

static int num_ports;

probe_module_t module_ipv6_udp_dns;

//this will convert www.google.com to 3www6google3com
static void convert_to_dns_name_format(unsigned char* dns,unsigned char* host) {
	int lock = 0;
	strcat((char*)host,".");
	for(int i = 0; i < ((int) strlen((char*)host)); i++) {
		if(host[i]=='.') {
			*dns++=i-lock;
			for(;lock<i;lock++) {
				*dns++=host[lock];
			}
			lock++;
		}
	}
	*dns++ = '\0';
}


int ipv6_udp_dns_global_initialize(struct state_conf *conf) {
	char *args, *c;
	int dns_domain_len;
	unsigned char* dns_domain;

	num_ports = conf->source_port_last - conf->source_port_first + 1;
	udp_set_num_ports(num_ports);

	// Only look at received packets destined to the specified scanning address (useful for parallel zmap scans)
	if (asprintf((char ** restrict) &module_ipv6_udp_dns.pcap_filter, "%s && ip6 dst host %s", module_ipv6_udp_dns.pcap_filter, conf->ipv6_source_ip) == -1) {
		return 1;
	}

	udp_send_msg_len = sizeof(udp_dns_msg_default);
	udp_send_msg = malloc(udp_send_msg_len);
	memcpy(udp_send_msg, udp_dns_msg_default, udp_send_msg_len);

	if (!(conf->probe_args && strlen(conf->probe_args) > 0))
		return(0);

	args = strdup(conf->probe_args);
	if (! args) exit(1);

	c = strchr(args, ':');
	if (!c) {
		free(args);
		free(udp_send_msg);
		log_fatal("udp_dns", "unknown UDP DNS probe specification (expected "
				"domain name with name:www.domain.com)");
		exit(1);
	}

	*c++ = 0;
	if (strcmp(args, "name") == 0) {
		free(udp_send_msg);
		// prepare domain name
		dns_domain_len=strlen(c)+2; // head 1 byte + null terminator
		dns_domain = malloc(dns_domain_len);
		convert_to_dns_name_format(dns_domain, (unsigned char*)c);

		udp_send_msg_len=dns_domain_len + DNS_HEAD_LEN + DNS_TAIL_LEN; // domain length +  header + tailer
		udp_send_msg = malloc(udp_send_msg_len);

		// create query packet
		memcpy(udp_send_msg, udp_dns_msg_default_head, sizeof(udp_dns_msg_default_head)); // header
		// random Transaction ID
		random_bytes(udp_send_msg, 2);
		memcpy(udp_send_msg + sizeof(udp_dns_msg_default_head), dns_domain, dns_domain_len); // domain
		memcpy(udp_send_msg + sizeof(udp_dns_msg_default_head) + dns_domain_len, udp_dns_msg_default_tail, sizeof(udp_dns_msg_default_tail)); // trailer
		free(dns_domain);
	} else {
		log_fatal("udp_dns", "unknown UDP DNS probe specification (expected "
				"domain name with name:www.domain.com)");
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

int ipv6_udp_dns_global_cleanup(__attribute__((unused)) struct state_conf *zconf,
		__attribute__((unused)) struct state_send *zsend,
		__attribute__((unused)) struct state_recv *zrecv) {
	if (udp_send_msg) {
		free(udp_send_msg);
	}
	udp_send_msg = NULL;
	return EXIT_SUCCESS;
}

int ipv6_udp_dns_init_perthread(void* buf, macaddr_t *src,
		macaddr_t *gw, __attribute__((unused)) port_h_t dst_port,
        __attribute__((unused)) void **arg_ptr) {
	memset(buf, 0, MAX_PACKET_SIZE);
	struct ether_header *eth_header = (struct ether_header *) buf;
	make_eth_header_ethertype(eth_header, src, gw, ETHERTYPE_IPV6);
	struct ip6_hdr *ipv6_header = (struct ip6_hdr*)(&eth_header[1]);
	uint16_t payload_len = sizeof(struct udphdr) + udp_send_msg_len;
	make_ip6_header(ipv6_header, IPPROTO_UDP, payload_len);

	struct udphdr *udp_header = (struct udphdr*)(&ipv6_header[1]);
	make_udp_header(udp_header, zconf.target_port, payload_len);

	char* payload = (char*)(&udp_header[1]);

	module_ipv6_udp_dns.packet_length = sizeof(struct ether_header) + sizeof(struct ip6_hdr)
				+ sizeof(struct udphdr) + udp_send_msg_len;
	assert(module_ipv6_udp_dns.packet_length <= MAX_PACKET_SIZE);

	memcpy(payload, udp_send_msg, udp_send_msg_len);

	return EXIT_SUCCESS;
}

int ipv6_udp_dns_make_packet(void *buf, UNUSED size_t *buf_len, UNUSED ipaddr_n_t src_ip, UNUSED ipaddr_n_t dst_ip,
		uint8_t ttl, uint32_t *validation, int probe_num, __attribute__((unused)) void *arg) {
	struct ether_header *eth_header = (struct ether_header *) buf;
	struct ip6_hdr *ip6_header = (struct ip6_hdr*) (&eth_header[1]);
	struct udphdr *udp_header= (struct udphdr *) &ip6_header[1];

	ip6_header->ip6_src = ((struct in6_addr *) arg)[0];
	ip6_header->ip6_dst = ((struct in6_addr *) arg)[1];
	ip6_header->ip6_ctlun.ip6_un1.ip6_un1_hlim = ttl;
	udp_header->uh_sport = htons(get_src_port(num_ports, probe_num,
				     validation));
	udp_header->uh_sum = ipv6_udp_checksum(&ip6_header->ip6_src, &ip6_header->ip6_dst, udp_header);

	return EXIT_SUCCESS;
}

void ipv6_udp_dns_print_packet(FILE *fp, void* packet) {
	struct ether_header *ethh = (struct ether_header *) packet;
	struct ip6_hdr *iph = (struct ip6_hdr *) &ethh[1];
	struct udphdr *udph  = (struct udphdr*) &iph[1];
	fprintf(fp, "udp_dns { source: %u | dest: %u | checksum: %#04X }\n",
		ntohs(udph->uh_sport),
		ntohs(udph->uh_dport),
		ntohs(udph->uh_sum));
	fprintf_ipv6_header(fp, iph);
	fprintf_eth_header(fp, ethh);
	fprintf(fp, "------------------------------------------------------\n");
}

int ipv6_udp_dns_validate_packet(const struct ip *ip_hdr, uint32_t len,
		UNUSED uint32_t *src_ip, uint32_t *validation)
{
	struct ip6_hdr *ipv6_hdr = (struct ip6_hdr *) ip_hdr;
/*
	if (ipv6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt != IPPROTO_UDP) {
		return 0;
	}
*/
	if ((ntohs(ipv6_hdr->ip6_ctlun.ip6_un1.ip6_un1_plen)) > len) {
		// buffer not large enough to contain expected UDP header, i.e. IPv6 payload
		return 0;
	}
	if (!ipv6_udp_validate_packet(ipv6_hdr, len, NULL, validation)) {
		return 0;
	}
	return 1;
}

void ipv6_udp_dns_process_packet(const u_char *packet, UNUSED uint32_t len, fieldset_t *fs,
		__attribute__((unused)) uint32_t *validation) {
	struct ip6_hdr *ipv6_hdr = (struct ip6_hdr *) &packet[sizeof(struct ether_header)];
	if (ipv6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_UDP) {
		struct udphdr *udp_hdr = (struct udphdr *) (&ipv6_hdr[1]);
		dns_header *dns_hdr = (dns_header *) (&udp_hdr[1]);
		fs_add_string(fs, "classification", (char*) "udp_dns", 0);
		// success is 1 if application level success
		// response pkt is an answer and response code is no error
		uint16_t qr = dns_hdr->qr;
		uint16_t rcode = dns_hdr->rcode;
		fs_add_uint64(fs, "success", (qr == DNS_QR_ANSWER) && (rcode == DNS_RCODE_NOERR));
		fs_add_uint64(fs, "sport", ntohs(udp_hdr->uh_sport));
		fs_add_uint64(fs, "dport", ntohs(udp_hdr->uh_dport));
		fs_add_null(fs, "icmp_responder");
		fs_add_null(fs, "icmp_type");
		fs_add_null(fs, "icmp_code");
		fs_add_null(fs, "icmp_unreach_str");
		fs_add_string(fs, "app_response_str", (char *) udp_dns_response_strings[rcode], 0);
		fs_add_uint64(fs, "app_response_code", rcode);
		fs_add_uint64(fs, "udp_pkt_size", ntohs(udp_hdr->uh_ulen));
		if(ntohs(udp_hdr->uh_ulen) == 0){
			fs_add_null(fs, "data");
		}else{
			fs_add_binary(fs, "data", (ntohs(udp_hdr->uh_ulen) - sizeof(struct udphdr)), (void*) &udp_hdr[1], 0);
		}

		/*
		char* ip_addrs = parse_dns_ip_results(dns_hdr);
		if (!ip_addrs){
			fs_add_null(fs, "addrs");
		} else {
			fs_add_string(fs, "addrs", ip_addrs, 1);
		}
		*/
		fs_add_null(fs, "addrs");
	} else if (ipv6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_ICMPV6) {
		struct icmp6_hdr *icmp6 = (struct icmp6_hdr *) (&ipv6_hdr[1]);
		struct ip6_hdr *ipv6_inner = (struct ip6_hdr *) &icmp6[1];
		// ICMP unreachable comes from another server, set saddr to original dst
		fs_modify_string(fs, "saddr", make_ipv6_str(&ipv6_inner->ip6_dst), 1);
		fs_add_string(fs, "classification", (char*) "icmp-unreach", 0);
		fs_add_uint64(fs, "success", 0);
		fs_add_null(fs, "sport");
		fs_add_null(fs, "dport");
		fs_add_string(fs, "icmp_responder", make_ipv6_str(&ipv6_hdr->ip6_src), 1);
		fs_add_uint64(fs, "icmp_type", icmp6->icmp6_type);
		fs_add_uint64(fs, "icmp_code", icmp6->icmp6_code);
		fs_add_null(fs, "icmp_unreach_str");
		fs_add_null(fs, "app_response_str");
		fs_add_null(fs, "app_response_code");
		fs_add_null(fs, "udp_pkt_size");
		fs_add_null(fs, "data");
		fs_add_null(fs, "addrs");
	} else {
		fs_add_string(fs, "classification", (char *) "other", 0);
		fs_add_uint64(fs, "success", 0);
		fs_add_null(fs, "sport");
		fs_add_null(fs, "dport");
		fs_add_null(fs, "icmp_responder");
		fs_add_null(fs, "icmp_type");
		fs_add_null(fs, "icmp_code");
		fs_add_null(fs, "icmp_unreach_str");
		fs_add_null(fs, "app_response_str");
		fs_add_null(fs, "app_response_code");
		fs_add_null(fs, "udp_pkt_size");
		fs_add_null(fs, "data");
		fs_add_null(fs, "addrs");
	}
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
	{.name = "app_response_str", .type = "string", .desc = "for DNS responses, the response code meaning of dns answer pkt"},
	{.name = "app_response_code", .type = "int", .desc = "for DNS responses, the RCODE of dns answer pkt"},
	{.name = "udp_pkt_size", .type="int", .desc = "UDP packet lenght"},
	{.name = "data", .type="binary", .desc = "UDP payload"},
	{.name = "addrs", .type="string", .desc = "DNS answers"}
};

probe_module_t module_ipv6_udp_dns = {
	.name = "ipv6_dns",
	.packet_length = 1,
	.pcap_filter = "ip6 proto 17 || icmp6",
	.pcap_snaplen = 1500,			// TO BE CHANGED FOR EXSTIMATE REFLECTION SIZE
	.port_args = 1,
	.thread_initialize = &ipv6_udp_dns_init_perthread,
	.global_initialize = &ipv6_udp_dns_global_initialize,
	.make_packet = &ipv6_udp_dns_make_packet,
	.print_packet = &ipv6_udp_dns_print_packet,
	.validate_packet = &ipv6_udp_dns_validate_packet,
	.process_packet = &ipv6_udp_dns_process_packet,
	.close = &ipv6_udp_dns_global_cleanup,
	.fields = fields,
	.numfields = sizeof(fields)/sizeof(fields[0])
};
