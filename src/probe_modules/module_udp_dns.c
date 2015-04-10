/*
  ZMap Copyright 2013 Regents of the University of Michigan
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
#include "module_udp.h"

#define MAX_UDP_PAYLOAD_LEN 1472
#define UNUSED __attribute__((unused))
#define DNS_HEAD_LEN 12
#define DNS_TAIL_LEN 4

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
// DOMAIN NAME 16 bytes
// default will be replaced by passed in argument
// \x03\x77\x77\x77\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00 -> www.google.com
// TAILER 4 bytes
// \x00\x01 -> Type: A (Host address)
// \x00\x01 -> Class: IN (0x0001)

static const char udp_dns_msg_default[32] = "\xb0\x0b\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03\x77\x77\x77\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01";
static const char udp_dns_msg_default_head[DNS_HEAD_LEN] = "\xb0\x0b\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00";
// static const char udp_dns_msg_default_name [16] = "\x03\x77\x77\x77\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00";
static const char udp_dns_msg_default_tail[DNS_TAIL_LEN]  = "\x00\x01\x00\x01";

// google packet from wireshark
// static const char udp_dns_msg_default[36] = "\xf5\x07\x00\x35\x00\x24\x04\x51\x10\xf5\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01";

/* defined in module_udp.c
const char *udp_unreach_strings[] */

const char *udp_dns_response_strings[] = {
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

probe_module_t module_udp_dns;
static int num_ports;

//this will convert www.google.com to 3www6google3com
void convert_to_dns_name_format(unsigned char* dns,unsigned char* host) {
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

// allocates and returns a string representation of a hexadecimal IP
// hexadecimal ip must be passed in network byte order
char* hex_to_ip(void* hex_ip) {

	if(!hex_ip){
		return NULL;
	}
	char* addrstr = malloc(INET_ADDRSTRLEN);
	if(addrstr == NULL){
		exit(1);
	}
	//fprintf(stderr, "hex_ip %s\n", (char*)hex_ip);

	//memcpy(addrstr, hex_ip, sizeof(&hex_ip));
	if(inet_ntop(AF_INET, (struct sockaddr_in *)hex_ip, addrstr, INET_ADDRSTRLEN) == NULL){
		free(addrstr);
		return NULL;
	}
	return addrstr;
}

char* parse_dns_ip_results(struct dnshdr* dns_hdr) {
	(void) dns_hdr;
	return strdup(""); // This is why we don't accept pull requests
#if 0
	// parse through dns_query since it can be of variable length
	char* dns_ans_start = (char *) (&dns_hdr[1]);
	while (*dns_ans_start++); // <---- SERIOUSLY FUCK THAT
	// skip  qtype and qclass octets
	dns_ans_start += 4;
	// number of answers * 16 chars each (each followed by space or null, and quotes)
	size_t size = ntohs(dns_hdr->ancount)*INET_ADDRSTRLEN+2;
	char* ip_addrs = malloc(size);

	// should always be 4 for ipv4 addrs, but include in case of unexpected response
	//uint16_t prev_data_len = 4;
	int output_pos = 0;
	if(ntohs(dns_hdr->ancount) > 1000){
		return NULL;
	}
	for (int i = 0; i < ntohs(dns_hdr->ancount); i++) {
		//dnsans* dns_ans = (dnsans *) ((char*) dns_ans_start + (12 + prev_data_len)*i);
		dnsans* dns_ans = (dnsans *) ((char*) dns_ans_start + (12)*i);
		if(!dns_ans->addr){
			//prev_data_len = ntohs(dns_ans->length);
			continue;
		}
		char* ip_addr = hex_to_ip(&dns_ans->addr);
		if (!ip_addr) {
			//prev_data_len = ntohs(dns_ans->length);
			continue;
		}
		output_pos += i == 0 ? sprintf(ip_addrs + output_pos, "\"%s", ip_addr) : sprintf(ip_addrs + output_pos, " %s", ip_addr);
		//prev_data_len = ntohs(dns_ans->length);
	}
	if (output_pos) {
		sprintf(ip_addrs + output_pos, "\"");
	}
	return ip_addrs;
#endif
}

static int udp_dns_global_initialize(struct state_conf *conf) {
	char *args, *c;
	int dns_domain_len;
	unsigned char* dns_domain;

	num_ports = conf->source_port_last - conf->source_port_first + 1;
	udp_set_num_ports(num_ports);


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

int udp_dns_global_cleanup(__attribute__((unused)) struct state_conf *zconf,
		__attribute__((unused)) struct state_send *zsend,
		__attribute__((unused)) struct state_recv *zrecv) {
	if (udp_send_msg) {
		free(udp_send_msg);
	}
	udp_send_msg = NULL;
	return EXIT_SUCCESS;
}

int udp_dns_init_perthread(void* buf, macaddr_t *src,
		macaddr_t *gw, __attribute__((unused)) port_h_t dst_port,
        __attribute__((unused)) void **arg_ptr) {
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
		uint32_t *validation, int probe_num, __attribute__((unused)) void *arg) {
	struct ether_header *eth_header = (struct ether_header *) buf;
	struct ip *ip_header = (struct ip*) (&eth_header[1]);
	struct udphdr *udp_header= (struct udphdr *) &ip_header[1];

	ip_header->ip_src.s_addr = src_ip;
	ip_header->ip_dst.s_addr = dst_ip;
	udp_header->uh_sport = htons(get_src_port(num_ports, probe_num,
				     validation));
	ip_header->ip_sum = 0;
	ip_header->ip_sum = zmap_ip_checksum((unsigned short *) ip_header);

	return EXIT_SUCCESS;
}

void udp_dns_print_packet(FILE *fp, void* packet) {
	struct ether_header *ethh = (struct ether_header *) packet;
	struct ip *iph = (struct ip *) &ethh[1];
	struct udphdr *udph  = (struct udphdr*) (iph + 4*iph->ip_hl);
	fprintf(fp, "udp_dns { source: %u | dest: %u | checksum: %#04X }\n",
		ntohs(udph->uh_sport),
		ntohs(udph->uh_dport),
		ntohs(udph->uh_sum));
	fprintf_ip_header(fp, iph);
	fprintf_eth_header(fp, ethh);
	fprintf(fp, "------------------------------------------------------\n");
}

int udp_dns_validate_packet(const struct ip *ip_hdr, uint32_t len,
		uint32_t *src_ip, uint32_t *validation)
{
	if (!udp_validate_packet(ip_hdr, len, src_ip, validation)) {
		return 0;
	}
	if (ip_hdr->ip_p == IPPROTO_UDP) {
		struct udphdr *udp = (struct udphdr *) ((char *) ip_hdr + ip_hdr->ip_hl * 4);
		uint16_t sport = ntohs(udp->uh_sport);
		if (sport != zconf.target_port) {
			return 0;
		}
	}
	return 1;
}

void udp_dns_process_packet(const u_char *packet, UNUSED uint32_t len, fieldset_t *fs) {
	struct ip *ip_hdr = (struct ip *) &packet[sizeof(struct ether_header)];
	if (ip_hdr->ip_p == IPPROTO_UDP) {
		struct udphdr *udp_hdr = (struct udphdr *) ((char *) ip_hdr + ip_hdr->ip_hl * 4);
		struct dnshdr *dns_hdr = (struct dnshdr *) (&udp_hdr[1]);
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
	} else if (ip_hdr->ip_p == IPPROTO_ICMP) {
		struct icmp *icmp = (struct icmp *) ((char *) ip_hdr + ip_hdr->ip_hl * 4);
		struct ip *ip_inner = (struct ip *) &icmp[1];
		// ICMP unreachable comes from another server, set saddr to original dst
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

probe_module_t module_udp_dns = {
	.name = "dns",
	.packet_length = 1,
	.pcap_filter = "udp || icmp",
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
