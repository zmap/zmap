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

#include "../../lib/includes.h"
#include "../fieldset.h"
#include "probe_modules.h"
#include "packet.h"
#include "logger.h"
#include "../../lib/xalloc.h"

#include "module_tcp_synopt.h"


probe_module_t module_tcp_synopt;
static uint32_t num_ports;

#define MAX_OPT_LEN 40

static char *tcp_send_opts = NULL;
static int tcp_send_opts_len = 0;

int tcpsynopt_global_initialize(struct state_conf *conf)
{
	// code partly copied from UDP module
	char *args, *c;
	int i;
	unsigned int n;

	num_ports = conf->source_port_last - conf->source_port_first + 1;

	if (!(conf->probe_args && strlen(conf->probe_args) > 0)){
		printf("no args, using empty tcp options\n");
		module_tcp_synopt.packet_length = sizeof(struct ether_header) + sizeof(struct ip)
				+ sizeof(struct tcphdr);
		return(EXIT_SUCCESS);
	}
	args = strdup(conf->probe_args);
	if (! args) exit(1);

	c = strchr(args, ':');
	if (! c) {
		free(args);
		//free(udp_send_msg);
		printf("tcp synopt usage error\n");
		exit(1);
	}

	*c++ = 0;

	if (strcmp(args, "hex") == 0) {
		printf("parsing hex options: %s \n", c);
		tcp_send_opts_len = strlen(c) / 2;
		if(strlen(c)/2 %4 != 0){
			printf("tcp options are not multiple of 4, please pad with NOPs (0x01)!\n");
			exit(1);
		}
		free(tcp_send_opts);
		tcp_send_opts = xmalloc(tcp_send_opts_len);

		for (i=0; i < tcp_send_opts_len; i++) {
			if (sscanf(c + (i*2), "%2x", &n) != 1) {
				free(args);
				free(tcp_send_opts);
				log_fatal("udp", "non-hex character: '%c'", c[i*2]);
				exit(1);
			}
			tcp_send_opts[i] = (n & 0xff);
		}
		free(args);
	} else {
		printf("options given, but not hex, exiting!");
		exit(1);
	}
	if (tcp_send_opts_len > MAX_OPT_LEN) {
		log_warn("udp", "warning: exiting - too long option!\n");
		tcp_send_opts_len = MAX_OPT_LEN;
		exit(1);
	}
	module_tcp_synopt.packet_length = sizeof(struct ether_header) + sizeof(struct ip)
			+ sizeof(struct tcphdr)+ tcp_send_opts_len;

	return EXIT_SUCCESS;
}


int tcpsynopt_init_perthread(void* buf, macaddr_t *src,
		macaddr_t *gw, port_h_t dst_port,
		__attribute__((unused)) void **arg_ptr)
{
	memset(buf, 0, MAX_PACKET_SIZE);
	struct ether_header *eth_header = (struct ether_header *) buf;
	make_eth_header(eth_header, src, gw);
	struct ip *ip_header = (struct ip*)(&eth_header[1]);
	uint16_t len = htons(sizeof(struct ip) + sizeof(struct tcphdr) + tcp_send_opts_len);
	make_ip_header(ip_header, IPPROTO_TCP, len);
	struct tcphdr *tcp_header = (struct tcphdr*)(&ip_header[1]);
	make_tcp_header(tcp_header, dst_port, TH_SYN);
	return EXIT_SUCCESS;
}

int tcpsynopt_make_packet(void *buf, ipaddr_n_t src_ip, ipaddr_n_t dst_ip,
		uint32_t *validation, int probe_num, __attribute__((unused)) void *arg)
{
	struct ether_header *eth_header = (struct ether_header *)buf;
	struct ip *ip_header = (struct ip*)(&eth_header[1]);
	struct tcphdr *tcp_header = (struct tcphdr*)(&ip_header[1]);
	unsigned char* opts = (unsigned char*)&tcp_header[1];
	uint32_t tcp_seq = validation[0];

	ip_header->ip_src.s_addr = src_ip;
	ip_header->ip_dst.s_addr = dst_ip;

	tcp_header->th_sport = htons(get_src_port(num_ports,
				probe_num, validation));
	tcp_header->th_seq = tcp_seq;

    memcpy(opts, tcp_send_opts, tcp_send_opts_len);

    tcp_header->th_off = 5+tcp_send_opts_len/4; // default length = 5 + 9*32 bit options

	tcp_header->th_sum = 0;
	tcp_header->th_sum = tcp_checksum(sizeof(struct tcphdr)+tcp_send_opts_len,
			ip_header->ip_src.s_addr, ip_header->ip_dst.s_addr, tcp_header);

	ip_header->ip_sum = 0;
	ip_header->ip_sum = zmap_ip_checksum((unsigned short *) ip_header);

	return EXIT_SUCCESS;
}

void tcpsynopt_print_packet(FILE *fp, void* packet)
{
	struct ether_header *ethh = (struct ether_header *) packet;
	struct ip *iph = (struct ip *) &ethh[1];
	struct tcphdr *tcph = (struct tcphdr *) &iph[1];
	fprintf(fp, "tcp { source: %u | dest: %u | seq: %u | checksum: %#04X }\n",
			ntohs(tcph->th_sport),
			ntohs(tcph->th_dport),
			ntohl(tcph->th_seq),
			ntohs(tcph->th_sum));
	fprintf_ip_header(fp, iph);
	fprintf_eth_header(fp, ethh);
	fprintf(fp, "------------------------------------------------------\n");
}

int tcpsynopt_validate_packet(const struct ip *ip_hdr, uint32_t len,
		__attribute__((unused))uint32_t *src_ip,
		uint32_t *validation)
{
	if (ip_hdr->ip_p != IPPROTO_TCP) {
		return 0;
	}
	// (4*5 =) 20 bytes IP header + 20 bytes tcp hdr + 36 bytes = 76 byte
	// reply packet may not contain any tcp options!
	if ((4*ip_hdr->ip_hl + sizeof(struct tcphdr) + 0) > len) {
		// buffer not large enough to contain expected tcp header
		printf("buffer (%u) not large enough!\n" ,len);
		return 0;
	}
	struct tcphdr *tcp = (struct tcphdr*)((char *) ip_hdr + 4*ip_hdr->ip_hl);
	uint16_t sport = tcp->th_sport;
	uint16_t dport = tcp->th_dport;
	// validate source port
	if (ntohs(sport) != zconf.target_port) {
		//printf("validating... sport fail!\n");
		return 0;
	}
	// validate destination port
	if (!check_dst_port(ntohs(dport), num_ports, validation)) {
		//printf("validating... dport fail!\n");
		return 0;
	}
	// validate tcp acknowledgement number
	if (htonl(tcp->th_ack) != htonl(validation[0])+1) {
		//printf("validating... ackno fail!\n");
		return 0;
	}
	//printf("validate: returning1!\n");
	return 1;
}

#define IP_ADDR_LEN_STR 20

void tcpsynopt_process_packet(const u_char *packet,
		__attribute__((unused)) uint32_t len, fieldset_t *fs,
	    __attribute__((unused)) uint32_t *validation)
{
	struct ip *ip_hdr = (struct ip *)&packet[sizeof(struct ether_header)];

	char srcip[IP_ADDR_LEN_STR+1];
	struct in_addr *s = (struct in_addr *) &(ip_hdr->ip_src);
	strncpy(srcip, inet_ntoa(*s), IP_ADDR_LEN_STR - 1);
	srcip[IP_ADDR_LEN_STR] = '\0';
	printf("Parsing packet from %s\n", srcip);

	struct tcphdr *tcp = (struct tcphdr*)((char *)ip_hdr
					+ 4*ip_hdr->ip_hl);
	unsigned int optionbytes2=len-(sizeof(struct ether_header)+4*ip_hdr->ip_hl + sizeof(struct tcphdr));

	tcpsynopt_process_packet_parse(len, fs,tcp,optionbytes2);
	return;
}

static fielddef_t fields[] = {
	{.name = "sport",  .type = "int", .desc = "TCP source port"},
	{.name = "dport",  .type = "int", .desc = "TCP destination port"},
	{.name = "seqnum", .type = "int", .desc = "TCP sequence number"},
	{.name = "acknum", .type = "int", .desc = "TCP acknowledgement number"},
	{.name = "window", .type = "int", .desc = "TCP window"},
	{.name = "tcpmss", .type = "int", .desc = "TCP mss"},
	{.name = "tsval", .type = "int", .desc = "tsval"},
	{.name = "tsecr", .type = "int", .desc = "tsecr"},
	{.name = "tsdiff", .type = "int", .desc = "tsval"},
	{.name = "wscale", .type = "int", .desc = "tsval"},
	{.name = "mptcpkey", .type = "string", .desc = "tsval"},
	{.name = "mptcpdiff", .type = "int", .desc = "tsval"},
	{.name = "tfocookie", .type = "int", .desc = "tsval"},
	{.name = "optionshex", .type = "string", .desc = "TCP options"},
	{.name = "optionstext", .type = "string", .desc = "TCP options"},
	{.name = "classification", .type="string", .desc = "packet classification"},
	{.name = "success", .type="bool", .desc = "is response considered success"}
};

probe_module_t module_tcp_synopt = {
	.name = "tcp_synopt",
	.packet_length = 54, // will be extended at runtime
	// tcp, ack set or syn+ack (bit random)
	.pcap_filter = "tcp && tcp[13] & 4 != 0 || tcp[13] == 18",
	.pcap_snaplen = 96+10*4, //max len
	.port_args = 1,
	.global_initialize = &tcpsynopt_global_initialize,
	.thread_initialize = &tcpsynopt_init_perthread,
	.make_packet = &tcpsynopt_make_packet,
	.print_packet = &tcpsynopt_print_packet,
	.process_packet = &tcpsynopt_process_packet,
	.validate_packet = &tcpsynopt_validate_packet,
	.close = NULL,
	.helptext = "TCP SYN with options module. Give options as hex argument. Not giving any options is SYN scan default behavior.",
	.fields = fields,
	.numfields = sizeof(fields)/sizeof(fields[0])
	};
//	.numfields = 17};
