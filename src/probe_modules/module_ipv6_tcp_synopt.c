/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

// probe module for performing TCP SYN scans over IPv6

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
#include "../../lib/xalloc.h"
#include "logger.h"

#include "module_tcp_synopt.h"

probe_module_t module_ipv6_tcp_synopt;
static uint32_t num_ports;

#define MAX_OPT_LEN 40

static char *tcp_send_opts = NULL;
static int tcp_send_opts_len = 0;

//extern void tcpsynopt_process_packet_parse(                                     
//        __attribute__((unused)) uint32_t len, fieldset_t *fs,                   
//	struct tcphdr *tcp, unsigned int optionbytes2);                          


int ipv6_tcp_synopt_global_initialize(struct state_conf *conf)
{
	// code partly copied from UDP module
	char *args, *c;
	int i;
	unsigned int n;

	num_ports = conf->source_port_last - conf->source_port_first + 1;

	if (!(conf->probe_args && strlen(conf->probe_args) > 0)){
		printf("no args, using empty tcp options\n");
		module_ipv6_tcp_synopt.packet_length = sizeof(struct ether_header) + sizeof(struct ip6_hdr)
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
	} else {
		printf("options given, but not hex, exiting!");
		exit(1);
	}
	if (tcp_send_opts_len > MAX_OPT_LEN) {
		log_warn("udp", "warning: exiting - too long option!\n");
		tcp_send_opts_len = MAX_OPT_LEN;
		exit(1);
	}
	module_ipv6_tcp_synopt.packet_length = sizeof(struct ether_header) + sizeof(struct ip6_hdr)
			+ sizeof(struct tcphdr)+ tcp_send_opts_len;

	return EXIT_SUCCESS;	
}

int ipv6_tcp_synopt_init_perthread(void* buf, macaddr_t *src,
		macaddr_t *gw, port_h_t dst_port,
		__attribute__((unused)) void **arg_ptr)
{
	memset(buf, 0, MAX_PACKET_SIZE);
	struct ether_header *eth_header = (struct ether_header *) buf;
	make_eth_header_ethertype(eth_header, src, gw, ETHERTYPE_IPV6);
	struct ip6_hdr *ip6_header = (struct ip6_hdr*)(&eth_header[1]);
	uint16_t payload_len = sizeof(struct tcphdr)+tcp_send_opts_len;
	make_ip6_header(ip6_header, IPPROTO_TCP, payload_len);
	struct tcphdr *tcp_header = (struct tcphdr*)(&ip6_header[1]);
	make_tcp_header(tcp_header, dst_port, TH_SYN);
	return EXIT_SUCCESS;
}

int ipv6_tcp_synopt_make_packet(void *buf, __attribute__((unused)) ipaddr_n_t src_ip, __attribute__((unused)) ipaddr_n_t dst_ip,
        uint32_t *validation, int probe_num, void *arg)
{
	struct ether_header *eth_header = (struct ether_header *) buf;
	struct ip6_hdr *ip6_header = (struct ip6_hdr*) (&eth_header[1]);
	struct tcphdr *tcp_header = (struct tcphdr*) (&ip6_header[1]);
	unsigned char* opts = (unsigned char*)&tcp_header[1];
	uint32_t tcp_seq = validation[0];

	ip6_header->ip6_src = ((struct in6_addr *) arg)[0];
	ip6_header->ip6_dst = ((struct in6_addr *) arg)[1];

	tcp_header->th_sport = htons(get_src_port(num_ports,
				probe_num, validation));
	tcp_header->th_seq = tcp_seq;

    memcpy(opts, tcp_send_opts, tcp_send_opts_len);

    tcp_header->th_off = 5+tcp_send_opts_len/4; // default length = 5 + 9*32 bit options

	
	tcp_header->th_sum = 0;
	tcp_header->th_sum = tcp6_checksum(sizeof(struct tcphdr)+tcp_send_opts_len,
			&ip6_header->ip6_src, &ip6_header->ip6_dst, tcp_header);

	return EXIT_SUCCESS;
}

void ipv6_tcp_synopt_print_packet(FILE *fp, void* packet)
{
	struct ether_header *ethh = (struct ether_header *) packet;
	struct ip6_hdr *iph = (struct ip6_hdr *) &ethh[1];
	struct tcphdr *tcph = (struct tcphdr *) &iph[1];
	fprintf(fp, "tcp { source: %u | dest: %u | seq: %u | checksum: %#04X }\n",
			ntohs(tcph->th_sport),
			ntohs(tcph->th_dport),
			ntohl(tcph->th_seq),
			ntohs(tcph->th_sum));
	fprintf_ipv6_header(fp, iph);
	fprintf_eth_header(fp, ethh);
	fprintf(fp, "------------------------------------------------------\n");
}

int ipv6_tcp_synopt_validate_packet(const struct ip *ip_hdr, uint32_t len,
		__attribute__((unused))uint32_t *src_ip,
		uint32_t *validation)
{
	struct ip6_hdr *ipv6_hdr = (struct ip6_hdr *) ip_hdr;

	if (ipv6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt != IPPROTO_TCP) {
		return 0;
	}
	if ((ntohs(ipv6_hdr->ip6_ctlun.ip6_un1.ip6_un1_plen)) > len) {
		// buffer not large enough to contain expected tcp header, i.e. IPv6 payload
		return 0;
	}
	struct tcphdr *tcp_hdr = (struct tcphdr*) (&ipv6_hdr[1]);
	uint16_t sport = tcp_hdr->th_sport;
	uint16_t dport = tcp_hdr->th_dport;
	// validate source port
	if (ntohs(sport) != zconf.target_port) {
		return 0;
	}
	// validate destination port
	if (!check_dst_port(ntohs(dport), num_ports, validation)) {
		return 0;
	}
	// validate tcp acknowledgement number
	if (htonl(tcp_hdr->th_ack) != htonl(validation[0])+1) {
		return 0;
	}
	return 1;
}

void ipv6_tcp_synopt_process_packet(const u_char *packet,
		__attribute__((unused)) uint32_t len, fieldset_t *fs,
		__attribute__((unused)) uint32_t *validation)
{
	struct ether_header *eth_hdr = (struct ether_header *) packet;
	struct ip6_hdr *ipv6_hdr = (struct ip6_hdr *) (&eth_hdr[1]);
	struct tcphdr *tcp_hdr = (struct tcphdr*) (&ipv6_hdr[1]);
	//	unsigned int optionbytes2=len-(sizeof(struct ether_header)+ntohs(ipv6_hdr->ip6_ctlun.ip6_un1.ip6_un1_plen) + sizeof(struct tcphdr));
	unsigned int optionbytes2=len-(sizeof(struct ether_header)+sizeof(struct ip6_hdr) + sizeof(struct tcphdr));
	tcpsynopt_process_packet_parse(len, fs,tcp_hdr,optionbytes2);
	return;

	/*
	
	char* opts = (char*)&tcp_hdr[1];
	static char* buf;
	buf = malloc(200); // buf[200];
	static char* buft;
	buft = malloc(200); // buf[200];


	fs_add_uint64(fs, "sport", (uint64_t) ntohs(tcp_hdr->th_sport));
	fs_add_uint64(fs, "dport", (uint64_t) ntohs(tcp_hdr->th_dport));
	fs_add_uint64(fs, "seqnum", (uint64_t) ntohl(tcp_hdr->th_seq));
	fs_add_uint64(fs, "acknum", (uint64_t) ntohl(tcp_hdr->th_ack));
	fs_add_uint64(fs, "window", (uint64_t) ntohs(tcp_hdr->th_win));
	fs_add_uint64(fs, "mss", (uint64_t) 0);
///////////////////////////////////////////////////////////////////

	ntohs(tcp_hdr->th_off);
	unsigned int option_bytes = (4*((unsigned int) 0xf & tcp_hdr->th_off))-20;
	unsigned int	i=0;
	snprintf(buf,3,"0x");
//	for (i=0;i<ntohs(tcp->th_off)-20;i++){
	for (i=0;i<option_bytes;i++){
		snprintf(&buf[i*2+2],3,"%02x",0xff & opts[i]);
//		printf("0x%02x\n",0xff & opts[i]);
//		printf("bufchar: %c,%c\n", buf[i*2+2],buf[i*2+1+2]);
	}
	unsigned int j=0;
	// inspired by https://nmap.org/book/osdetect-methods.html
	// ts rfc: https://www.ietf.org/rfc/rfc1323.txt
	// iana tcp options: http://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml
	unsigned char cur;
	
	for (i=0;i<option_bytes;){
		cur=0xff & opts[i];
		switch(cur) {
		case 0:
			if(	(0xff & opts[i+1]) == 0 &&
				(0xff & opts[i+2]) == 0 &&
				(0xff & opts[i+3]) == 0)
			{
				snprintf(&buft[j],2,"E"); j++;
			} else {
				snprintf(&buft[j],2,"X"); j++;				
			}
			i=option_bytes;		
			break;
		case 1: // NOP
			snprintf(&buft[j],2,"N"); j++;
			i++;
			break;
		case 2: // MSS
			if( (0xff & opts[i+1]) == 4){
				snprintf(&buft[j],2,"M"); j++;
				//snprintf(&buft[j],3,"%02x",0xff & opts[i+2]); j+=2;
				//snprintf(&buft[j],3,"%02x",0xff & opts[i+3]); j+=2;
				snprintf(&buft[j],5,"%04x", (unsigned int) ( 20+ntohs(*(unsigned short*) &opts[i+2]) ) ); j+=4;
				fs_modify_uint64(fs, "mss", (unsigned int) ( 20+ntohs(*(unsigned short*) &opts[i+2])));
				//printf("i+3: %02x\n",opts[i+3]);
				i=i+4;
			} else { // invalid case, exit parsing
				snprintf(&buft[j],5,"MXXX"); j=j+4;
				i=option_bytes;
			}
			break;
		case 4: // SACK permitted
				snprintf(&buft[j],2,"S"); j++;
				i=i+2;				
				break;
		case 8: // timestamps
			if( (0xff & opts[i+1]) == 0x0a){
				snprintf(&buft[j],5,"T"); j=j+1;
				snprintf(&buft[j],3,"%02x",0xff & opts[i+6]); j=j+2;
				snprintf(&buft[j],3,"%02x",0xff & opts[i+7]); j=j+2;
				snprintf(&buft[j],3,"%02x",0xff & opts[i+8]); j=j+2;
				snprintf(&buft[j],3,"%02x",0xff & opts[i+9]); j=j+2;
				i=i+10;
			} else {
				snprintf(&buft[j],5,"TXXX"); j=j+4;
				i=option_bytes;
			}
			break;
	// NOW DO CASES THAT SHOULD NOT APPEAR
		case 3: // Window Scale, only permitted in SYN
				snprintf(&buft[j],2,"X"); j++;
				i=i+3;
				break;
		case 5: // SACK, only permitted in SYN
				snprintf(&buft[j],2,"X"); j++;
				i=i+ (unsigned int)(0xff & opts[i+1]);
				break;
		case 6: // obsolete
				snprintf(&buft[j],2,"X"); j++;
				i=i+6;
				break;
		case 7: // obsolete
				snprintf(&buft[j],2,"X"); j++;
				i=i+6;
				break;
		case 9: // obsolete
				snprintf(&buft[j],2,"X"); j++;
				i=i+2;
				break;
		case 10: // obsolete
				snprintf(&buft[j],2,"X"); j++;
				i=i+3;
				break;
		case 14: // obsolete
				snprintf(&buft[j],2,"X"); j++;
				i=i+3;
				break;
		case 15: // SACK, only permitted in SYN
				snprintf(&buft[j],2,"X"); j++;
				i=i+ (unsigned int)(0xff & opts[i+1]);
				break;
		case 18: // obsolete
				snprintf(&buft[j],2,"X"); j++;
				i=i+3;
				break;
		case 19: // obsolete
				snprintf(&buft[j],2,"X"); j++;
				i=i+18;
				break;				
		case 27: // obsolete
				snprintf(&buft[j],2,"X"); j++;
				i=i+8;
				break;	
		case 28: // obsolete
				snprintf(&buft[j],2,"X"); j++;
				i=i+4;
				break;									
		case 30: // MPTCP TODO MAYBE USE FOR FP
				snprintf(&buft[j],2,"X"); j++;
				i=i+ (unsigned int)(0xff & opts[i+1]);
				break;									
		case 34: // TFO
				snprintf(&buft[j],2,"X"); j++;
				i=i+ (unsigned int)(0xff & opts[i+1]);
				break;	
		case 253: // exp
				snprintf(&buft[j],2,"X"); j++;
				i=i+ (unsigned int)(0xff & opts[i+1]);
				break;	
		case 254: // exp
				snprintf(&buft[j],2,"X"); j++;
				i=i+ (unsigned int)(0xff & opts[i+1]);
				break;	
		default: // even crazier crazyness ...  
			// unrec. option
			snprintf(&buft[j],2,"U"); j++;
			i=option_bytes;
			break;
	}	
	}
	
	//buf[i*2+1] = '\0';
//	printf("buf: %s\n",buf);
//	printf("--\n");
	//snprintf(buf,199,"0x%x",(unsigned int)opts[0]);
	//snprintf(buf,199,"0x%x",ntohl((unsigned int)opts));

//	printf("0x%02x\n",ntohl((unsigned int)opts));
//	printf("0x%02x\n",(unsigned int)opts);
//	printf("0x%02x",0xff&opts[0]);
//	printf("%02x",0xff&opts[1]);
//	printf("%02x",0xff&opts[2]);
//	printf("%02x\n",0xff&opts[3]);

	fs_add_string(fs, "optionshex", (char*) buf, 1); // set to 1 to avoid mem leak
	fs_add_string(fs, "optionstext", (char*) buft, 1); // set to 1 to avoid mem leak



////////////////////////////////////////////////////////////////////
	if (tcp_hdr->th_flags & TH_RST) { // RST packet
		fs_add_string(fs, "classification", (char*) "rst", 0);
		fs_add_uint64(fs, "success", 0);
	} else { // SYNACK packet
		fs_add_string(fs, "classification", (char*) "synack", 0);
		fs_add_uint64(fs, "success", 1);
	}*/
}

probe_module_t module_ipv6_tcp_synopt = {
	.name = "ipv6_tcp_synopt",
	.packet_length = 74, // will be extended at runtime
	.pcap_filter = "ip6 proto 6 && (ip6[53] & 4 != 0 || ip6[53] == 18)",
	.pcap_snaplen = 116+10*4, // max option len
	.port_args = 1,
	.global_initialize = &ipv6_tcp_synopt_global_initialize,
	.thread_initialize = &ipv6_tcp_synopt_init_perthread,
	.make_packet = &ipv6_tcp_synopt_make_packet,
	.print_packet = &ipv6_tcp_synopt_print_packet,
	.process_packet = &ipv6_tcp_synopt_process_packet,
	.validate_packet = &ipv6_tcp_synopt_validate_packet,
	.close = NULL,
	.helptext = "Probe module that sends an IPv6+TCP SYN packet to a specific "
		"port. Possible classifications are: synack and rst. A "
		"SYN-ACK packet is considered a success and a reset packet "
		"is considered a failed response.",
	.fields = fields,
	.numfields = sizeof(fields)/sizeof(fields[0])
	};
//	.numfields = 10};


