/*
 * ZMap Copyright 2013 Regents of the University of Michigan 
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

/* send module for performing TCP SYN scans */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/ether.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "probe_modules.h"
#include "packet.h"
#include "logger.h"

#define MAX_UDP_PAYLOAD_LEN 1472

char *udp_send_msg = NULL;
int udp_send_msg_len = 0;

const char *udp_send_msg_default = "GET / HTTP/1.1\r\nHost: www\r\n\r\n"; 

static int num_ports = 1;

probe_module_t module_udp;


int udp_global_initialize(struct state_conf * zconf) {
	char *args, *c;
	int i;
	unsigned int n;

	FILE *inp;

	udp_send_msg = strdup(udp_send_msg_default);
	udp_send_msg_len = strlen(udp_send_msg);

	if (! (zconf->probe_args && strlen(zconf->probe_args) > 0)) 
		return(0);
	
	args = strdup(zconf->probe_args);
	if (! args) exit(1);

	c = strchr(args, ':');
	if (! c) {
		free(args);
		free(udp_send_msg);
		log_fatal("udp", "unknown UDP probe specification (expected file:/path or text:STRING or hex:01020304)");
		exit(1);
	}

	*c++ = 0;

	if (strcmp(args, "text") == 0) {
		free(udp_send_msg);
		udp_send_msg = strdup(c);
		udp_send_msg_len = strlen(udp_send_msg);

	} else if (strcmp(args, "file") == 0) {
		inp = fopen(c, "rb");
		if (!inp) {
			free(args);
			free(udp_send_msg);
			log_fatal("udp", "could not open UDP data file '%s'\n", c);
			exit(1);
		}
		free(udp_send_msg);
		udp_send_msg = malloc(MAX_UDP_PAYLOAD_LEN);
		if (! udp_send_msg) {
			free(args);
			log_fatal("udp", "failed to malloc payload buffer");
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
			log_fatal("udp", "failed to malloc payload buffer");
			exit(1);
		}

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
		log_fatal("udp", "unknown UDP probe specification (expected file:/path, text:STRING, or hex:01020304)");
		free(udp_send_msg);
		free(args);
		exit(1);
	}

	if (udp_send_msg_len > MAX_UDP_PAYLOAD_LEN) {
		log_warn("udp", "warning: reducing UDP payload to %d bytes (from %d) to fit on the wire\n", 
				MAX_UDP_PAYLOAD_LEN, udp_send_msg_len);
		udp_send_msg_len = MAX_UDP_PAYLOAD_LEN;
	}
	free(args);
	return(0);
}

int udp_global_cleanup(__attribute__((unused)) struct state_conf *zconf,
					   __attribute__((unused)) struct state_send *zsend,
					   __attribute__((unused)) struct state_recv *zrecv) {
	if (udp_send_msg) free(udp_send_msg);
	udp_send_msg = NULL;
	return(0);
}


int udp_init_perthread(void* buf, macaddr_t *src,
		macaddr_t *gw, __attribute__((unused)) port_h_t dst_port)
{
	memset(buf, 0, MAX_PACKET_SIZE);
	struct ethhdr *eth_header = (struct ethhdr *)buf;
	make_eth_header(eth_header, src, gw);
	struct iphdr *ip_header = (struct iphdr*)(&eth_header[1]);
	uint16_t len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + udp_send_msg_len);
	make_ip_header(ip_header, IPPROTO_UDP, len);

	struct udphdr *udp_header = (struct udphdr*)(&ip_header[1]);
	len = sizeof(struct udphdr) + udp_send_msg_len;
	make_udp_header(udp_header, zconf.target_port, len);

	char* payload = (char*)(&udp_header[1]);

	module_udp.packet_length = sizeof(struct ethhdr) + sizeof(struct iphdr) 
				+ sizeof(struct udphdr) + udp_send_msg_len;
	assert(module_udp.packet_length <= MAX_PACKET_SIZE);

	memcpy(payload, udp_send_msg, udp_send_msg_len);

	num_ports = zconf.source_port_last - zconf.source_port_first + 1;

	return EXIT_SUCCESS;
}

int udp_make_packet(void *buf, ipaddr_n_t src_ip, ipaddr_n_t dst_ip, 
		uint32_t *validation, int probe_num)
{
	struct ethhdr *eth_header = (struct ethhdr *)buf;
	struct iphdr *ip_header = (struct iphdr*)(&eth_header[1]);
	struct udphdr *udp_header = (struct udphdr*)(&ip_header[1]);
	uint16_t src_port = zconf.source_port_first
					+ ((validation[1] + probe_num) % num_ports);

	ip_header->saddr = src_ip;
	ip_header->daddr = dst_ip;
	udp_header->source = src_port;

	ip_header->check = 0;
	ip_header->check = ip_checksum((unsigned short *) ip_header);

	return EXIT_SUCCESS;
}

void udp_print_packet(FILE *fp, void* packet)
{
	struct ethhdr *ethh = (struct ethhdr *) packet;
	struct iphdr *iph = (struct iphdr *) &ethh[1];
	struct udphdr *udph  = (struct udphdr*)(&iph[1]);
	fprintf(fp, "udp { source: %u | dest: %u | checksum: %u }\n",
			ntohs(udph->source),
			ntohs(udph->dest),
			ntohl(udph->check));
	//ip_header = (struct iphdr*)(&eth_header[1])
	struct in_addr *s = (struct in_addr *) &(iph->saddr);
	struct in_addr *d = (struct in_addr *) &(iph->daddr);
	char srcip[20];
	char dstip[20];
	// inet_ntoa is a const char * so we if just call it in
	// fprintf, you'll get back wrong results since we're
	// calling it twice.
	strncpy(srcip, inet_ntoa(*s), 19);
	strncpy(dstip, inet_ntoa(*d), 19);
	fprintf(fp, "ip { saddr: %s | daddr: %s | checksum: %u }\n",
			srcip,
			dstip,
			ntohl(iph->check));
	fprintf(fp, "eth { shost: %02x:%02x:%02x:%02x:%02x:%02x | "
			"dhost: %02x:%02x:%02x:%02x:%02x:%02x }\n",
			(int) ((unsigned char *) ethh->h_source)[0],
			(int) ((unsigned char *) ethh->h_source)[1],
			(int) ((unsigned char *) ethh->h_source)[2],
			(int) ((unsigned char *) ethh->h_source)[3],
			(int) ((unsigned char *) ethh->h_source)[4],
			(int) ((unsigned char *) ethh->h_source)[5],
			(int) ((unsigned char *) ethh->h_dest)[0],
			(int) ((unsigned char *) ethh->h_dest)[1],
			(int) ((unsigned char *) ethh->h_dest)[2],
			(int) ((unsigned char *) ethh->h_dest)[3],
			(int) ((unsigned char *) ethh->h_dest)[4],
			(int) ((unsigned char *) ethh->h_dest)[5]);
	fprintf(fp, "------------------------------------------------------\n");
}


response_type_t* udp_classify_packet(const u_char *packet, uint32_t len)
{
	(void)len;
	struct iphdr *ip_hdr = (struct iphdr *)&packet[sizeof(struct ethhdr)];
	if (ip_hdr->protocol == IPPROTO_UDP) {
		return &(module_udp.responses[0]);
	} else if (ip_hdr->protocol == IPPROTO_ICMP) {
		return &(module_udp.responses[1]);
	} else {
		return &(module_udp.responses[2]);
	}
}

// Returns 0 if dst_port is outside the expected valid range, non-zero otherwise
static inline int check_dst_port(uint16_t port, uint32_t *validation)
{
	if (port > zconf.source_port_last 
					|| port < zconf.source_port_first) {
		return EXIT_FAILURE;
	}
	int32_t to_validate = port - zconf.source_port_first;
	int32_t min = validation[1] % num_ports;
	int32_t max = (validation[1] + zconf.packet_streams - 1) % num_ports;

	return (((max - min) % num_ports) >= ((to_validate - min) % num_ports));
}

int udp_validate_packet(const struct iphdr *ip_hdr, uint32_t len, 
		__attribute__((unused))uint32_t *src_ip, uint32_t *validation)
{
	uint16_t dport, sport;
	if (ip_hdr->protocol == IPPROTO_UDP) {
		if ((4*ip_hdr->ihl + sizeof(struct udphdr)) > len) {
			// buffer not large enough to contain expected udp header 
			return 0;
		}
		struct udphdr *udp = (struct udphdr*)((char *)ip_hdr + 4*ip_hdr->ihl);

		sport = ntohs(udp->dest);
		dport = ntohs(udp->source);
	} else if (ip_hdr->protocol == IPPROTO_ICMP) {
		// UDP can return ICMP Destination unreach
		// IP( ICMP( IP( UDP ) ) ) for a destination unreach
		uint32_t min_len = 4*ip_hdr->ihl + sizeof(struct icmphdr)
				+ sizeof(struct iphdr) + sizeof(struct udphdr);
		if (len < min_len) {
			// Not enough information for us to validate
			return 0;
		}

		struct icmphdr *icmp = (struct icmphdr*)((char *)ip_hdr + 4*ip_hdr->ihl);
		if (icmp->type != ICMP_DEST_UNREACH) {
			return 0;
		}
		
		struct iphdr *ip_inner = (struct iphdr*)&icmp[1];
		// Now we know the actual inner ip length, we should recheck the buffer
		if (len < 4*ip_inner->ihl - sizeof(struct iphdr) + min_len) {
			return 0;
		}
		// This is the packet we sent
		struct udphdr *udp = (struct udphdr *)((char*)ip_inner + 4*ip_inner->ihl);

		sport = ntohs(udp->source);
		dport = ntohs(udp->dest);	
	} else {
		return 0;
	}
	if (dport != zconf.target_port) {
		return 0;
	}
	if (!check_dst_port(sport, validation)) {
		return 0;
	}
	return 1;
}

static response_type_t responses[] = {
	{
		.is_success = 1,
		.name = "data"
	},
	{
		.is_success = 0,
		.name = "port-unreach"
	},
	{
		.is_success = 0,
		.name = "invalid"
	}
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
	.classify_packet = &udp_classify_packet,
	.close = &udp_global_cleanup,
	.responses = responses
};

