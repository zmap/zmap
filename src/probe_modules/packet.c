/*
 * ZMap Copyright 2013 Regents of the University of Michigan 
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include "packet.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "../../lib/includes.h"
#include "../state.h"

#ifndef NDEBUG
void print_macaddr(struct ifreq* i)
{
	printf("Device %s -> Ethernet %02x:%02x:%02x:%02x:%02x:%02x\n",
			i->ifr_name,
			(int) ((unsigned char *) &i->ifr_addr.sa_data)[0],
			(int) ((unsigned char *) &i->ifr_addr.sa_data)[1],
			(int) ((unsigned char *) &i->ifr_addr.sa_data)[2],
			(int) ((unsigned char *) &i->ifr_addr.sa_data)[3],
			(int) ((unsigned char *) &i->ifr_addr.sa_data)[4],
			(int) ((unsigned char *) &i->ifr_addr.sa_data)[5]);
}
#endif /* NDEBUG */

void fprintf_ip_header(FILE *fp, struct ip *iph)
{
	struct in_addr *s = (struct in_addr *) &(iph->ip_src);
	struct in_addr *d = (struct in_addr *) &(iph->ip_dst);
	char srcip[20];
	char dstip[20];
	// inet_ntoa is a const char * so we if just call it in
	// fprintf, you'll get back wrong results since we're
	// calling it twice.
	strncpy(srcip, inet_ntoa(*s), 19);
	strncpy(dstip, inet_ntoa(*d), 19);
	fprintf(fp, "ip { saddr: %s | daddr: %s | checksum: %#04X }\n",
			srcip,
			dstip,
			ntohs(iph->ip_sum));
}

void fprintf_eth_header(FILE *fp, struct ether_header *ethh)
{
	fprintf(fp, "eth { shost: %02x:%02x:%02x:%02x:%02x:%02x | "
			"dhost: %02x:%02x:%02x:%02x:%02x:%02x }\n",
			(int) ((unsigned char *) ethh->ether_shost)[0],
			(int) ((unsigned char *) ethh->ether_shost)[1],
			(int) ((unsigned char *) ethh->ether_shost)[2],
			(int) ((unsigned char *) ethh->ether_shost)[3],
			(int) ((unsigned char *) ethh->ether_shost)[4],
			(int) ((unsigned char *) ethh->ether_shost)[5],
			(int) ((unsigned char *) ethh->ether_dhost)[0],
			(int) ((unsigned char *) ethh->ether_dhost)[1],
			(int) ((unsigned char *) ethh->ether_dhost)[2],
			(int) ((unsigned char *) ethh->ether_dhost)[3],
			(int) ((unsigned char *) ethh->ether_dhost)[4],
			(int) ((unsigned char *) ethh->ether_dhost)[5]);
}

void make_eth_header(struct ether_header *ethh, macaddr_t *src, macaddr_t *dst)
{
	memcpy(ethh->ether_shost, src, ETHER_ADDR_LEN);
	memcpy(ethh->ether_dhost, dst, ETHER_ADDR_LEN);
	ethh->ether_type = htons(ETHERTYPE_IP);
}

void make_ip_header(struct ip *iph, uint8_t protocol, uint16_t len)
{	   
	iph->ip_hl = 5; // Internet Header Length
	iph->ip_v = 4; // IPv4
	iph->ip_tos = 0; // Type of Service
	iph->ip_len = len; 
	iph->ip_id = htons(54321); // identification number
	iph->ip_off = 0; //fragmentation falg
	iph->ip_ttl = MAXTTL; // time to live (TTL)
	iph->ip_p = protocol; // upper layer protocol => TCP
	// we set the checksum = 0 for now because that's
	// what it needs to be when we run the IP checksum
	iph->ip_sum = 0;
}

void make_icmp_header(struct icmp *buf)
{
	buf->icmp_type = ICMP_ECHO;
	buf->icmp_code = 0;
	buf->icmp_seq = 0;
}

void make_tcp_header(struct tcphdr *tcp_header, port_h_t dest_port)
{
    tcp_header->th_seq = random();
    tcp_header->th_ack = 0;
    tcp_header->th_x2 = 0;
    tcp_header->th_off = 5; // data offset
    tcp_header->th_flags = 0; 
    tcp_header->th_flags |= TH_SYN;
    tcp_header->th_win = htons(65535); // largest possible window
    tcp_header->th_sum = 0;
    tcp_header->th_urp = 0;
    tcp_header->th_dport = htons(dest_port);
}

void make_udp_header(struct udphdr *udp_header, port_h_t dest_port,
				uint16_t len)
{
	udp_header->uh_dport = htons(dest_port);
	udp_header->uh_ulen = htons(len);
	// checksum ignored in IPv4 if 0
	udp_header->uh_sum = 0;
}

// Note: caller must free return value
char *make_ip_str(uint32_t ip)
{
	struct in_addr t;
	t.s_addr = ip;
	const char *temp = inet_ntoa(t);
	char *retv = malloc(strlen(temp)+1);
	assert (retv);
	strcpy(retv, temp);
	return retv;
}

