/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "../../lib/includes.h"
#include "../../lib/xalloc.h"
#include "packet.h"

#include "../state.h"

#ifndef NDEBUG
void print_macaddr(struct ifreq *i)
{
	printf("Device %s -> Ethernet %02x:%02x:%02x:%02x:%02x:%02x\n",
	       i->ifr_name, (int)((unsigned char *)&i->ifr_addr.sa_data)[0],
	       (int)((unsigned char *)&i->ifr_addr.sa_data)[1],
	       (int)((unsigned char *)&i->ifr_addr.sa_data)[2],
	       (int)((unsigned char *)&i->ifr_addr.sa_data)[3],
	       (int)((unsigned char *)&i->ifr_addr.sa_data)[4],
	       (int)((unsigned char *)&i->ifr_addr.sa_data)[5]);
}
#endif /* NDEBUG */

#define IP_ADDR_LEN_STR 20

void fprintf_ip_header(FILE *fp, struct ip *iph)
{
	struct in_addr *s = (struct in_addr *)&(iph->ip_src);
	struct in_addr *d = (struct in_addr *)&(iph->ip_dst);

	char srcip[IP_ADDR_LEN_STR + 1];
	char dstip[IP_ADDR_LEN_STR + 1];
	// inet_ntoa is a const char * so we if just call it in
	// fprintf, you'll get back wrong results since we're
	// calling it twice.
	strncpy(srcip, inet_ntoa(*s), IP_ADDR_LEN_STR - 1);
	strncpy(dstip, inet_ntoa(*d), IP_ADDR_LEN_STR - 1);

	srcip[IP_ADDR_LEN_STR] = '\0';
	dstip[IP_ADDR_LEN_STR] = '\0';

	fprintf(fp, "ip { saddr: %s | daddr: %s | checksum: %#04X }\n", srcip,
		dstip, ntohs(iph->ip_sum));
}

void fprintf_ipv6_header(FILE *fp, struct ip6_hdr *iph)
{
	struct in6_addr *s = (struct in6_addr *) &(iph->ip6_src);
	struct in6_addr *d = (struct in6_addr *) &(iph->ip6_dst);

	char srcip[INET6_ADDRSTRLEN+1];
	char dstip[INET6_ADDRSTRLEN+1];
	unsigned char next = (unsigned char) (iph->ip6_nxt);

	// TODO: Is restrict correct here?
	inet_ntop(AF_INET6, s, (char * restrict) &srcip, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6, d, (char * restrict) &dstip, INET6_ADDRSTRLEN);

	srcip[INET6_ADDRSTRLEN] = '\0';
	dstip[INET6_ADDRSTRLEN] = '\0';

	fprintf(fp, "ip6 { saddr: %s | daddr: %s | nxthdr: %u }\n",
			srcip,
			dstip,
			next);
}

void fprintf_eth_header(FILE *fp, struct ether_header *ethh)
{
	if (!zconf.send_ip_pkts) {
		fprintf(fp,
			"eth { shost: %02x:%02x:%02x:%02x:%02x:%02x | "
			"dhost: %02x:%02x:%02x:%02x:%02x:%02x }\n",
			(int)((unsigned char *)ethh->ether_shost)[0],
			(int)((unsigned char *)ethh->ether_shost)[1],
			(int)((unsigned char *)ethh->ether_shost)[2],
			(int)((unsigned char *)ethh->ether_shost)[3],
			(int)((unsigned char *)ethh->ether_shost)[4],
			(int)((unsigned char *)ethh->ether_shost)[5],
			(int)((unsigned char *)ethh->ether_dhost)[0],
			(int)((unsigned char *)ethh->ether_dhost)[1],
			(int)((unsigned char *)ethh->ether_dhost)[2],
			(int)((unsigned char *)ethh->ether_dhost)[3],
			(int)((unsigned char *)ethh->ether_dhost)[4],
			(int)((unsigned char *)ethh->ether_dhost)[5]);
	}
}

void make_eth_header(struct ether_header *ethh, macaddr_t *src, macaddr_t *dst)
{
	// Create a frame with IPv4 ethertype by default
	make_eth_header_ethertype(ethh, src, dst, ETHERTYPE_IP);
}

void make_eth_header_ethertype(struct ether_header *ethh, macaddr_t *src, macaddr_t *dst, uint16_t ethertype)
{
	memcpy(ethh->ether_shost, src, ETHER_ADDR_LEN);
	memcpy(ethh->ether_dhost, dst, ETHER_ADDR_LEN);
	ethh->ether_type = htons(ethertype);
}

void make_ip_header(struct ip *iph, uint8_t protocol, uint16_t len)
{
	iph->ip_hl = 5;  // Internet Header Length
	iph->ip_v = 4;   // IPv4
	iph->ip_tos = 0; // Type of Service
	iph->ip_len = len;
	iph->ip_id = htons(54321); // identification number
	iph->ip_off = 0;	   // fragmentation flag
	iph->ip_ttl = MAXTTL;      // time to live (TTL)
	iph->ip_p = protocol;      // upper layer protocol => TCP
	// we set the checksum = 0 for now because that's
	// what it needs to be when we run the IP checksum
	iph->ip_sum = 0;
}

void make_ip6_header(struct ip6_hdr *iph, uint8_t protocol, uint16_t len)
{
	iph->ip6_ctlun.ip6_un2_vfc = 0x60; // 4 bits version, top 4 bits class
	iph->ip6_ctlun.ip6_un1.ip6_un1_plen = htons(len); // payload length
	iph->ip6_ctlun.ip6_un1.ip6_un1_nxt = protocol; // next header
	iph->ip6_ctlun.ip6_un1.ip6_un1_hlim = MAXTTL; // hop limit
}
void make_icmp6_header(struct icmp6_hdr *buf)
{
    buf->icmp6_type = ICMP6_ECHO_REQUEST;
    buf->icmp6_code = 0;
    buf->icmp6_cksum = 0;
    // buf->icmp_seq = 0;
    // TODO: Set ICMP ECHO REQ specific fields
}

void make_icmp_header(struct icmp *buf)
{
	buf->icmp_type = ICMP_ECHO;
	buf->icmp_code = 0;
	buf->icmp_seq = 0;
}

void make_tcp_header(struct tcphdr *tcp_header, port_h_t dest_port,
		     uint16_t th_flags)
{
	tcp_header->th_seq = random();
	tcp_header->th_ack = 0;
	tcp_header->th_x2 = 0;
	tcp_header->th_off = 5; // data offset
	tcp_header->th_flags = 0;
	tcp_header->th_flags |= th_flags;
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
	char *retv = xmalloc(strlen(temp) + 1);
	strcpy(retv, temp);
	return retv;
}

// Note: caller must free return value
char *make_ipv6_str(struct in6_addr *ipv6)
{
	char *retv = xmalloc(INET6_ADDRSTRLEN + 1);
	inet_ntop(AF_INET6, ipv6, retv, INET6_ADDRSTRLEN);
	return retv;
}
