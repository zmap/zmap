#include "state.h"

#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>

#ifndef HEADER_ZMAP_PACKET_H
#define HEADER_ZMAP_PACKET_H

#define MAX_PACKET_SIZE 4096

typedef unsigned short __attribute__((__may_alias__)) alias_unsigned_short;

void make_eth_header(struct ethhdr *ethh, macaddr_t *src, macaddr_t *dst);

void make_ip_header(struct iphdr *iph, uint8_t, uint16_t);
void make_tcp_header(struct tcphdr*, port_h_t);
void make_icmp_header(struct icmp *);
void make_udp_header(struct udphdr *udp_header, port_h_t dest_port,
				uint16_t len);

static inline unsigned short in_checksum(unsigned short *ip_pkt, int len)
{
	unsigned long sum = 0;
	for (int nwords = len/2; nwords > 0; nwords--) {
		sum += *ip_pkt++;
	}
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return (unsigned short) (~sum);
}

__attribute__((unused)) static inline unsigned short ip_checksum(
                unsigned short *buf)
{
	return in_checksum(buf, (int) sizeof(struct iphdr));
}

__attribute__((unused)) static inline unsigned short icmp_checksum(
                unsigned short *buf)
{
	return in_checksum(buf, (int) sizeof(struct icmp));
}

static __attribute__((unused)) uint16_t tcp_checksum(unsigned short len_tcp,
		uint32_t saddr, uint32_t daddr, struct tcphdr *tcp_pkt)
{
	alias_unsigned_short *src_addr = (alias_unsigned_short *) &saddr;
	alias_unsigned_short *dest_addr = (alias_unsigned_short *) &daddr;

	unsigned char prot_tcp = 6;
	unsigned long sum = 0;
	int nleft = len_tcp;
	unsigned short *w;

	w = (unsigned short *) tcp_pkt;
	// calculate the checksum for the tcp header and tcp data
	while(nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}
	// if nleft is 1 there ist still on byte left.
	// We add a padding byte (0xFF) to build a 16bit word
	if (nleft > 0) {
		sum += *w & ntohs(0xFF00);
	}
	// add the pseudo header
	sum += src_addr[0];
	sum += src_addr[1];
	sum += dest_addr[0];
	sum += dest_addr[1];
	sum += htons(len_tcp);
	sum += htons(prot_tcp);
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	// Take the one's complement of sum
	return (unsigned short) (~sum);
}

#endif
