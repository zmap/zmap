#include "../../lib/includes.h"
#include "../state.h"

#ifndef PACKET_H
#define PACKET_H

#define MAX_PACKET_SIZE 4096

typedef unsigned short __attribute__((__may_alias__)) alias_unsigned_short;

void make_eth_header(struct ether_header *ethh, macaddr_t *src, macaddr_t *dst);

void make_ip_header(struct ip *iph, uint8_t, uint16_t);
void make_tcp_header(struct tcphdr*, port_h_t);
void make_icmp_header(struct icmp *);
void make_udp_header(struct udphdr *udp_header, port_h_t dest_port,
				uint16_t len);
void fprintf_ip_header(FILE *fp, struct ip *iph);
void fprintf_eth_header(FILE *fp, struct ether_header *ethh);

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

__attribute__((unused)) static inline unsigned short zmap_ip_checksum(
                unsigned short *buf)
{
	return in_checksum(buf, (int) sizeof(struct ip));
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

// Returns 0 if dst_port is outside the expected valid range, non-zero otherwise
static __attribute__((unused)) inline int check_dst_port(uint16_t port,
				int num_ports, uint32_t *validation)
{
	if (port > zconf.source_port_last 
					|| port < zconf.source_port_first) {
		return -1;
	}
	int32_t to_validate = port - zconf.source_port_first;
	int32_t min = validation[1] % num_ports;
	int32_t max = (validation[1] + zconf.packet_streams - 1) % num_ports;

	return (((max - min) % num_ports) >= ((to_validate - min) % num_ports));
}

static __attribute__((unused)) inline uint16_t get_src_port(int num_ports, 
				int probe_num, uint32_t *validation)
{
	return zconf.source_port_first + ((validation[1] + probe_num) % num_ports);
}

// Note: caller must free return value
char *make_ip_str(uint32_t ip);

#endif
