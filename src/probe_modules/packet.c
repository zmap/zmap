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

#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#include <net/if.h>
#include <arpa/inet.h>

#include "state.h"

void print_macaddr(struct ifreq* i)
{
	printf("Device %s -> Ethernet %02x:%02x:%02x:%02x:%02x:%02x\n",
			i->ifr_name,
			(int) ((unsigned char *) &i->ifr_hwaddr.sa_data)[0],
			(int) ((unsigned char *) &i->ifr_hwaddr.sa_data)[1],
			(int) ((unsigned char *) &i->ifr_hwaddr.sa_data)[2],
			(int) ((unsigned char *) &i->ifr_hwaddr.sa_data)[3],
			(int) ((unsigned char *) &i->ifr_hwaddr.sa_data)[4],
			(int) ((unsigned char *) &i->ifr_hwaddr.sa_data)[5]);
}

void make_eth_header(struct ethhdr *ethh, macaddr_t *src, macaddr_t *dst)
{
	memcpy(ethh->h_source, src, ETH_ALEN);
	memcpy(ethh->h_dest, dst, ETH_ALEN);
	ethh->h_proto = htons(ETH_P_IP);
}

void make_ip_header(struct iphdr *iph, uint8_t protocol, uint16_t len)
{	   
	iph->ihl = 5; // Internet Header Length
	iph->version = 4; // IPv4
	iph->tos = 0; // Type of Service
	iph->tot_len = len; 
	iph->id = htons(54321); // identification number
	iph->frag_off = 0; //fragmentation falg
	iph->ttl = MAXTTL; // time to live (TTL)
	iph->protocol = protocol; // upper layer protocol => TCP
	// we set the checksum = 0 for now because that's
	// what it needs to be when we run the IP checksum
	iph->check = 0;
}

void make_icmp_header(struct icmp *buf)
{
	buf->icmp_type = ICMP_ECHO;
	buf->icmp_code = 0;
	buf->icmp_seq = 0;
}

void make_tcp_header(struct tcphdr *tcp_header, port_h_t dest_port)
{
    tcp_header->seq = random();
    tcp_header->ack_seq = 0;
    tcp_header->res2 = 0;
    tcp_header->doff = 5; // data offset 
    tcp_header->syn = 1;
    tcp_header->window = htons(65535); // largest possible window
    tcp_header->check = 0;
    tcp_header->urg_ptr = 0;
    tcp_header->dest = htons(dest_port);
}

void make_udp_header(struct udphdr *udp_header, port_h_t dest_port,
				uint16_t len)
{
	udp_header->dest = htons(dest_port);
	udp_header->len = htons(len);
	// checksum ignored in IPv4 if 0
	udp_header->check = 0;
}

