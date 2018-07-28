/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef ZMAP_SEND_LINUX_H
#define ZMAP_SEND_LINUX_H

#include "../lib/includes.h"
#include <sys/ioctl.h>

#include <netpacket/packet.h>

#ifdef ZMAP_SEND_BSD_H
#error "Don't include both send-bsd.h and send-linux.h"
#endif

// Dummy sockaddr for sendto
static struct sockaddr_ll sockaddr;

int send_run_init(sock_t s)
{
	// Get the actual socket
	int sock = s.sock;
	// get source interface index
	struct ifreq if_idx;
	memset(&if_idx, 0, sizeof(struct ifreq));
	if (strlen(zconf.iface) >= IFNAMSIZ) {
		log_error("send", "device interface name (%s) too long\n",
			  zconf.iface);
		return EXIT_FAILURE;
	}
	strncpy(if_idx.ifr_name, zconf.iface, IFNAMSIZ - 1);
	if (ioctl(sock, SIOCGIFINDEX, &if_idx) < 0) {
		perror("SIOCGIFINDEX");
		return EXIT_FAILURE;
	}
	int ifindex = if_idx.ifr_ifindex;

	// destination address for the socket
	memset((void *)&sockaddr, 0, sizeof(struct sockaddr_ll));
	sockaddr.sll_ifindex = ifindex;
	sockaddr.sll_halen = ETH_ALEN;
	if (zconf.send_ip_pkts) {
		sockaddr.sll_protocol = htons(ETHERTYPE_IP);
	}
	memcpy(sockaddr.sll_addr, zconf.gw_mac, ETH_ALEN);
	return EXIT_SUCCESS;
}

int send_packet(sock_t sock, void *buf, int len, UNUSED uint32_t idx)
{
	return sendto(sock.sock, buf, len, 0, (struct sockaddr *)&sockaddr,
		      sizeof(struct sockaddr_ll));
}

#endif /* ZMAP_SEND_LINUX_H */
