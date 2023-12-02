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
#include "./send.h"
#include <sys/ioctl.h>
#include <stdlib.h>
#include <stdio.h>

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
		log_error("send", "%s", "SIOCGIFINDEX");
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

int send_batch(sock_t sock, batch_t* batch) {
	printf("Entered send batch\n");
	struct mmsghdr msgvec[batch->len]; // Array of multiple msg header structures
	printf("created msgvec\n");

	for (int i = 0; i < batch->len; ++i) {
		printf("loop iteration %d\n", i);
		struct iovec iov = {batch->packets[i]->buf, batch->packets[i]->len};
		struct msghdr message;
		memset(&message, 0, sizeof(struct msghdr));
		message.msg_name = &sockaddr;
		message.msg_namelen = sizeof(struct sockaddr_ll)
		message.msg_iov = &iov;
		message.msg_iovlen = 1;

		msgvec[i].msg_hdr = message;
		msgvec[i].msg_len = batch->packets[i]->len;
	}

	// Use sendmmsg to send the batch of packets
	printf("about to sendmmsg\n");
	int rv = sendmmsg(sock.sock, msgvec, batch->len, 0);
	printf("send mmsg returned %d\n", rv);
	return rv;
}

#endif /* ZMAP_SEND_LINUX_H */
