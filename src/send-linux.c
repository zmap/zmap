//
// Created by Phillip Stephens on 12/4/23.
//

#define _GNU_SOURCE
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>

#include <netpacket/packet.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <linux/netlink.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "../lib/includes.h"
#include "./send.h"
#include "./send-linux.h"

#include <netpacket/packet.h>


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

int send_batch(sock_t sock, batch_t* batch) {
	// TODO need to malloc this and make it dependent on batch size
	struct mmsghdr msgvec [BATCH_SIZE]; // Array of multiple msg header structures
	struct msghdr msgs[BATCH_SIZE];
	struct iovec iovs[BATCH_SIZE];
	// printf("send_batch called\n");

	for (int i = 0; i < batch->len; ++i) {
//		printf("loop iteration %d\n", i);
		struct iovec *iov = &iovs[i];
	    	iov->iov_base = ((void *)batch->packets) + (i * MAX_PACKET_SIZE);
	       	iov->iov_len = batch->lens[i];
		struct msghdr *msg = &msgs[i];
		memset(msg, 0, sizeof(struct msghdr));
		// necessary based on https://github.com/torvalds/linux/blob/master/net/socket.c#L2180
		msg->msg_name = (struct sockaddr *)&sockaddr;
		msg->msg_namelen = sizeof(struct sockaddr_ll);
		msg->msg_iov = iov;
		msg->msg_iovlen = 1;

		msgvec[i].msg_hdr = *msg;
		msgvec[i].msg_len = batch->lens[i];

	}
	// Use sendmmsg to send the batch of packets
	int rv = sendmmsg(sock.sock, &msgvec, batch->len, 0);
	if (rv < 0) {
		perror("Error in sendmmsg");
	}
	return rv;
}
