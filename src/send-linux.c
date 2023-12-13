/*
 * Copyright 2023 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>

#include <netpacket/packet.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/netlink.h>

#include "../lib/includes.h"
#include "../lib/logger.h"
#include "./send.h"
#include "./send-linux.h"

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

int send_batch(sock_t sock, batch_t* batch, int retries) {
	struct mmsghdr msgvec [batch->capacity]; // Array of multiple msg header structures
	struct msghdr msgs[batch->capacity];
	struct iovec iovs[batch->capacity];

	for (int i = 0; i < batch->len; ++i) {
		struct iovec *iov = &iovs[i];
	    	iov->iov_base = ((void *)batch->packets) + (i * MAX_PACKET_SIZE);
	       	iov->iov_len = batch->lens[i];
		struct msghdr *msg = &msgs[i];
		memset(msg, 0, sizeof(struct msghdr));
		// based on https://github.com/torvalds/linux/blob/master/net/socket.c#L2180
		msg->msg_name = (struct sockaddr *)&sockaddr;
		msg->msg_namelen = sizeof(struct sockaddr_ll);
		msg->msg_iov = iov;
		msg->msg_iovlen = 1;
		msgvec[i].msg_hdr = *msg;
		msgvec[i].msg_len = batch->lens[i];
	}
	int rv = 0;
	for (int i = 0; i < retries; i++) {
		// according to manpages
		// On success, sendmmsg() returns the number of messages sent from msgvec; if this is less than vlen, the
		//       caller can retry with a further sendmmsg() call to send the remaining messages.
		// On error, -1 is returned, and errno is set to indicate the error.
		rv = sendmmsg(sock.sock, &msgvec, batch->len, 0);
		if (rv < 0) {
			// only retry if all messages failed to send
			log_error("batch send", "error in sendmmsg: %s", strerror(errno));
		} else {
			break;
		}
	}
	return rv;
}
