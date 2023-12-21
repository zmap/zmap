/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef ZMAP_SEND_LINUX_H
#define ZMAP_SEND_LINUX_H

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <errno.h>
#include <liburing.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "../lib/includes.h"


#ifdef ZMAP_SEND_BSD_H
#error "Don't include both send-bsd.h and send-linux.h"
#endif

// TODO Phillip you'll need to figure out how to compile both the below and for earlier linux versions w/o iouring

// Dummy sockaddr for sendto
static struct sockaddr_ll sockaddr;

// Each thread will send packets using its own liburing variables to avoid needing locks/increasing contention
// io_uring instance for each thread
__thread struct io_uring ring;
__thread uint16_t submission_ring_len = 0;
#define QUEUE_DEPTH 512
// The io_uring is an async I/O package. In send_packet, the caller passes in a pointer to a buffer. We'll create a submission queue entry (sqe) using this buffer and put it on the sqe ring buffer.
// However, then we return to the caller which re-uses this buffer. If we didn't copy the buffer into another data structure, we'd lose data.
// Get a chunk of memory to copy packets into, this will function as a ring buffer similar to the SQE/CQE ring buffers.
struct data_and_metadata
{
    char buf[MAX_PACKET_SIZE];
    struct msghdr msg;
    struct iovec iov;
};
__thread struct data_and_metadata* data_arr;
__thread uint16_t data_arr_index;

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

	// initialize io_uring
	int ret = io_uring_queue_init(QUEUE_DEPTH, &ring, 0);
	if (ret < 0) {
		// TODO Phillip handle error
		fprintf(stderr, "Error initializing io_uring: %s\n", strerror(-ret));
	}
        data_arr = calloc(QUEUE_DEPTH, sizeof(struct data_and_metadata));
	// points to an open buffer in buf_array
	data_arr_index = 0;




	return EXIT_SUCCESS;
}

int send_packet(sock_t sock, void *buf, int len, UNUSED uint32_t idx)
{
	// get next data entry in ring buffer
	struct data_and_metadata d = data_arr[data_arr_index];
	// copy buf into data_arr so caller can re-use the buf pointer after we return
	memcpy(d.buf, buf, len);
	// setup msg/iov structs for sendmsg
	struct iovec *iov = &d.iov;
	iov->iov_base = d.buf;
	iov->iov_len = len;
	struct msghdr *msg = &d.msg;
	// based on https://github.com/torvalds/linux/blob/master/net/socket.c#L2180
	msg->msg_name = (struct sockaddr *)&sockaddr;
	msg->msg_namelen = sizeof(struct sockaddr_ll);
	msg->msg_iov = iov;
	msg->msg_iovlen = 1;

	// Initialize the SQE for sending a packet
	struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
	if (!sqe) {
		fprintf(stderr, "Error getting submission queue entry\n");
		// Handle error
	}
	// add msg to sqe
	io_uring_prep_sendmsg(sqe, sock.sock, msg, 0);

	// notify kernel we have sqes ready for processing (this is a syscall)
	int ret = io_uring_submit(&ring);
	if (ret < 0) {
		fprintf(stderr, "Error submitting operation: %s\n", strerror(-ret));
		// Handle error
	}
	struct io_uring_cqe* cqe;
	ret = io_uring_wait_cqe(&ring, &cqe);
	if (ret < 0) {
		fprintf(stderr, "Error waiting for completion: %s\n", strerror(errno));
		// Handle error
	}

	// Process completion
	if (cqe->res < 0) {
		fprintf(stderr, "Error in completion: %s\n", strerror(cqe->res));
		// Handle error
	}

	io_uring_cqe_seen(&ring, cqe);

	// increment arr ptr index
	data_arr_index = (data_arr_index + 1) % QUEUE_DEPTH;
}

int send_run_cleanup(void) {
	log_warn("send", "send run cleanuped!");
	io_uring_queue_exit(&ring);
	return 0;
}

#endif /* ZMAP_SEND_LINUX_H */
