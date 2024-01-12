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
#include <sys/syscall.h>
#include <unistd.h>

#include "../lib/includes.h"


#ifdef ZMAP_SEND_BSD_H
#error "Don't include both send-bsd.h and send-linux.h"
#endif

// TODO Phillip you'll need to figure out how to compile both the below and for earlier linux versions w/o iouring

// Dummy sockaddr for sendto
static struct sockaddr_ll sockaddr;

// io_uring/liburing resources
// Great high-level introduction - https://www.scylladb.com/2020/05/05/how-io_uring-and-ebpf-will-revolutionize-programming-in-linux/
// Blog with good explanations and examples, it is 2 years old tho and some things have changed with liburing - https://unixism.net/loti/
// Consult the manpages for io_uring... (man -k io_uring). This has the most up-to-date info for the version of liburing that ships with your distro
// Note: Liburing is under active development, and new features have been added and documentation has changed. Something to keep in mind when you look at examples, both newer/older.
// Ubuntu 23.04 ships with liburing v2.3 - https://packages.ubuntu.com/lunar/liburing-dev , v.2.5 is the latest - https://github.com/axboe/liburing

// Each thread will send packets using its own liburing variables to avoid needing locks/increasing contention
__thread struct io_uring ring;
#define QUEUE_DEPTH 2048 // ring buffer size for liburing's submission queue
#define SQ_POLLING_IDLE_TIMEOUT 15000 // how long kernel thread will wait before timing out
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
// points to an open buffer in buf_array
__thread uint16_t free_buffer_ptr = 0;
__thread struct io_uring_cqe* cqe;
__thread int fds[1]; // socket file descriptor
__thread int cqe_waits = 0;
// packets_sent tracks how many packets have been sent over the whole scan, for debugging
__thread uint packets_sent = 0;
// to_submit is the sqe's that have been queued but not culled from the cqe ring
__thread uint to_submit = 0;
int clear_cqe_ring(void);

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

	// initialize io_uring and relevant datastructures
	// Using the submission queue polling feature to avoid syscall overhead incurred by submitting SQE's to the kernel
	// Details available here: https://unixism.net/loti/tutorial/sq_poll.html#sq-poll

	struct io_uring_params params;
	memset(&params, 0, sizeof(params));
	params.flags |= IORING_SETUP_SQPOLL;
	// adding these seems to kill multi-threaded performance, but at expense of hitrate????
//	params.flags |= IORING_FEAT_NODROP;
//	params.flags |= IORING_FEAT_SUBMIT_STABLE;
	params.sq_thread_idle = SQ_POLLING_IDLE_TIMEOUT;
//	params.flags |= IORING_SETUP_SQ_AFF;
//	params.sq_thread_cpu = 9;
	// register socket
	fds[0] = sock;
	int ret = io_uring_queue_init_params(QUEUE_DEPTH, &ring, &params);
	if (ret < 0) {
		// TODO Phillip handle error
		fprintf(stderr, "Error initializing io_uring: %s\n", strerror(-ret));
	}
	ret = io_uring_register_files(&ring, fds, 1);
	if (ret < 0) {
		// TODO Phillip handle error
		log_fatal("send_init", "Error registering file descriptor: %s/%d", strerror(-ret), ret);
	}

	// Once the SQE's are submitted, the memory can be re-used according to the docs for liburing
	// TODO Phillip trying to get polling working
        data_arr = calloc(QUEUE_DEPTH, sizeof(struct data_and_metadata));
	log_warn("io_uring_setup", "size of sqe = %d, size of cqe=%d", params.sq_entries, params.cq_entries);
	return EXIT_SUCCESS;
}

int send_packet(sock_t sock, void *buf, int len, UNUSED uint32_t idx)
{
	// get next data entry in ring buffer
	struct data_and_metadata* d = &data_arr[free_buffer_ptr];
	// copy buf into data_arr so caller can re-use the buf pointer after we return
	memcpy(d->buf, buf, len);
	// setup msg/iov structs for sendmsg
	struct iovec *iov = &d->iov;
	iov->iov_base = d->buf;
	iov->iov_len = len;
	struct msghdr *msg = &d->msg;
	// based on https://github.com/torvalds/linux/blob/master/net/socket.c#L2180
	msg->msg_name = (struct sockaddr *)&sockaddr;
	msg->msg_namelen = sizeof(struct sockaddr_ll);
	msg->msg_iov = iov;
	msg->msg_iovlen = 1;


	// Initialize the SQE for sending a packet
	struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
	int has_cleared = 0;
	while(!sqe) {
		// submission queue is full, we need to block to let the kernel send traffic and cull some CQE's
                if (has_cleared > 0) {
			// for debugging our performance issues. if we enter this loop multiple times, we'll note it
			cqe_waits++;
                }
		has_cleared++;
		// clear any available cqe's from the ring
		int cqes_cleared = clear_cqe_ring();
		to_submit -= cqes_cleared;
		// reattempt to get a new sqe
		sqe = io_uring_get_sqe(&ring);
		if (!sqe) {
			// sqe unavailable, kernel needs more time to send packets
			usleep(1000);
		}

	}
	// since we registered the file descriptor, we can just use the index.
	// There's only one fd, so index = 0
	io_uring_prep_sendmsg(sqe, 0, msg, 0);
	sqe->flags |= IOSQE_FIXED_FILE;
	io_uring_submit(&ring);
	// sqe ready to send, increment arr ptr index to next data
	free_buffer_ptr = (free_buffer_ptr + 1) % QUEUE_DEPTH;
	packets_sent++;
	to_submit++;
}

int send_run_cleanup(void) {
	// wait for submission q to empty
	while (io_uring_sq_ready(&ring) != 0) {
		// might be a better way than busy-waiting
		sleep(1);
	}

	clear_cqe_ring();
	// free up data structures
	free(data_arr);
	io_uring_queue_exit(&ring);
	return 0;
}

int clear_cqe_ring(void) {
	unsigned head;
	int i = 0;

	io_uring_for_each_cqe(&ring, head, cqe) {
		/* handle completion */
		if (cqe->res < 0) {
			log_fatal("send", "send_run_cleanup: cqe %d failed: %s", i, strerror(errno));
		}
		i++;
	}
	io_uring_cq_advance(&ring, i);
	return i;
}

#endif /* ZMAP_SEND_LINUX_H */
