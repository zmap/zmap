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
#define QUEUE_DEPTH 128 // ring buffer size for liburing's submission queue
#define SQ_POLLING_IDLE_TIMEOUT 1000 // how long kernel thread will wait before timing out
// io_uring is an async I/O package. In send_packet, the caller passes in a pointer to a buffer. We'll create a submission queue entry (sqe) using this buffer and put it on the sqe ring buffer.
// However, then we then immediately return to the caller which re-uses this buffer.
// We need to create a data-structure to persist this data so it can be sent async and the caller can reuse the buffer
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

int clear_cqe_ring(void);
void print_debug_ring_features(void);

int send_run_init(sock_t s, uint32_t kernel_cpu)
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
	struct io_uring_params params;
	memset(&params, 0, sizeof(params));
	// using the submission queue polling feature to avoid syscall overhead incurred by submitting SQE's to the kernel
	// details available here: https://unixism.net/loti/tutorial/sq_poll.html#sq-poll
	params.flags |= IORING_SETUP_SQPOLL;
	// If no sqe's were submitted for SQ_POLLING_IDLE_TIMEOUT, the kernel thread would be killed and need to be restarted.
	// This wouldn't be expected to happen since ZMap is constantly sending packets, but is best practice to define.
	params.sq_thread_idle = SQ_POLLING_IDLE_TIMEOUT;
        log_debug("send_init", "Pinning a kernel polling thread for send events to core %u", kernel_cpu);
	// assign the kernel thread to a given core
	params.flags |= IORING_SETUP_SQ_AFF;
	params.sq_thread_cpu = kernel_cpu;
	// optimization hint to kernel that no other thread will submit using this ring
	params.flags |= IORING_SETUP_SINGLE_ISSUER;
	int ret = io_uring_queue_init_params(QUEUE_DEPTH, &ring, &params);
	if (ret < 0) {
		log_fatal("send_init", "Error initializing io_uring: %s", strerror(-ret));
	}

	// Since io_uring is asynchronous, need to be sure the packet data is valid after submission to ring.
	// Allocating an array to store these packets with the same length as the sqe ring buffer
        data_arr = calloc(QUEUE_DEPTH, sizeof(struct data_and_metadata));
    	print_debug_ring_features();
	return EXIT_SUCCESS;
}

int send_packet(sock_t sock, void *buf, int len, UNUSED uint32_t idx)
{
	// get next data entry in data ring buffer
	struct data_and_metadata* d = &data_arr[free_buffer_ptr];
	// copy buf into data_arr so caller can re-use the buf pointer after we return
	memcpy(d->buf, buf, len);
	// setup msg/iov structs for sendmsg
	struct iovec *iov = &d->iov;
	iov->iov_base = d->buf;
	iov->iov_len = len;
	struct msghdr *msg = &d->msg;
	msg->msg_name = (struct sockaddr *)&sockaddr;
	msg->msg_namelen = sizeof(struct sockaddr_ll);
	msg->msg_iov = iov;
	msg->msg_iovlen = 1;

	// initialize the SQE for sending a packet
	struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
	int has_cleared = 0;
	while(!sqe) {
		// submission queue is full, we need to block to let the kernel send traffic and cull some CQE's
		// since we submit with IOSQE_CQE_SKIP_SUCCESS, the only completion events expected are for errors.
		clear_cqe_ring();
		// wait for space in ring buffer to open up
		io_uring_sqring_wait(&ring);
		// reattempt to get a new sqe
		sqe = io_uring_get_sqe(&ring);
	}
        // Optimization: ZMap doesn't do anything when a packet is sent successfully
        // We'll log any errors but if a packet is successfully sent, tell io_uring
        // it doesn't need to notify us.
	sqe->flags |= IOSQE_CQE_SKIP_SUCCESS;
	io_uring_prep_sendmsg(sqe, sock.sock, msg, 0);
        io_uring_submit(&ring);
	// increment arr ptr index to next data for next send_packet
	free_buffer_ptr = (free_buffer_ptr + 1) % QUEUE_DEPTH;
}

int send_run_cleanup(void) {
	// wait for submission q to empty
	while (io_uring_sq_ready(&ring) != 0) {
		sleep(1);
	}
	// check for any send errors
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

// print_ring_features prints out what features the current version of io_uring has
// this is dependent on the linux kernel that is being used, and is helpful for debugging
void print_debug_ring_features() {
	if (ring.features & IORING_FEAT_CQE_SKIP) {
		log_debug("send_init", "io_uring supports CQE_SKIP");
	} else {
		log_debug("send_init", "io_uring does NOT support CQE_SKIP");
	}
	if (ring.features & IORING_FEAT_SUBMIT_STABLE) {
		log_debug("send_init", "io_uring supports Submit Stable");
	} else {
		log_debug("send_init", "io_uring does NOT support Submit Stable");
	}
	if (ring.features & IORING_FEAT_NODROP) {
		log_debug("send_init", "io_uring supports No Drop");
	} else {
		log_debug("send_init", "io_uring does NOT support No Drop");
	}
}


#endif /* ZMAP_SEND_LINUX_H */
