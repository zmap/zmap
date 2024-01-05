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

int io_uring_enter(int ring_fd, unsigned int to_submit,
		   unsigned int min_complete, unsigned int flags)
{
	return (int) syscall(__NR_io_uring_enter, ring_fd, to_submit, min_complete,
			    flags, NULL, 0);
}

// Each thread will send packets using its own liburing variables to avoid needing locks/increasing contention
// io_uring instance for each thread
__thread struct io_uring ring;
#define QUEUE_DEPTH 10000 // how deep the liburing's should be
#define CULL_DEPTH 512 // how many CQE's to cull (blocking) if the SQE buffer fills up
#define LIBRING_SUBMIT_FREQ 1 // after how many sqe's being prepped should we make a submit syscall
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
__thread uint16_t msgs_added_to_queue = 0;
__thread struct io_uring_cqe* cqe;
__thread int fds[1]; // socket file descriptor
// packets_sent tracks how many packets have been sent over the whole scan, for debugging
uint packets_sent = 0;
// to_submit is the sqe's that have been queued but not culled from the cqe ring
uint to_submit = 0;
int clear_cqe_ring(void);

void print_sq_poll_kernel_thread_status(void) {

	if (system("ps --ppid 2 | grep io_uring-sq" ) == 0)
		printf("Kernel thread io_uring-sq found running...\n");
	else
		printf("Kernel thread io_uring-sq is not running.\n");
}

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
	if (geteuid()) {
		log_fatal("send", "You need root privileges to run this program");
	}

	struct io_uring_params params;
	memset(&params, 0, sizeof(params));
	params.flags |= IORING_SETUP_SQPOLL;
	params.sq_thread_idle = SQ_POLLING_IDLE_TIMEOUT;
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
	while(!sqe) {
		// submission queue is full, we need to block to let the kernel send traffic and cull some CQE's
//		int ret = io_uring_enter(ring.ring_fd, to_submit, CULL_DEPTH, IORING_ENTER_GETEVENTS);
//		if (ret < 0) {
//			log_fatal("send cleanup", "send_run_cleanup: io_uring enter failed: %s", strerror(errno));
//		}
		int cqes_cleared = clear_cqe_ring();
		to_submit -= cqes_cleared;
		sqe = io_uring_get_sqe(&ring);
	}
	// add msg to sqe
	// since we registered the file descriptor, we can just use the index.
	// There's only one fd, so index = 0
//	sqe->flags = IOSQE_FIXED_FILE;
	io_uring_prep_sendmsg(sqe, 0, msg, 0);
	sqe->flags |= IOSQE_FIXED_FILE;

	io_uring_submit(&ring);
//	io_uring_prep_write(sqe, 0, d->buf, len, 0);
//	sqe->flags |= IOSQE_FIXED_FILE;

	// sqe ready to send, increment arr ptr index to next data
	free_buffer_ptr = (free_buffer_ptr + 1) % QUEUE_DEPTH;
	msgs_added_to_queue++;
	packets_sent++;
	to_submit++;

	// io_uring_submit and its different flavors are syscalls. We'll call this every batch to amortize the syscall cost
////	if (msgs_sent_since_last_submit % LIBRING_SUBMIT_FREQ == 0) {
//		int ret = io_uring_submit(&ring);
//		if (ret < 0) {
//			fprintf(stderr, "Error submitting operation: %s\n",
//				strerror(-ret));
//			// Handle error
//		}
////		msgs_sent_since_last_submit = 0;
////	}
//
//
//	if (msgs_added_to_queue < QUEUE_DEPTH) {
//		// still have room on the queue, no need to wait for cqe's
//		return 0;
//	}
//	// sqe ring is full, let's check how many cqe's can be culled
//	uint num_cqes_avail = io_uring_cq_ready(&ring);
//	uint cqes_removed = wait_for_cqes(num_cqes_avail);
//	// TODO Phillip, this might not be necessary if we decide to go with the polling approach since we cull above
//	// TODO Phillip remove
////	log_warn("send", "able to purge %d entries", cqes_removed);
//	// decrement counter
//	msgs_added_to_queue -= cqes_removed;
}

int send_run_cleanup(void) {
	// notify kernel of unsubmitted sqe's
//        int ret = io_uring_submit(&ring);
	int ret = io_uring_enter(ring.ring_fd, to_submit, to_submit, IORING_ENTER_GETEVENTS);
	if (ret < 0) {
		log_fatal("send cleanup", "send_run_cleanup: io_uring enter failed: %s", strerror(errno));
	}

	log_warn("send-cleanup", "%d cqe's ready to be removed, out of %d submitted", io_uring_cq_ready(&ring), msgs_added_to_queue);
//	wait_for_cqes(msgs_added_to_queue);
	clear_cqe_ring();
	log_warn("send cleanup", "%d cqe's ready to be removed, out of %d submitted", io_uring_cq_ready(&ring), msgs_added_to_queue);
	log_warn("send cleanup", "send run cleanuped!");
	// free up data structures
	free(data_arr);
	io_uring_queue_exit(&ring);
	return 0;
}

//int wait_for_cqes(uint num_cqe) {
//	int num_successful = 0;
//	// check all completed cqe's for their status
//	for (uint i = 0; i < num_cqe; i++) {
//		// wait for all remaining cqe's to complete
//		int ret = io_uring_wait_cqe(&ring, &cqe);
//		if (ret < 0) {
//			log_fatal("send cleanup", "send_run_cleanup: io_uring wait failed: %s", strerror(errno));
//		}
//		if (!cqe) {
//			// cqe is empty, warn user and continue
//			log_warn("send cleanup", "%d of %d cqe's was null", i, num_cqe);
//			continue;
//		}
//		if (cqe->res < 0) {
//			log_fatal("send", "send_run_cleanup: cqe %d failed: %s", i, strerror(errno));
//			// TODO Phillip, you'll probably want to figure out how to handle retries :(
//		}
//		// notify kernel that we've seen this cqe
//		io_uring_cqe_seen(&ring, cqe);
//		num_successful++;
//	}
//	return num_successful;
//}

int clear_cqe_ring() {
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
