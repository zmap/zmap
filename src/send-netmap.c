/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#if !(defined(__FreeBSD__) || defined(__linux__))
#error "NETMAP requires FreeBSD or Linux"
#endif

#include "send.h"

#include <net/netmap_user.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <inttypes.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>

#include "../lib/includes.h"
#include "../lib/logger.h"
#include "../lib/queue.h"

#include "socket.h"
#include "state.h"

static pthread_once_t submit_queue_inited = PTHREAD_ONCE_INIT;
static zqueue_t *submit_queue;

static void
submit_queue_init_once(void)
{
	submit_queue = queue_init();
	assert(submit_queue);
}

int send_run_init(sock_t sock)
{
	if (sock.nm.tx_ring_idx == 0) {
		pthread_once(&submit_queue_inited, submit_queue_init_once);
	}

	struct pollfd fds = {
	    .fd = sock.nm.tx_ring_fd,
	    .events = POLLOUT,
	};
	log_debug("send-netmap", "tx ring %" PRIu32 ": polling for POLLOUT", sock.nm.tx_ring_idx);
	if (poll(&fds, 1, -1) == -1) {
		log_error("send-netmap", "poll(POLLOUT) failed: %d: %s", errno, strerror(errno));
		return -1;
	}
	return 0;
}

// Called from the recv thread to submit a batch of packets
// for sending on thread 0; typically batch size is just 1.
// Used for responding to ARP requests.
// The way this works is rather inefficient and only makes
// sense for low volume packets.
// Since we don't know if send_run_init() has been called
// yet or not, we need to ensure the queue is initialized.
void submit_batch_internal(batch_t *batch)
{
	pthread_once(&submit_queue_inited, submit_queue_init_once);
	push_back((void *)batch, submit_queue);
}

int send_batch_internal(sock_t sock, batch_t *batch)
{
	struct netmap_ring *ring = NETMAP_TXRING(zconf.nm.nm_if, sock.nm.tx_ring_idx);
	struct pollfd fds = {
	    .fd = sock.nm.tx_ring_fd,
	    .events = POLLOUT,
	};

	for (int i = 0; i < batch->len; i++) {
		if (ring->head == ring->tail && poll(&fds, 1, -1) == -1) {
			int oerrno = errno;
			log_debug("send-netmap", "poll(POLLOUT) failed: %d: %s", errno, strerror(errno));
			errno = oerrno;
			return -1;
		}

		uint32_t len = batch->packets[i].len;
		assert(len <= ring->nr_buf_size);
		memcpy(NETMAP_BUF(ring, ring->slot[ring->cur].buf_idx), batch->packets[i].buf, len);
		ring->slot[ring->cur].len = len;
		ring->head = ring->cur = nm_ring_next(ring, ring->cur);
	}

	if (ioctl(fds.fd, NIOCTXSYNC, NULL) == -1) {
		int oerrno = errno;
		log_debug("send-netmap", "ioctl(NIOCTXSYNC) failed: %d: %s", errno, strerror(errno));
		errno = oerrno;
		return -1;
	}

	return batch->len;
}

// Netmap's send_batch does not use attempts, because retries do
// not make sense based on the premise that syncing a TX ring will
// never fail for transient reasons.
//
// Netmap's send_batch never reports batches as partially failed,
// because the netmap API does not have partial failure semantics.
// All we know is that a poll or ioctl syscall failed, not if or
// how many of the packets we placed in the ringbuffer were sent.
//
// There is a bit of unused optimization potential here; ZMap's
// current architecture requires us to copy packet data on the
// send path, we cannot supply netmap buffers to ZMap to write
// into directly.  And even though netmap would allow us to reuse
// data still in buffers (unless NS_BUF_CHANGED has been set by
// the kernel), we cannot take advantage of that currently.
int send_batch(sock_t sock, batch_t *batch, UNUSED int attempts)
{
	// On send thread 0, send any batches that have been
	// submitted onto the submit_queue before sending the
	// actual batch.  There should only be packets in the
	// submit_queue very infrequently.
	if (sock.nm.tx_ring_idx == 0) {
		while (!is_empty(submit_queue)) {
			znode_t *node = pop_front(submit_queue);
			batch_t *extra_batch = (batch_t *)node->data;
			assert(extra_batch->len > 0);
			free(node);
			if (send_batch_internal(sock, extra_batch) != extra_batch->len) {
				log_error("send-netmap", "Failed to send extra batch of %u submitted packet(s)", extra_batch->len);
			} else {
				log_debug("send-netmap", "Sent extra batch of %u submitted packet(s)", extra_batch->len);
			}
			free_packet_batch(extra_batch);
		}
	}

	if (batch->len == 0) {
		return 0;
	}

	return send_batch_internal(sock, batch);
}
