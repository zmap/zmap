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

#include "../lib/includes.h"
#include "../lib/logger.h"

#include "socket.h"
#include "state.h"

int
send_run_init(sock_t sock)
{
	struct pollfd fds = {
		.fd = sock.nm.tx_ring_fd,
		.events = POLLOUT,
	};
	log_debug("send-netmap", "tx ring %"PRIu32": polling for POLLOUT", sock.nm.tx_ring_idx);
	if (poll(&fds, 1, -1) == -1) {
		log_error("send-netmap", "poll(POLLOUT) failed: %d: %s", errno, strerror(errno));
		return -1;
	}
	return 0;
}

// This implementation does not use attempts, because retries do not
// make sense based on the premise that syncing a TX ring will never
// fail for transient reasons.
//
// This implementation never reports batches as partially failed,
// because the netmap API does not have partial failure semantics.
// All we know is that a poll or ioctl syscall failed, not if or
// how many of the packets we placed in the ringbuffer were sent.
//
// ZMap's current architecture forces us to copy packet data here.
// An even more optimised implementation might reuse packet data
// in buffers (unless NS_BUF_CHANGED has been set by the kernel on
// a slot), and only update the fields that need to change, such
// as dst IP, checksum etc depending on scan type and params.
int
send_batch(sock_t sock, batch_t *batch, UNUSED int attempts)
{
	if (batch->len == 0) {
		return 0;
	}

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

		void *src_buf = (void *)((uint8_t *)batch->packets + i * MAX_PACKET_SIZE);
		int len = batch->lens[i];
		assert((uint32_t)len <= ring->nr_buf_size);

		void *dst_buf = NETMAP_BUF(ring, ring->slot[ring->cur].buf_idx);
		memcpy(dst_buf, src_buf, len);
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
