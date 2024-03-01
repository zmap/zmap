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

#include "recv.h"
#include "recv-internal.h"
#include "socket.h"
#include "send.h"
#include "send-internal.h"
#include "probe_modules/packet.h"
#include "if-netmap.h"
#include "state.h"

#include "../lib/includes.h"
#include "../lib/logger.h"

#include <net/netmap_user.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <poll.h>
#include <stdbool.h>
#include <assert.h>
#include <inttypes.h>

static struct pollfd fds;
static struct netmap_if *nm_if;
static bool *in_multi_seg_packet;
static void (*handle_packet_func)(uint32_t buflen, const uint8_t *bytes, const struct timespec ts);
static if_stats_ctx_t *stats_ctx;
static bool need_recv_counter;
static uint64_t recv_counter;

static void
handle_packet_wait_ping(uint32_t buflen, const uint8_t *bytes, UNUSED const struct timespec ts)
{
	if (buflen < sizeof(struct ether_header) + sizeof(struct ip) + ICMP_MINLEN) {
		return;
	}
	struct ether_header *eh = (struct ether_header *)bytes;
	if (eh->ether_type != htons(ETHERTYPE_IP)) {
		return;
	}
	struct ip *iph = (struct ip *)(eh + 1);
	if (iph->ip_v != 4 ||
	    iph->ip_p != IPPROTO_ICMP ||
	    iph->ip_src.s_addr != zconf.nm.wait_ping_dstip) {
		return;
	}
	struct icmp *icmph = (struct icmp *)(iph + 1);
	if (icmph->icmp_type != ICMP_ECHOREPLY) {
		return;
	}

	log_debug("recv-netmap", "Received ICMP echo reply, ready to commence scan");
	handle_packet_func = handle_packet;
}

static size_t
make_wait_ping_req(uint8_t *buf)
{
	struct ether_header *eh = (struct ether_header *)buf;
	make_eth_header(eh, zconf.hw_mac, zconf.gw_mac);

	struct ip *iph = (struct ip *)(eh + 1);
	uint16_t iplen = sizeof(struct ip) + ICMP_MINLEN;
	make_ip_header(iph, IPPROTO_ICMP, htons(iplen));
	iph->ip_src.s_addr = zconf.source_ip_addresses[0];
	iph->ip_dst.s_addr = zconf.nm.wait_ping_dstip;

	struct icmp *icmph = (struct icmp *)(iph + 1);
	memset(icmph, 0, sizeof(struct icmp));
	icmph->icmp_type = ICMP_ECHO;
	icmph->icmp_cksum = icmp_checksum((unsigned short *)icmph, ICMP_MINLEN);

	iph->ip_sum = 0;
	iph->ip_sum = zmap_ip_checksum((unsigned short *)iph);
	return sizeof(struct ether_header) + iplen;
}

static void
send_wait_ping_req(sock_t sock)
{
	batch_t *batch = create_packet_batch(1);
	batch->lens[0] = (int)make_wait_ping_req((uint8_t *)batch->packets);
	batch->ips[0] = zconf.nm.wait_ping_dstip;
	batch->len = 1;
	if (send_batch(sock, batch, 1) != 1) {
		log_fatal("recv-netmap", "Failed to send ICMP echo request: %d: %s", errno, strerror(errno));
	}
	free_packet_batch(batch);
	log_debug("recv-netmap", "Sent ICMP echo request");
}

#ifndef NSEC_PER_SEC
#define NSEC_PER_SEC 1000000000
#endif

static struct timespec
timespec_diff(struct timespec const *t1, struct timespec const *t0)
{
	struct timespec diff = {
		.tv_sec = t1->tv_sec - t0->tv_sec,
		.tv_nsec = t1->tv_nsec - t0->tv_nsec,
	};
	if (diff.tv_nsec < 0) {
		diff.tv_sec--;
		diff.tv_nsec += NSEC_PER_SEC;
	}
	return diff;
}

static void
timespec_get_monotonic(struct timespec *t)
{
	if (clock_gettime(CLOCK_MONOTONIC, t) == -1) {
		log_fatal("recv-netmap", "Failed to obtain monotonic time: %d: %s", errno, strerror(errno));
	}
}

// Drive RX and TX ringbuffers directly to wait for end-to-end connectivity.
// Ping an IP address every second and do not return before receiving a reply.
static void
wait_for_e2e_connectivity(void)
{
	static const time_t timeout_secs = 60;

	// Synthesize a sock_t for the main netmap fd.
	// This is safe as long as send threads are not spun up yet.
	// We're syncing all TX rings this way, not just ring 0.
	sock_t sock;
	sock.nm.tx_ring_idx = 0;
	sock.nm.tx_ring_fd = zconf.nm.nm_fd;

	struct timespec t_start;
	timespec_get_monotonic(&t_start);
	struct timespec t_last_send;
	memset(&t_last_send, 0, sizeof(t_last_send));

	// handle_packet_wait_ping called from recv_packets will
	// set handle_packet_func to handle_packet upon receipt
	// of the expected ICMP echo response packet.
	while (handle_packet_func == handle_packet_wait_ping) {
		struct timespec t_now;
		timespec_get_monotonic(&t_now);

		if (timespec_diff(&t_now, &t_start).tv_sec >= timeout_secs) {
			log_fatal("recv-netmap", "No ICMP echo reply received in %zus", (size_t)timeout_secs);
		}

		if (timespec_diff(&t_now, &t_last_send).tv_sec >= 1) {
			send_wait_ping_req(sock);
			timespec_get_monotonic(&t_last_send);
		}

		recv_packets();
	}
}

void recv_init(void)
{
	fds.fd = zconf.nm.nm_fd;
	fds.events = POLLIN;

	nm_if = zconf.nm.nm_if;

	in_multi_seg_packet = (bool *)malloc(nm_if->ni_rx_rings * sizeof(bool));
	assert(in_multi_seg_packet);
	for (size_t ri = 0; ri < nm_if->ni_rx_rings; ri++) {
		in_multi_seg_packet[ri] = false;
	}

	zconf.data_link_size = if_get_data_link_size(zconf.iface, zconf.nm.nm_fd);
	log_debug("recv-netmap", "data_link_size %d", zconf.data_link_size);

	if (zconf.nm.wait_ping_dstip != 0) {
		handle_packet_func = handle_packet_wait_ping;
		wait_for_e2e_connectivity();
	} else {
		handle_packet_func = handle_packet;
	}

	stats_ctx = if_stats_init(zconf.iface, zconf.nm.nm_fd);
	assert(stats_ctx);
	need_recv_counter = !if_stats_have_recv_ctr(stats_ctx);
	if (need_recv_counter) {
		recv_counter = 0;
	}
}

void
recv_cleanup(void)
{
	if_stats_fini(stats_ctx);
	stats_ctx = NULL;
	free(in_multi_seg_packet);
	in_multi_seg_packet = NULL;
	nm_if = NULL;
}

void
recv_packets(void)
{
	// On Linux, EINTR seems to happen here once at startup.
	// Haven't seen any EINTR on FreeBSD.  Retry is not wrong
	// and making the total delay longer should not hurt.
	// We may want to look into the root cause some time tho.
	for (ssize_t retry = 5; retry >= 0; retry--) {
		int ret = poll(&fds, 1, 100 /* ms */);
		if (ret > 0) {
			break;
		} else if (ret == 0) {
			return;
		} else if (errno != EINTR || retry == 0) {
			log_error("recv-netmap", "poll(POLLIN) failed: %d: %s", errno, strerror(errno));
			return;
		} else {
			log_debug("recv-netmap", "poll(POLLIN) failed: %d: %s (retrying)", errno, strerror(errno));
		}
	}

	for (unsigned int ri = 0; ri < nm_if->ni_rx_rings; ri++) {
		struct netmap_ring *rxring = NETMAP_RXRING(nm_if, ri);
		unsigned head = rxring->head;
		unsigned tail = rxring->tail;
		for (; head != tail; head = nm_ring_next(rxring, head)) {
			struct netmap_slot *slot = rxring->slot + head;

			// Some NICs can produce multi-segment packets,
			// e.g. ixgbe and i40e on Linux.
			// A multi-segment packet is a single received
			// frame split into multiple netmap buffers;
			// "segment" here refers neither to TCP
			// segmentation, nor IP fragmentation.
			//
			// In the absence of ZMap support for handling
			// vectored packets, to avoid the overhead of
			// reassembly into contiguous memory, and based
			// on the premise that ZMap scans won't need to
			// see full packet data for packets larger than
			// txring->nr_buf_size, pass the first segment
			// to the handler and skip the rest.
			//
			// We cannot depend on multi-segment packets
			// all fitting into a ring in one sync, thus
			// have to keep track of state across calls to
			// recv_packets().
			if ((slot->flags & NS_MOREFRAG) != 0) {
				if (in_multi_seg_packet[ri]) {
					// Middle segment.
					continue;
				} else {
					// Head segment.
					in_multi_seg_packet[ri] = true;
				}
			} else if (in_multi_seg_packet[ri]) {
				// Tail segment.
				in_multi_seg_packet[ri] = false;
				continue;
			}

			char *buf = NETMAP_BUF(rxring, slot->buf_idx);
			struct timespec ts;
			ts.tv_sec = rxring->ts.tv_sec;
			ts.tv_nsec = rxring->ts.tv_usec * 1000;
			if (need_recv_counter) {
				recv_counter++;
			}
			handle_packet_func(slot->len, (uint8_t *)buf, ts);
		}
		rxring->cur = rxring->head = head;
	}

#if 0
	// We can get by without this sync because we are getting
	// called again in a tight loop and poll() will sync then,
	// saving us a kernel round trip.
	// When we are done and the outer loop is broken, then we
	// do not care about dropped packets anymore anyway, as we
	// will be about to terminate.
	// Leaving this here for future debugging.
	if (ioctl(fds.fd, NIOCRXSYNC, NULL) == -1) {
		log_error("recv-netmap", "ioctl(NIOCRXSYNC) failed: %d: %s", errno, strerror(errno));
	}
#endif
}

int recv_update_stats(void)
{
	if (!stats_ctx) {
		return EXIT_FAILURE;
	}

	if (if_stats_get(stats_ctx, &zrecv.pcap_recv, &zrecv.pcap_drop, &zrecv.pcap_ifdrop) == -1) {
		return EXIT_FAILURE;
	}
	if (need_recv_counter) {
		zrecv.pcap_recv = (uint32_t)recv_counter;
	}
	return EXIT_SUCCESS;
}
