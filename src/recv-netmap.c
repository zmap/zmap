/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef __FreeBSD__
#error "NETMAP is only currently supported on FreeBSD"
#endif

#include "recv.h"
#include "recv-internal.h"

#include "../lib/includes.h"
#include "../lib/logger.h"

#include <net/netmap_user.h>
#include <net/if_types.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <poll.h>
#include <stdbool.h>
#include <assert.h>
#include <inttypes.h>

#include "state.h"

static void
fetch_if_data(struct if_data *ifd)
{
	struct ifreq ifr;
	bzero(&ifr, sizeof(ifr));
	strlcpy(ifr.ifr_name, zconf.iface, sizeof(ifr.ifr_name));
	ifr.ifr_data = (caddr_t)ifd;
	if (ioctl(zconf.nm.nm_fd, SIOCGIFDATA, &ifr) == -1) {
		log_fatal("recv-netmap", "unable to retrieve if_data: %d %s",
			  errno, strerror(errno));
	}
}

static size_t
data_link_size_from_if_type(unsigned char if_type)
{
	switch (if_type) {
	case IFT_ETHER:
		log_debug("recv-netmap", "IFT_ETHER");
		return sizeof(struct ether_header);
	case IFT_LOOP:
		log_debug("recv-netmap", "IFT_LOOP");
		return 4;
	default:
		log_fatal("recv-netmap", "Unknown if_type: %u", if_type);
	}
}

static size_t
fetch_data_link_size(void)
{
	struct if_data ifd;
	bzero(&ifd, sizeof(ifd));
	fetch_if_data(&ifd);
	return data_link_size_from_if_type(ifd.ifi_type);
}

static struct {
	bool initialized;
	bool hwstats;
	uint64_t ifi_ipackets;
	uint64_t ifi_iqdrops;
	uint64_t ifi_ierrors;
	uint64_t ifi_oerrors;
} stats;

static int
fetch_stats(uint32_t *ps_recv, uint32_t *ps_drop, uint32_t *ps_ifdrop)
{
	// Notes on if counters:
	// On interfaces without hardware counters (HWSTATS), ipackets misses
	// packets that we do not forward to the host ring pair.
	// oqdrops counts packets the host OS could not send due to netmap mode.
	struct if_data ifd;
	bzero(&ifd, sizeof(ifd));
	fetch_if_data(&ifd);

	if (!stats.initialized) {
		assert(!ps_recv && !ps_drop && !ps_ifdrop);
		stats.initialized = true;
		stats.hwstats = (ifd.ifi_hwassist & IFCAP_HWSTATS) != 0;
		if (stats.hwstats) {
			stats.ifi_ipackets = ifd.ifi_ipackets;
		} else {
			stats.ifi_ipackets = 0;
		}
		stats.ifi_iqdrops = ifd.ifi_iqdrops;
		stats.ifi_ierrors = ifd.ifi_ierrors;
		stats.ifi_oerrors = ifd.ifi_oerrors;
	} else {
		if (stats.hwstats) {
			*ps_recv = (uint32_t)(ifd.ifi_ipackets - stats.ifi_ipackets);
		} else {
			*ps_recv = (uint32_t)stats.ifi_ipackets;
		}
		*ps_drop = (uint32_t)(ifd.ifi_iqdrops - stats.ifi_iqdrops);
		*ps_ifdrop = (uint32_t)(ifd.ifi_ierrors - stats.ifi_ierrors +
		                        ifd.ifi_oerrors - stats.ifi_oerrors);
	}
	return 0;
}

static struct pollfd fds;
static struct netmap_if *nm_if;
static bool *in_multi_seg_packet;

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

	zconf.data_link_size = fetch_data_link_size();
	log_debug("recv-netmap", "data_link_size %d", zconf.data_link_size);

	if (fetch_stats(NULL, NULL, NULL) == -1) {
		log_fatal("recv-netmap", "Failed to fetch initial interface counters");
	}
}

void recv_cleanup(void)
{
	free(in_multi_seg_packet);
	in_multi_seg_packet = NULL;
	nm_if = NULL;
}

void recv_packets(void)
{
	int ret = poll(&fds, 1, 100 /* ms */);
	if (ret == 0) {
		return;
	}
	else if (ret == -1) {
		log_error("recv-netmap", "poll(POLLIN) failed: %d: %s", errno, strerror(errno));
		return;
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
			if (!stats.hwstats) {
				stats.ifi_ipackets++;
			}
			handle_packet(slot->len, (uint8_t *)buf, ts);
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
	if (!stats.initialized) {
		return EXIT_FAILURE;
	}

	if (fetch_stats(&zrecv.pcap_recv, &zrecv.pcap_drop, &zrecv.pcap_ifdrop) == -1) {
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}
