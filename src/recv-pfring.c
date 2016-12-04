/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include "recv.h"
#include "recv-internal.h"

#include "../lib/includes.h"
#include "../lib/logger.h"

#include <errno.h>
#include <unistd.h>

#include <pfring_zc.h>

#include "state.h"

static pfring_zc_pkt_buff *pf_buffer;
static pfring_zc_queue *pf_recv;

void recv_init()
{
	// Get the socket and packet handle
	pf_recv = zconf.pf.recv;
	pf_buffer = pfring_zc_get_packet_handle(zconf.pf.cluster);
	if (pf_buffer == NULL) {
		log_fatal("recv", "Could not get packet handle: %s",
				strerror(errno));
	}
}

void recv_cleanup()
{
	if (!pf_recv) {
		return;
	}
	pfring_zc_sync_queue(pf_recv, rx_only);
}

void recv_packets()
{
	int ret;
	// Poll for packets
	do {
		ret = pfring_zc_recv_pkt(pf_recv, &pf_buffer, 0);
		if (ret == 0) {
			usleep(1000);
		}
	} while (ret == 0);
	// Handle other errors, by not doing anything and logging
	if (ret != 1) {
		log_error("recv", "Error: %d", ret);
		return;
	}
	// Successfully got a packet, now handle it
	uint8_t* pkt_buf = pfring_zc_pkt_buff_data(pf_buffer, pf_recv);
	handle_packet(pf_buffer->len, pkt_buf);
}

int recv_update_stats(void)
{
	if (!pf_recv) {
		return EXIT_FAILURE;
	}
	pfring_zc_stat pfst;
	if (pfring_zc_stats(pf_recv, &pfst)) {
		log_error("recv", "unable to retrieve pfring statistics");
		return EXIT_FAILURE;
	} else {
		zrecv.pcap_recv = pfst.recv;
		zrecv.pcap_drop = pfst.drop;
	}
	return EXIT_SUCCESS;
}

