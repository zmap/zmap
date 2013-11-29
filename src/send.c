/*
 * ZMap Copyright 2013 Regents of the University of Michigan 
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include "send.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include "../lib/includes.h"
#include "../lib/logger.h"
#include "../lib/random.h"
#include "../lib/blacklist.h"

#include "cyclic.h"
#include "get_gateway.h"
#include "state.h"
#include "probe_modules/packet.h"
#include "probe_modules/probe_modules.h"
#include "validate.h"

// OS specific functions called by send_run
static inline int send_packet(int fd, void *buf, int len);
static inline int send_run_init(int sock);


// Include the right implementations
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__)
#include "send-bsd.h"
#else /* LINUX */
#include "send-linux.h"
#endif /* __APPLE__ || __FreeBSD__ || __NetBSD__ */

// Lock to manage access to share send state such as counters and 
// cyclic group
pthread_mutex_t send_mutex = PTHREAD_MUTEX_INITIALIZER;

// Lock to provide thread safety to the user provided send callback
pthread_mutex_t syncb_mutex = PTHREAD_MUTEX_INITIALIZER;

// Globals to handle sending from multiple IP addresses
static uint16_t num_src_ports;
static uint32_t num_addrs;
static in_addr_t srcip_first;
static in_addr_t srcip_last;

// Offset send addresses according to a random chose per scan execution
// in order to help prevent cross-scan interference
static uint32_t srcip_offset;

// global sender initialize (not thread specific)
int send_init(void)
{
	// generate a new primitive root and starting position
	cyclic_init(0, 0);
	zsend.first_scanned = cyclic_get_curr_ip();

	// compute number of targets
	uint64_t allowed = blacklist_count_allowed();
	if (allowed == (1LL << 32)) {
		zsend.targets = 0xFFFFFFFF;
	} else {
		zsend.targets = allowed;
	}
	if (zsend.targets > zconf.max_targets) {
		zsend.targets = zconf.max_targets;
	}

	// process the dotted-notation addresses passed to ZMAP and determine
	// the source addresses from which we'll send packets;
	srcip_first = inet_addr(zconf.source_ip_first);
	if (srcip_first == INADDR_NONE) {
		log_fatal("send", "invalid begin source ip address: `%s'",
				zconf.source_ip_first);
	}
	srcip_last = inet_addr(zconf.source_ip_last);
	log_debug("send", "srcip_first: %u", srcip_first);
	log_debug("send", "srcip_last: %u", srcip_last);
	if (srcip_last == INADDR_NONE) {
		log_fatal("send", "invalid end source ip address: `%s'",
				zconf.source_ip_last);
	}
	if (srcip_first == srcip_last) {
		srcip_offset = 0;
		num_addrs = 1;
	} else {
		srcip_offset = rand() % (srcip_last - srcip_first);
		num_addrs = ntohl(srcip_last) - ntohl(srcip_first) + 1;
	}

	// process the source port range that ZMap is allowed to use
	num_src_ports = zconf.source_port_last - zconf.source_port_first + 1;
	log_debug("send", "will send from %i address%s on %u source ports",
		 num_addrs, ((num_addrs==1)?"":"es"), num_src_ports);

	// global initialization for send module
	assert(zconf.probe_module);
	if (zconf.probe_module->global_initialize) {
		zconf.probe_module->global_initialize(&zconf);
	}

	// concert specified bandwidth to packet rate
	if (zconf.bandwidth > 0) {
		int pkt_len = zconf.probe_module->packet_length;
		pkt_len *= 8;	
		pkt_len += 8*24;	// 7 byte MAC preamble, 1 byte Start frame, 
		                        // 4 byte CRC, 12 byte inter-frame gap
		if (pkt_len < 84*8) {
			pkt_len = 84*8;
		}
		if (zconf.bandwidth / pkt_len > 0xFFFFFFFF) {
			zconf.rate = 0;
		} else {
			zconf.rate = zconf.bandwidth / pkt_len;
			if (zconf.rate == 0) {
				log_warn("send", "bandwidth %lu bit/s is slower than 1 pkt/s, "
								"setting rate to 1 pkt/s", zconf.bandwidth);
				zconf.rate = 1;
			}
		}
		log_debug("send", "using bandwidth %lu bits/s, rate set to %d pkt/s",
						zconf.bandwidth, zconf.rate);
	}

	if (zconf.dryrun) {
		log_info("send", "dryrun mode -- won't actually send packets");
	}

	// initialize random validation key
	validate_init();

	zsend.start = now();	
	return EXIT_SUCCESS;
}

static inline ipaddr_n_t get_src_ip(ipaddr_n_t dst, int local_offset)
{
	if (srcip_first == srcip_last) {
		return srcip_first;
	}
	return htonl(((ntohl(dst) + srcip_offset + local_offset) 
			% num_addrs)) + srcip_first;
}

int get_dryrun_socket(void)
{
	// we need a socket in order to gather details about the system
	// such as source MAC address and IP address. However, because
	// we don't want to require root access in order to run dryrun,
	// we just create a TCP socket.
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock <= 0) {
		log_fatal("send", "couldn't create socket. "
			  "Error: %s\n", strerror(errno));
	}
	return sock;
}

// one sender thread
int send_run(int sock)
{
	log_debug("send", "thread started");
	pthread_mutex_lock(&send_mutex);

	// Allocate a buffer to hold the outgoing packet
	char buf[MAX_PACKET_SIZE];
	memset(buf, 0, MAX_PACKET_SIZE);

	// OS specific per-thread init
	if (send_run_init(sock)) {
		return -1;
	}

	// Get the source hardware address, and give it to the probe
	// module
	unsigned char hw_mac[ETHER_ADDR_LEN];
	if (get_iface_hw_addr(zconf.iface, hw_mac)) {
		log_fatal("send", "Couldn't get hardware address for"
			  "interface: %s", zconf.iface);
		return -1;
	}

	zconf.probe_module->thread_initialize(buf, hw_mac, zconf.gw_mac,
					      zconf.target_port);
	pthread_mutex_unlock(&send_mutex);

	
	// adaptive timing to hit target rate
	uint32_t count = 0;
	uint32_t last_count = count;
	double last_time = now();
	uint32_t delay = 0;
	int interval = 0;
	volatile int vi;
	if (zconf.rate > 0) {
		// estimate initial rate
		delay = 10000;
		for (vi = delay; vi--; )
			;
		delay *= 1 / (now() - last_time) / (zconf.rate / zconf.senders);
		interval = (zconf.rate / zconf.senders) / 20;
		last_time = now();
	}
	while (1) {
		// adaptive timing delay
		if (delay > 0) {
			count++;
			for (vi = delay; vi--; )
				;
			if (!interval || (count % interval == 0)) {
				double t = now();
				delay *= (double)(count - last_count) 
					/ (t - last_time) / (zconf.rate / zconf.senders);
				if (delay < 1)
					delay = 1;
				last_count = count;
				last_time = t;
			}
		}
		// generate next ip from cyclic group and update global state
		// (everything locked happens here)
		pthread_mutex_lock(&send_mutex);
		if (zsend.complete) {
			pthread_mutex_unlock(&send_mutex);
			break;
		}
		if (zsend.sent >= zconf.max_targets) {
			zsend.complete = 1;
			zsend.finish = now();
			pthread_mutex_unlock(&send_mutex);
			break;
		}
		if (zconf.max_runtime && zconf.max_runtime <= now() - zsend.start) {
			zsend.complete = 1;
			zsend.finish = now();
			pthread_mutex_unlock(&send_mutex);
			break;
		}
		uint32_t curr = cyclic_get_next_ip();
		if (curr == zsend.first_scanned) {
			zsend.complete = 1;
			zsend.finish = now();
		}
		zsend.sent++;
		pthread_mutex_unlock(&send_mutex);
		for (int i=0; i < zconf.packet_streams; i++) {
			uint32_t src_ip = get_src_ip(curr, i);

		  	uint32_t validation[VALIDATE_BYTES/sizeof(uint32_t)];
			validate_gen(src_ip, curr, (uint8_t *)validation);
			zconf.probe_module->make_packet(buf, src_ip, curr, validation, i);

			if (zconf.dryrun) {
				zconf.probe_module->print_packet(stdout, buf);
			} else {
				int length = zconf.probe_module->packet_length;
				void *contents = buf + zconf.send_ip_pkts*sizeof(struct ether_header);
				int rc = send_packet(sock, contents, length);
				if (rc < 0) {
					struct in_addr addr;
					addr.s_addr = curr;
					log_debug("send", "send_packet failed for %s. %s",
							  inet_ntoa(addr), strerror(errno));
					pthread_mutex_lock(&send_mutex);
					zsend.sendto_failures++;
					pthread_mutex_unlock(&send_mutex);
				}
			}
		}
	}
	log_debug("send", "thread finished");
	return EXIT_SUCCESS;
}

