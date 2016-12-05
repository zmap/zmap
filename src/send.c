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
#include <signal.h>

#include "../lib/includes.h"
#include "../lib/logger.h"
#include "../lib/random.h"
#include "../lib/blacklist.h"
#include "../lib/lockfd.h"
#include "../lib/pbm.h"

#include "aesrand.h"
#include "get_gateway.h"
#include "iterator.h"
#include "probe_modules/packet.h"
#include "probe_modules/probe_modules.h"
#include "shard.h"
#include "state.h"
#include "validate.h"

// OS specific functions called by send_run
static inline int send_packet(sock_t sock, void *buf, int len, uint32_t idx);
static inline int send_run_init(sock_t sock);

// Include the right implementations
#if defined(PFRING)
#include "send-pfring.h"
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__DragonFly__)
#include "send-bsd.h"
#else /* LINUX */
#include "send-linux.h"
#endif /* __APPLE__ || __FreeBSD__ || __NetBSD__ || __DragonFly__ */

// The iterator over the cyclic group

// Lock for send run
static pthread_mutex_t send_mutex = PTHREAD_MUTEX_INITIALIZER;

// Source IP address for outgoing packets
static in_addr_t srcip_first;
static in_addr_t srcip_last;
static uint32_t srcip_offset;
static uint32_t num_src_addrs;

// Source ports for outgoing packets
static uint16_t num_src_ports;


void sig_handler_increase_speed(UNUSED int signal)
{
	int old_rate = zconf.rate;
	zconf.rate += (zconf.rate * 0.05);
	log_info("send", "send rate increased from %i to %i pps.",
			old_rate, zconf.rate);
}

void sig_handler_decrease_speed(UNUSED int signal)
{
	int old_rate = zconf.rate;
	zconf.rate -= (zconf.rate * 0.05);
	log_info("send", "send rate decreased from %i to %i pps.",
			old_rate, zconf.rate);
}


// global sender initialize (not thread specific)
iterator_t* send_init(void)
{
	// generate a new primitive root and starting position
	iterator_t *it;
	it = iterator_init(zconf.senders, zconf.shard_num, zconf.total_shards);
	// process the dotted-notation addresses passed to ZMAP and determine
	// the source addresses from which we'll send packets;
	srcip_first = inet_addr(zconf.source_ip_first);
	if (srcip_first == INADDR_NONE) {
		log_fatal("send", "invalid begin source ip address: `%s'",
				zconf.source_ip_first);
	}
	srcip_last = inet_addr(zconf.source_ip_last);
	if (srcip_last == INADDR_NONE) {
		log_fatal("send", "invalid end source ip address: `%s'",
				zconf.source_ip_last);
	}
	log_debug("send", "srcip_first: %u", srcip_first);
	log_debug("send", "srcip_last: %u", srcip_last);
	if (srcip_first == srcip_last) {
		srcip_offset = 0;
		num_src_addrs = 1;
	} else {
		uint32_t ip_first = ntohl(srcip_first);
		uint32_t ip_last = ntohl(srcip_last);
		assert(ip_first && ip_last);
		assert(ip_last > ip_first);
		uint32_t offset = (uint32_t) (aesrand_getword(zconf.aes)
						& 0xFFFFFFFF);
		srcip_offset = offset % (srcip_last - srcip_first);
		num_src_addrs = ip_last - ip_first + 1;
	}

	// process the source port range that ZMap is allowed to use
	num_src_ports = zconf.source_port_last - zconf.source_port_first + 1;
	log_debug("send", "will send from %i address%s on %u source ports",
		  num_src_addrs, ((num_src_addrs ==1 ) ? "":"es"),
		  num_src_ports);
	// global initialization for send module
	assert(zconf.probe_module);
	if (zconf.probe_module->global_initialize) {
		if (zconf.probe_module->global_initialize(&zconf)) {
        		log_fatal("send", "global initialization for probe module failed.");
	        }
	}
	// concert specified bandwidth to packet rate
	if (zconf.bandwidth > 0) {
		size_t pkt_len = zconf.probe_module->packet_length;
		pkt_len *= 8;
		pkt_len += 8*24; // 7 byte MAC preamble, 1 byte Start frame,
		                 // 4 byte CRC, 12 byte inter-frame gap
		if (pkt_len < 84*8) {
			pkt_len = 84*8;
		}
        // rate is a uint32_t so, don't overflow
		if (zconf.bandwidth / pkt_len > 0xFFFFFFFFu) {
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
	// Get the source hardware address, and give it to the probe
	// module
    if (!zconf.hw_mac_set) {
	    if (get_iface_hw_addr(zconf.iface, zconf.hw_mac)) {
	    	log_fatal("send", "could not retrieve hardware address for "
	    		  "interface: %s", zconf.iface);
	    	return NULL;
	    }
        log_debug("send", "no source MAC provided. "
                "automatically detected %02x:%02x:%02x:%02x:%02x:%02x as hw "
                "interface for %s",
                zconf.hw_mac[0], zconf.hw_mac[1], zconf.hw_mac[2],
                zconf.hw_mac[3], zconf.hw_mac[4], zconf.hw_mac[5],
                zconf.iface);
    }
	log_debug("send", "source MAC address %02x:%02x:%02x:%02x:%02x:%02x",
           zconf.hw_mac[0], zconf.hw_mac[1], zconf.hw_mac[2],
           zconf.hw_mac[3], zconf.hw_mac[4], zconf.hw_mac[5]);

	if (zconf.dryrun) {
		log_info("send", "dryrun mode -- won't actually send packets");
	}
	// initialize random validation key
	validate_init();
	// setup signal handlers for changing scan speed
	signal(SIGUSR1, sig_handler_increase_speed);
	signal(SIGUSR2, sig_handler_decrease_speed);

	zsend.start = now();
	return it;
}


static inline ipaddr_n_t get_src_ip(ipaddr_n_t dst, int local_offset)
{
	if (srcip_first == srcip_last) {
		return srcip_first;
	}
	return htonl(((ntohl(dst) + srcip_offset + local_offset)
			% num_src_addrs)) + srcip_first;
}

// one sender thread
int send_run(sock_t st, shard_t *s)
{
	log_debug("send", "send thread started");
	pthread_mutex_lock(&send_mutex);
	// Allocate a buffer to hold the outgoing packet
	char buf[MAX_PACKET_SIZE];
	memset(buf, 0, MAX_PACKET_SIZE);

	// OS specific per-thread init
	if (send_run_init(st)) {
		return -1;
	}

	// MAC address length in characters
	char mac_buf[(ETHER_ADDR_LEN * 2) + (ETHER_ADDR_LEN - 1) + 1];
	char *p = mac_buf;
	for(int i=0; i < ETHER_ADDR_LEN; i++) {
		if (i == ETHER_ADDR_LEN-1) {
			snprintf(p, 3, "%.2x", zconf.hw_mac[i]);
			p += 2;
		} else {
			snprintf(p, 4, "%.2x:", zconf.hw_mac[i]);
			p += 3;
		}
	}
	log_debug("send", "source MAC address %s",
			mac_buf);
	void *probe_data;
	if (zconf.probe_module->thread_initialize) {
		zconf.probe_module->thread_initialize(buf, zconf.hw_mac,
						zconf.gw_mac,
						zconf.target_port, &probe_data);
	}
	pthread_mutex_unlock(&send_mutex);

	// adaptive timing to hit target rate
	uint32_t count = 0;
	uint32_t last_count = count;
	double last_time = now();
	uint32_t delay = 0;
	int interval = 0;
	uint32_t max_targets = s->state.max_targets;
	volatile int vi;
    struct timespec ts, rem;
    double send_rate = (double) zconf.rate / zconf.senders;
    const double slow_rate = 50; // packets per seconds per thread
 			   					// at which it uses the slow methods
    long nsec_per_sec = 1000 * 1000 * 1000;
    long long sleep_time = nsec_per_sec;
	if (zconf.rate > 0) {
		delay = 10000;
        if (send_rate < slow_rate) {
            // set the inital time difference
            sleep_time = nsec_per_sec / send_rate;
            last_time = now() - (1.0 / send_rate);
        } else {
		    // estimate initial rate
		    for (vi = delay; vi--; )
		    	;
		    delay *= 1 / (now() - last_time) / (zconf.rate / zconf.senders);
		    interval = (zconf.rate / zconf.senders) / 20;
		    last_time = now();
        }
	}
	uint32_t curr = shard_get_cur_ip(s);
	// if list of IPs provided to scan, then the first generated address
	// might not be on that list. iterate until we find one and can start
	// the true scanning process
	if (zconf.list_of_ips_filename) {
		while (!pbm_check(zsend.list_of_ips_pbm, curr)) {
			curr = shard_get_next_ip(s);
			s->state.tried_sent++;
			if (!curr) {
				log_debug("send", "never made it to send loop in send thread %i", s->id);
				s->cb(s->id, s->arg);
				goto cleanup;
			}
		}
	}
	int attempts = zconf.num_retries + 1;
	uint32_t idx = 0;
	while (1) {
		// adaptive timing delay
		send_rate = (double) zconf.rate / zconf.senders;
		if (delay > 0) {
            if (send_rate < slow_rate) {
                double t = now();
                double last_rate = (1.0 / (t - last_time));

                sleep_time *= ((last_rate / send_rate) + 1) / 2;
                ts.tv_sec = sleep_time / nsec_per_sec;
                ts.tv_nsec = sleep_time % nsec_per_sec;
                log_debug("sleep", "sleep for %d sec, %ld nanoseconds",
				ts.tv_sec, ts.tv_nsec);
                while (nanosleep(&ts, &rem) == -1) {}
                last_time = t;
            } else {
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
		}
		if (zrecv.complete) {
			s->cb(s->id, s->arg);
			break;
		}
		if (s->state.sent >= max_targets) {
			s->cb(s->id, s->arg);
			log_debug("send", "send thread %hhu finished (max targets of %u reached)", s->id, max_targets);
			break;
		}
		// estimate a random sample for a provided list of IPs to scan
		if (zconf.list_of_ips_filename && s->state.tried_sent >= max_targets) {
			s->cb(s->id, s->arg);
			log_debug("send", "send thread %hhu finished (max targets of %u reached)", s->id, max_targets);
			break;
		}
		if (zconf.max_runtime && zconf.max_runtime <= now() - zsend.start) {
			s->cb(s->id, s->arg);
			break;
		}
		if (curr == 0) {
			s->cb(s->id, s->arg);
			log_debug("send", "send thread %hhu finished, shard depleted", s->id);
			break;
		}
		for (int i=0; i < zconf.packet_streams; i++) {
			count++;
			uint32_t src_ip = get_src_ip(curr, i);
		  	uint32_t validation[VALIDATE_BYTES/sizeof(uint32_t)];
			validate_gen(src_ip, curr, (uint8_t *)validation);
			zconf.probe_module->make_packet(buf, src_ip, curr,
					validation, i, probe_data);
			if (zconf.dryrun) {
				lock_file(stdout);
				zconf.probe_module->print_packet(stdout, buf);
				unlock_file(stdout);
			} else {
				int length = zconf.probe_module->packet_length;
				void *contents = buf + zconf.send_ip_pkts*sizeof(struct ether_header);
				int any_sends_successful = 0;
				for (int i = 0; i < attempts; ++i) {
					int rc = send_packet(st, contents, length, idx);
					if (rc < 0) {
						struct in_addr addr;
						addr.s_addr = curr;
						char addr_str_buf[INET_ADDRSTRLEN];
						const char *addr_str = inet_ntop(AF_INET, &addr, addr_str_buf, INET_ADDRSTRLEN);
						if (addr_str != NULL) {
							log_debug("send", "send_packet failed for %s. %s",
								addr_str, strerror(errno));
						}
					} else {
						any_sends_successful = 1;
						break;
					}
				}
				if (!any_sends_successful) {
					s->state.failures++;
				}
				idx++;
				idx &= 0xFF;
			}
		}
		// number of hosts we actually scanned
		curr = shard_get_next_ip(s);
		s->state.sent++;
		s->state.tried_sent++;
		if (curr && zconf.list_of_ips_filename) {
			while (!pbm_check(zsend.list_of_ips_pbm, curr)) {
				curr = shard_get_next_ip(s);
				s->state.tried_sent++;
				if (!curr) {
					s->cb(s->id, s->arg);
					log_debug("send", "send thread %hhu shard finished in get_next_ip_loop depleted", s->id);
					goto cleanup;

				}
			}
		}
	}
cleanup:
	if (zconf.dryrun) {
		lock_file(stdout);
		fflush(stdout);
		unlock_file(stdout);
	}
	log_debug("send", "thread %hu cleanly finished", s->id);
	return EXIT_SUCCESS;
}
