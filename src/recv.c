/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include "recv.h"

#include <assert.h>

#include "../lib/includes.h"
#include "../lib/logger.h"
#include "../lib/pbm.h"
#include "../lib/xalloc.h"
#include "../lib/util.h"

#include <pthread.h>
#include <unistd.h>

#include "recv-internal.h"
#include "state.h"
#include "validate.h"
#include "fieldset.h"
#include "expression.h"
#include "probe_modules/probe_modules.h"
#include "output_modules/output_modules.h"

static u_char fake_eth_hdr[65535];
// bitmap of observed IP addresses
static uint8_t **seen = NULL;

void wait_recv_handle_complete();

void do_handle_packet(uint32_t buflen, const u_char *bytes)
{
	if ((sizeof(struct ip) + zconf.data_link_size) > buflen) {
		// buffer not large enough to contain ethernet
		// and ip headers. further action would overrun buf
		return;
	}
	struct ip *ip_hdr = (struct ip *)&bytes[zconf.data_link_size];

	uint32_t src_ip = ip_hdr->ip_src.s_addr;

	uint32_t validation[VALIDATE_BYTES / sizeof(uint8_t)];
	// TODO: for TTL exceeded messages, ip_hdr->saddr is going to be
	// different and we must calculate off potential payload message instead
	validate_gen(ip_hdr->ip_dst.s_addr, ip_hdr->ip_src.s_addr,
		     (uint8_t *)validation);

	if (!zconf.probe_module->validate_packet(
		ip_hdr,
		buflen - (zconf.send_ip_pkts ? 0 : sizeof(struct ether_header)),
		&src_ip, validation)) {
		atomic_fetch_add(&zrecv.validation_failed, 1);
		return;
	} else {
		atomic_fetch_add(&zrecv.validation_passed, 1);
	}
	// woo! We've validated that the packet is a response to our scan
	int is_repeat = pbm_check(seen, ntohl(src_ip));
	// track whether this is the first packet in an IP fragment.
	if (ip_hdr->ip_off & IP_MF) {
		atomic_fetch_add(&zrecv.ip_fragments, 1);
	}

	fieldset_t *fs = fs_new_fieldset();
	fs_add_ip_fields(fs, ip_hdr);
	// HACK:
	// probe modules expect the full ethernet frame
	// in process_packet. For VPN, we only get back an IP frame.
	// Here, we fake an ethernet frame (which is initialized to
	// have ETH_P_IP proto and 00s for dest/src).
	if (zconf.send_ip_pkts) {
		if (buflen > sizeof(fake_eth_hdr)) {
			buflen = sizeof(fake_eth_hdr);
		}
		memcpy(&fake_eth_hdr[sizeof(struct ether_header)],
		       bytes + zconf.data_link_size, buflen);
		bytes = fake_eth_hdr;
	}
	zconf.probe_module->process_packet(bytes, buflen, fs, validation);
	fs_add_system_fields(fs, is_repeat, zsend.complete);
	int success_index = zconf.fsconf.success_index;
	assert(success_index < fs->len);
	int is_success = fs_get_uint64_by_index(fs, success_index);

	if (is_success) {
		atomic_fetch_add(&zrecv.success_total, 1);
		if (!is_repeat) {
			atomic_fetch_add(&zrecv.success_unique, 1);
			pbm_set(seen, ntohl(src_ip));
		}
		if (zsend.complete) {
			atomic_fetch_add(&zrecv.cooldown_total, 1);
			if (!is_repeat) {
				atomic_fetch_add(&zrecv.cooldown_unique, 1);
			}
		}
	} else {
		atomic_fetch_add(&zrecv.failure_total, 1);
	}
	// probe module includes app_success field
	if (zconf.fsconf.app_success_index >= 0) {
		int is_app_success =
		    fs_get_uint64_by_index(fs, zconf.fsconf.app_success_index);
		if (is_app_success) {
			atomic_fetch_add(&zrecv.app_success_total, 1);
			if (!is_repeat) {
				atomic_fetch_add(&zrecv.app_success_unique, 1);
			}
		}
	}

	fieldset_t *o = NULL;
	// we need to translate the data provided by the probe module
	// into a fieldset that can be used by the output module
	if (!is_success && zconf.filter_unsuccessful) {
		goto cleanup;
	}
	if (is_repeat && zconf.filter_duplicates) {
		goto cleanup;
	}
	if (!evaluate_expression(zconf.filter.expression, fs)) {
		goto cleanup;
	}
	atomic_fetch_add(&zrecv.filter_success, 1);
	o = translate_fieldset(fs, &zconf.fsconf.translation);
	if (zconf.output_module && zconf.output_module->process_ip) {
		zconf.output_module->process_ip(o);
	}
cleanup:
	fs_free(fs);
	free(o);
	if (zconf.output_module && zconf.output_module->update &&
	    !(zrecv.success_unique % zconf.output_module->update_interval)) {
		zconf.output_module->update(&zconf, &zsend, &zrecv);
	}
}

int recv_run(pthread_mutex_t *recv_ready_mutex)
{
	log_trace("recv", "recv thread started");
	log_debug("recv", "capturing responses on %s", zconf.iface);
	if (!zconf.dryrun) {
		recv_init();
	}
	if (zconf.send_ip_pkts) {
		struct ether_header *eth = (struct ether_header *)fake_eth_hdr;
		memset(fake_eth_hdr, 0, sizeof(fake_eth_hdr));
		eth->ether_type = htons(ETHERTYPE_IP);
	}
	// initialize paged bitmap
	seen = pbm_init();
	if (zconf.filter_duplicates) {
		log_debug("recv",
			  "duplicate responses will be excluded from output");
	} else {
		log_debug("recv",
			  "duplicate responses will be included in output");
	}
	if (zconf.filter_unsuccessful) {
		log_debug(
		    "recv",
		    "unsuccessful responses will be excluded from output");
	} else {
		log_debug("recv",
			  "unsuccessful responses will be included in output");
	}

	pthread_mutex_lock(recv_ready_mutex);
	zconf.recv_ready = 1;
	pthread_mutex_unlock(recv_ready_mutex);
	zrecv.start = now();
	if (zconf.max_results == 0) {
		zconf.max_results = -1;
	}

	do {
		if (zconf.dryrun) {
			sleep(1);
		} else {
			recv_packets();
			if (zconf.max_results &&
			    zrecv.filter_success >= zconf.max_results) {
				break;
			}
		}
	} while (
	    !(zsend.complete && (now() - zsend.finish > zconf.cooldown_secs)));
	zrecv.finish = now();
	wait_recv_handle_complete();
	// get final pcap statistics before closing
	recv_update_stats();
	if (!zconf.dryrun) {
		pthread_mutex_lock(recv_ready_mutex);
		recv_cleanup();
		pthread_mutex_unlock(recv_ready_mutex);
	}
	zrecv.complete = 1;
	log_debug("recv", "thread finished");
	return 0;
}

static u_char* work_buf = NULL;
static uint32_t work_buf_idx = 0;
static uint32_t cpu_rotated = 0;
#define UP_WORK_CPU_CORE 24
#define LOW_WORK_CPU_CORE 8
#define MAX_WORK_BUF_SIZE (1024 * 1024 * 256)
#define MAX_WORK_THREADS 1024
static pthread_t* thread_ids = NULL;
static uint32_t current_threads = 0;

void* handle_packet_buf_thread(void* arg) {
	log_debug("zmap", "handle_packet_buf_thread starting new thread");
	if (cpu_rotated < LOW_WORK_CPU_CORE || cpu_rotated > UP_WORK_CPU_CORE) {
		cpu_rotated = LOW_WORK_CPU_CORE;
	}
	set_cpu(cpu_rotated++);
	u_char* buf = (u_char*)arg;
	uint32_t idx = 0;
	uint32_t buflen = *((uint32_t*)(&buf[idx]));
	while (buflen > 0) {
		idx += sizeof(uint32_t);
		do_handle_packet(buflen, &buf[idx]);
		idx += buflen;
		buflen = *((uint32_t*)(&buf[idx]));
	}
	xfree(buf);
	log_debug("zmap", "handle_packet_buf_thread completed");
	return NULL;
}

void start_handle_thread() {
	if (work_buf == NULL) {
		return;
	}
	if (thread_ids == NULL) {
		thread_ids = xmalloc(MAX_WORK_THREADS * sizeof(pthread_t));
	}

	if (current_threads >= MAX_WORK_THREADS) {
		log_fatal("zmap", "too many work threads, try to increase MAX_WORK_BUF_SIZE for less threads.");
	}
	int r = pthread_create(&thread_ids[current_threads++], NULL, handle_packet_buf_thread, work_buf);
	if (r != 0) {
		log_fatal("zmap", "unable to create packet handle thread");
	}
}

void handle_packet(uint32_t buflen, const u_char* bytes)
{
	if ((MAX_WORK_BUF_SIZE - work_buf_idx - 1) > (buflen + sizeof(buflen))) {
		if (work_buf == NULL) {
			work_buf = (u_char*)xmalloc(MAX_WORK_BUF_SIZE);
			if (work_buf == NULL) {
				log_fatal("handle_packet", "couldn't allocate work buffer.");  
			}
		}
		*((uint32_t*)(&work_buf[work_buf_idx])) = buflen;
		work_buf_idx += sizeof(buflen);
		memmove(&work_buf[work_buf_idx], bytes, buflen);
		work_buf_idx += buflen;
	} else {
		start_handle_thread();
		work_buf = NULL;
		work_buf_idx = 0;
	}
}

void wait_recv_handle_complete() {
	// in case there are remainders
	start_handle_thread();

	for (uint32_t i = 0; i < current_threads; i++) {
		pthread_join(thread_ids[i], NULL);
	}
	xfree(thread_ids);
	log_info("zmap", "recv handle complete");
}
