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
#include <sys/syscall.h>
#include <sys/sysinfo.h>

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

void packet_buf_init();
void wait_recv_handle_complete();

uint8_t ** get_recv_pbm() {
	return seen;
}

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
		zrecv.validation_failed++;
		return;
	} else {
		zrecv.validation_passed++;
	}
	// woo! We've validated that the packet is a response to our scan
	int is_repeat = pbm_check(seen, ntohl(src_ip));
	// track whether this is the first packet in an IP fragment.
	if (ip_hdr->ip_off & IP_MF) {
		zrecv.ip_fragments++;
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
		zrecv.success_total++;
		if (!is_repeat) {
			zrecv.success_unique++;
			pbm_set(seen, ntohl(src_ip));
		}
		if (zsend.complete) {
			zrecv.cooldown_total++;
			if (!is_repeat) {
				zrecv.cooldown_unique++;
			}
		}
	} else {
		zrecv.failure_total++;
	}
	// probe module includes app_success field
	if (zconf.fsconf.app_success_index >= 0) {
		int is_app_success =
		    fs_get_uint64_by_index(fs, zconf.fsconf.app_success_index);
		if (is_app_success) {
			zrecv.app_success_total++;
			if (!is_repeat) {
				zrecv.app_success_unique++;
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
	zrecv.filter_success++;
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
		packet_buf_init();
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

#define MAX_PACKET_BUF_POOL_SIZE 1024
static u_char** packet_buf_pool = NULL;
static uint32_t packet_buf_pool_idx = 0;
static pthread_spinlock_t packet_buf_pool_spin;
#define MAX_PACKET_BUF_SIZE (1024 * 1024 * 128)
static u_char* packet_buf = NULL;
static uint32_t packet_buf_idx = 0;
static uint32_t current_packet_buf = 0;
static uint32_t current_cpu = 0;
static pthread_t* thread_ids = NULL;

u_char* get_next_packet_buf() {
	u_char* ret = NULL;
	pthread_spin_lock(&packet_buf_pool_spin);
	if (current_packet_buf < packet_buf_pool_idx) {
		ret = packet_buf_pool[current_packet_buf];
		current_packet_buf++;
	}
	pthread_spin_unlock(&packet_buf_pool_spin);
	return ret;
}

void* handle_packet_buf_thread(void* arg) {
	log_debug("zmap", "handle_packet_buf_thread starting new thread(%d)", syscall(SYS_gettid));
	set_cpu((uint32_t)(uint64_t)arg);

	while (1) {
		u_char* buf = get_next_packet_buf();
		if (!buf) {
			if (zsend.complete) {
				break;
			}
			log_debug("zmap", "handle_packet_buf_thread waiting (%d)", syscall(SYS_gettid));
			sleep(1);
			continue;
		}
		uint32_t idx = 0;
		uint32_t buflen = *((uint32_t*)(&buf[idx]));
		uint32_t count = 0;
		while (buflen > 0) {
			idx += sizeof(uint32_t);
			do_handle_packet(buflen, &buf[idx]);
			idx += buflen;
			buflen = *((uint32_t*)(&buf[idx]));
			count++;
		}
		log_debug("zmap", "handle_packet_buf_thread processed %llu packets (%d)", count, syscall(SYS_gettid));
		xfree(buf);
	}
	log_debug("zmap", "handle_packet_buf_thread completed(%d)", syscall(SYS_gettid));
	return NULL;
}

void packet_buf_init() {
	if (thread_ids == NULL) {
		thread_ids = xmalloc(get_nprocs() * sizeof(pthread_t));
	}
	if (packet_buf_pool == NULL) {
		packet_buf_pool = xmalloc(MAX_PACKET_BUF_POOL_SIZE * sizeof(u_char*));
		pthread_spin_init(&packet_buf_pool_spin, PTHREAD_PROCESS_PRIVATE);
	}

	// use from the second half, leave the first half cpu cores for tx/rx/mon threads.
	current_cpu = get_nprocs() / 2;
	int r = pthread_create(&thread_ids[current_cpu], NULL, handle_packet_buf_thread, (void*)(uint64_t)current_cpu);
	if (r != 0) {
		log_fatal("zmap", "unable to create packet handle thread");
	}
}

void start_handle_thread() {
	if (packet_buf == NULL) {
		return;
	}

	pthread_spin_lock(&packet_buf_pool_spin);
	if (packet_buf_pool_idx >= MAX_PACKET_BUF_POOL_SIZE) {
		log_fatal("zmap", "packet buf pool overflow.");
	}
	*((uint32_t*)(&packet_buf[packet_buf_idx])) = 0;
	packet_buf_pool[packet_buf_pool_idx++] = packet_buf;
	pthread_spin_unlock(&packet_buf_pool_spin);
	packet_buf = NULL;
	packet_buf_idx = 0;
}

void handle_packet(uint32_t buflen, const u_char* bytes)
{
	uint32_t remainder = MAX_PACKET_BUF_SIZE - packet_buf_idx - 1 - sizeof(uint32_t);
	if (remainder < (buflen + sizeof(uint32_t))) {
		start_handle_thread();
	}
	if (packet_buf == NULL) {
		packet_buf = (u_char*)xmalloc(MAX_PACKET_BUF_SIZE);
		if (packet_buf == NULL) {
			log_fatal("zmap", "couldn't allocate work buffer.");
		}
	}
	*((uint32_t*)(&packet_buf[packet_buf_idx])) = buflen;
	packet_buf_idx += sizeof(uint32_t);
	memcpy(&packet_buf[packet_buf_idx], bytes, buflen);
	packet_buf_idx += buflen;
}

void wait_recv_handle_complete() {
	// in case there are remainders
	start_handle_thread();

	pthread_join(thread_ids[current_cpu], NULL);

	xfree(thread_ids);
	xfree(packet_buf_pool);
	pthread_spin_destroy(&packet_buf_pool_spin);
	log_info("zmap", "recv handle complete");
}
