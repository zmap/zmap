/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include <assert.h>
#include <pthread.h>
#include <stdint.h>
#include <time.h>

#include "../lib/includes.h"
#include "../lib/blocklist.h"
#include "../lib/logger.h"
#include "../lib/xalloc.h"
#include "../lib/util.h"

#include "iterator.h"

#include "aesrand.h"
#include "shard.h"
#include "state.h"

struct iterator {
	cycle_t cycle;
	uint8_t num_threads;
	shard_t *thread_shards;
	uint8_t *complete;
	pthread_mutex_t mutex;
	uint32_t curr_threads;
};

void shard_complete(uint8_t thread_id, void *arg)
{
	iterator_t *it = (iterator_t *)arg;
	assert(thread_id < it->num_threads);
	pthread_mutex_lock(&it->mutex);
	it->complete[thread_id] = 1;
	it->curr_threads--;
	shard_t *s = &it->thread_shards[thread_id];
	zsend.packets_sent += s->state.packets_sent;
	zsend.targets_scanned += s->state.targets_scanned;
	zsend.sendto_failures += s->state.packets_failed;
	uint8_t done = 1;
	for (uint8_t i = 0; done && (i < it->num_threads); ++i) {
		done = done && it->complete[i];
	}
	if (done) {
		zsend.finish = now();
		zsend.complete = 1;
		zsend.first_scanned = it->thread_shards[0].state.first_scanned;
	}
	pthread_mutex_unlock(&it->mutex);
}

static uint64_t bits_needed(uint64_t n)
{
	n -= 1;
	int r = 0;
	while (n) {
		r++;
		n >>= 1;
	}
	return r;
}

iterator_t *iterator_init(uint8_t num_threads, uint16_t shard,
			  uint16_t num_shards, uint64_t num_addrs,
			  uint32_t num_ports)
{
	uint8_t bits_for_ip = bits_needed(num_addrs);
	log_debug("iterator", "bits needed for %u addresses: %u", num_addrs,
		  bits_for_ip);
	uint8_t bits_for_port = bits_needed(num_ports);
	log_debug("iterator", "bits needed for %u ports: %u", num_ports,
		  bits_for_port);
	uint64_t group_min_size = ((uint64_t)1)
				  << (bits_for_ip + bits_for_port);
	log_debug("iterator", "minimum elements to iterate over: %llu",
		  group_min_size);
	iterator_t *it = xmalloc(sizeof(struct iterator));
	const cyclic_group_t *group = get_group(group_min_size);
	if (num_addrs > (1LL << 32)) {
		zsend.max_index = 0xFFFFFFFF;
	} else {
		zsend.max_index = (uint32_t)num_addrs;
	}
	log_debug("iterator", "max index %u", zsend.max_index);
	it->cycle = make_cycle(group, zconf.aes);
	it->num_threads = num_threads;
	it->curr_threads = num_threads;
	it->thread_shards = xcalloc(num_threads, sizeof(shard_t));
	it->complete = xcalloc(it->num_threads, sizeof(uint8_t));
	pthread_mutex_init(&it->mutex, NULL);
	log_debug("iterator", "max targets is %u", zsend.max_targets);
	for (uint8_t i = 0; i < num_threads; ++i) {
		shard_init(&it->thread_shards[i], shard, num_shards, i,
			   num_threads, zsend.max_targets, bits_for_port,
			   &it->cycle, shard_complete, it);
	}
	zconf.generator = it->cycle.generator;
	return it;
}

uint64_t iterator_get_sent(iterator_t *it)
{
	uint64_t sent = 0;
	for (uint8_t i = 0; i < it->num_threads; ++i) {
		sent += it->thread_shards[i].state.packets_sent;
	}
	return sent;
}

uint64_t iterator_get_iterations(iterator_t *it)
{
	uint64_t iterations = 0;
	for (uint8_t i = 0; i < it->num_threads; ++i) {
		iterations += it->thread_shards[i].iterations;
	}
	return iterations;
}

uint32_t iterator_get_fail(iterator_t *it)
{
	uint32_t fails = 0;
	for (uint8_t i = 0; i < it->num_threads; ++i) {
		fails += it->thread_shards[i].state.packets_failed;
	}
	return fails;
}

shard_t *get_shard(iterator_t *it, uint8_t thread_id)
{
	assert(thread_id < it->num_threads);
	return &it->thread_shards[thread_id];
}

uint32_t iterator_get_curr_send_threads(iterator_t *it)
{
	assert(it);
	return it->curr_threads;
}
