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
#include "../lib/blacklist.h"
#include "../lib/logger.h"
#include "../lib/xalloc.h"

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
	iterator_t *it = (iterator_t *) arg;
	assert(thread_id < it->num_threads);
	pthread_mutex_lock(&it->mutex);
	it->complete[thread_id] = 1;
	it->curr_threads--;
	shard_t *s = &it->thread_shards[thread_id];
	zsend.sent += s->state.sent;
	zsend.tried_sent += s->state.tried_sent;
	zsend.blacklisted += s->state.blacklisted;
	zsend.whitelisted += s->state.whitelisted;
	zsend.sendto_failures += s->state.failures;
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

iterator_t* iterator_init(uint8_t num_threads, uint8_t shard,
			  uint8_t num_shards)
{
	uint64_t num_addrs = blacklist_count_allowed();
	iterator_t *it = xmalloc(sizeof(struct iterator));
	const cyclic_group_t *group = get_group(num_addrs);
	if (num_addrs > (1LL << 32)) {
		zsend.max_index = 0xFFFFFFFF;
	} else {
		zsend.max_index = (uint32_t) num_addrs;
	}
	it->cycle = make_cycle(group, zconf.aes);
	it->num_threads = num_threads;
	it->curr_threads = num_threads;
	it->thread_shards = xcalloc(num_threads, sizeof(shard_t));
	it->complete = xcalloc(it->num_threads, sizeof(uint8_t));
	pthread_mutex_init(&it->mutex, NULL);
	for (uint8_t i = 0; i < num_threads; ++i) {
		shard_init(&it->thread_shards[i],
			   shard,
			   num_shards,
			   i,
			   num_threads,
			   &it->cycle,
			   shard_complete,
			   it
			   );

	}
	zconf.generator = it->cycle.generator;
	return it;
}

uint32_t iterator_get_sent(iterator_t *it)
{
	uint32_t sent = 0;
	for (uint8_t i = 0; i < it->num_threads; ++i) {
		sent += it->thread_shards[i].state.sent;
	}
	return sent;
}

uint32_t iterator_get_tried_sent(iterator_t *it)
{
	uint32_t sent = 0;
	for (uint8_t i = 0; i < it->num_threads; ++i) {
		sent += it->thread_shards[i].state.tried_sent;
	}
	return sent;
}

uint32_t iterator_get_fail(iterator_t *it)
{
	uint32_t fails = 0;
	for (uint8_t i = 0; i < it->num_threads; ++i) {
		fails += it->thread_shards[i].state.failures;
	}
	return fails;
}



shard_t* get_shard(iterator_t *it, uint8_t thread_id)
{
	assert(thread_id < it->num_threads);
	return &it->thread_shards[thread_id];
}

uint32_t iterator_get_curr_send_threads(iterator_t *it)
{
	assert(it);
	return it->curr_threads;
}

