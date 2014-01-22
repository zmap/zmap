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
};

void shard_complete(uint8_t thread_id, void *arg)
{
	iterator_t *it = (iterator_t *) arg;
	assert(thread_id < it->num_threads);
	pthread_mutex_lock(&it->mutex);
	it->complete[thread_id] = 1;
	shard_t *s = &it->thread_shards[thread_id];
	zsend.sent += s->state.sent;
	zsend.blacklisted += s->state.blacklisted;
	zsend.targets += s->state.max_targets;
	zsend.sendto_failures += s->state.failures;
	uint8_t done = 1;
	for (uint32_t i = 0; done && (i < it->num_threads); ++i) {
		done = done && it->complete[i];
	}
	if (done) {
		zsend.complete = 1;
		zsend.finish = now();
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
	it->cycle = make_cycle(group);
	it->num_threads = num_threads;
	it->thread_shards = xcalloc(num_threads, sizeof(shard_t));
	it->complete = xcalloc(it->num_threads, sizeof(uint8_t));
	pthread_mutex_init(&it->mutex, NULL);
	for (uint32_t i = 0; i < num_threads; ++i) {
		shard_init(it->thread_shards + i,
			   shard,
			   num_shards,
			   i,
			   num_threads,
			   &it->cycle,
			   shard_complete,
			   it
			   );

	}
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

shard_t* get_shard(iterator_t *it, uint8_t thread_id)
{
	assert(thread_id < it->num_threads);
	return &it->thread_shards[thread_id];
}
