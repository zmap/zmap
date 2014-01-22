#ifndef ZMAP_ITERATOR_H
#define ZMAP_ITERATOR_H

#include <stdint.h>

#include "../lib/includes.h"

#include "cyclic.h"
#include "shard.h"

typedef struct iterator iterator_t;

iterator_t* iterator_init(uint8_t num_threads, uint8_t shard,
			  uint8_t num_shards);

uint32_t iterator_get_sent(iterator_t *it);

shard_t* get_shard(iterator_t *it, uint8_t thread_id);

#endif /* ZMAP_ITERATOR_H */
