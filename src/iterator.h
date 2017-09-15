/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef ZMAP_ITERATOR_H
#define ZMAP_ITERATOR_H

#include <stdint.h>

#include "../lib/includes.h"

#include "aesrand.h"
#include "cyclic.h"
#include "shard.h"

typedef struct iterator iterator_t;

iterator_t *iterator_init(uint8_t num_threads, uint16_t shard,
			  uint16_t num_shards);

uint32_t iterator_get_sent(iterator_t *it);
uint32_t iterator_get_tried_sent(iterator_t *it);
uint32_t iterator_get_fail(iterator_t *it);

uint32_t iterator_get_curr_send_threads(iterator_t *it);

shard_t *get_shard(iterator_t *it, uint8_t thread_id);

#endif /* ZMAP_ITERATOR_H */
