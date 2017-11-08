/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef ZMAP_SHARD_H
#define ZMAP_SHARD_H

#include <stdint.h>

#include "cyclic.h"

#define ZMAP_SHARD_DONE 0

typedef void (*shard_complete_cb)(uint8_t id, void *arg);

typedef struct shard {
	struct shard_state {
		uint32_t sent;
		uint32_t tried_sent;
		uint32_t blacklisted;
		uint32_t whitelisted;
		uint32_t failures;
		uint32_t first_scanned;
		uint32_t max_targets;
	} state;
	struct shard_params {
		uint64_t first;
		uint64_t last;
		uint64_t factor;
		uint64_t modulus;
	} params;
	uint64_t current;
	uint8_t thread_id;
	shard_complete_cb cb;
	void *arg;
} shard_t;

void shard_init(shard_t *shard, uint16_t shard_idx, uint16_t num_shards,
		uint8_t thread_idx, uint8_t num_threads,
		uint32_t max_total_targets, const cycle_t *cycle,
		shard_complete_cb cb, void *arg);

uint32_t shard_get_cur_ip(shard_t *shard);
uint32_t shard_get_next_ip(shard_t *shard);

#endif /* ZMAP_SHARD_H */
