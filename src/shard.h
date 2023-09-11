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
#define ZMAP_SHARD_OK 1

typedef void (*shard_complete_cb)(uint8_t id, void *arg);

typedef struct shard {
	struct shard_state {
		uint64_t packets_sent;
		uint32_t targets_scanned;
		uint32_t max_targets;
		uint32_t max_packets;
		uint32_t packets_failed;
		uint32_t first_scanned;
	} state;
	struct shard_params {
		uint64_t first;
		uint64_t last;
		uint64_t factor;
		uint64_t modulus;
	} params;
	uint64_t current;
	uint64_t iterations;
	uint8_t thread_id;
	uint8_t bits_for_port;
	shard_complete_cb cb;
	void *arg;
} shard_t;

void shard_init(shard_t *shard, uint16_t shard_idx, uint16_t num_shards,
		uint8_t thread_idx, uint8_t num_threads,
		uint32_t max_total_targets, uint8_t bits_for_port,
		const cycle_t *cycle, shard_complete_cb cb, void *arg);

typedef struct target {
	uint32_t ip;
	uint16_t port;
	uint8_t status;
} target_t;

target_t shard_get_cur_target(shard_t *shard);
target_t shard_get_next_target(shard_t *shard);

#endif /* ZMAP_SHARD_H */
