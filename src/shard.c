/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include <stdint.h>
#include <assert.h>

#include <gmp.h>

#include "../lib/includes.h"
#include "../lib/blacklist.h"
#include "shard.h"
#include "state.h"

void shard_init(shard_t* shard,
		uint8_t shard_id,
		uint8_t num_shards,
		uint8_t sub_id,
		uint8_t num_subshards,
		const cycle_t* cycle,
		shard_complete_cb cb,
		void *arg)
{
	// Start out by figuring out the multiplication factor for this shard.
	// With one shard, this would just be the generator, but with n shards,
	// f = g^n.

	// Then on top of that, we want to shard internally (subshards) per
	// thread. With t threads, f = g^(nr).
	//
	// tot_shards = nr
	uint32_t tot_shards = (uint32_t) num_shards * (uint32_t) num_subshards;
	uint64_t num_elts = cycle->group->prime - 1;
	mpz_t start, generator, prime, result, power;
	mpz_init_set_ui(start, cycle->offset);
	mpz_init_set_ui(generator, cycle->generator);
	mpz_init_set_ui(power, tot_shards);
	mpz_init_set_ui(prime, cycle->group->prime);
	mpz_init(result);
	mpz_powm(result, generator, power, prime);
	shard->params.factor = (uint64_t) mpz_get_ui(result);
	shard->params.modulus = cycle->group->prime;

	// e = p - 1 = num_elts
	// begin_idx = s + tr
	// end_idx = [e - (e % nr) + (s + tr)] % e
	//         = [e - (e % nr) + begin_idx] % e
	uint64_t begin_idx = shard_id + sub_id*num_shards;
	uint64_t end_idx = (num_elts - (num_elts % tot_shards) + begin_idx) % num_elts;
	if (end_idx >= tot_shards) {
		end_idx += tot_shards;
		end_idx %= num_elts;
	}
	mpz_powm_ui(result, generator, begin_idx + 1, prime);
	shard->params.first = (uint64_t) mpz_get_ui(result);
	shard->params.first *= cycle->offset;
	shard->params.first %= shard->params.modulus;
	mpz_powm_ui(result, generator, end_idx + 1, prime);
	shard->params.last = (uint64_t) mpz_get_ui(result);
	shard->params.last *= cycle->offset;
	shard->params.last %= shard->params.modulus;
	shard->current = shard->params.first;
	// Handle scanning a sample
	if (zsend.targets != zsend.max_index) {
		shard->state.max_targets = zsend.targets / num_subshards;
		uint32_t leftover = zsend.targets % num_subshards;
		if (leftover > sub_id) {
			shard->state.max_targets++;
		}
	} else {
		shard->state.max_targets = zsend.targets;
	}


	// Set the (thread) id
	shard->id = sub_id;

	// Set the callbacks
	shard->cb = cb;
	shard->arg = arg;

	if (shard->current - 1 >= zsend.max_index) {
		shard_get_next_ip(shard);
	}

	// Clear everything
	mpz_clear(start);
	mpz_clear(generator);
	mpz_clear(prime);
	mpz_clear(power);
	mpz_clear(result);
}

uint32_t shard_get_cur_ip(shard_t *shard)
{
	return (uint32_t) blacklist_lookup_index(shard->current - 1);
}

static inline uint32_t shard_get_next_elem(shard_t *shard)
{
	do {
		shard->current *= shard->params.factor;
		shard->current %= shard->params.modulus;
	} while (shard->current >= (1LL << 32));
	return (uint32_t) shard->current;
}

uint32_t shard_get_next_ip(shard_t *shard)
{
	while (1) {
		uint32_t candidate = shard_get_next_elem(shard);
		if (candidate == shard->params.last) {
			return 0;
		}
		if (candidate - 1 < zsend.max_index) {
			shard->state.whitelisted++;
			return blacklist_lookup_index(candidate - 1);
		}
		shard->state.blacklisted++;
	}
}
