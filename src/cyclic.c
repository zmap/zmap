/*
 * ZMap Copyright 2013 Regents of the University of Michigan 
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

/*
 * cyclic provides an inexpensive approach to iterating over the IPv4 address
 * space in a random(-ish) manner such that we connect to every host once in
 * a scan execution without having to keep track of the IPs that have been
 * scanned or need to be scanned and such that each scan has a different 
 * ordering. We accomplish this by utilizing a cyclic multiplicative group 
 * of integers modulo a prime and generating a new primitive root (generator)
 * for each scan.
 *
 * We know that 3 is a generator of (Z mod 2^32 + 15 - {0}, *) 
 * and that we have coverage over the entire address space because 2**32 + 15
 * is prime and ||(Z mod PRIME - {0}, *)|| == PRIME - 1. Therefore, we
 * just need to find a new generator (primitive root) of the cyclic group for
 * each scan that we perform.
 *
 * Because generators map to generators over an isomorphism, we can efficiently
 * find random primitive roots of our mult. group by finding random generators
 * of the group (Zp-1, +) which is isomorphic to (Zp*, *). Specifically the
 * generators of (Zp-1, +) are { s | (s, p-1) == 1 } which implies that
 * the generators of (Zp*, *) are { d^s | (s, p-1) == 1 }. where d is a known
 * generator of the multiplicative group. We efficiently find
 * generators of the additive group by precalculating the psub1_f of
 * p - 1 and randomly checking random numbers against the psub1_f until
 * we find one that is coprime and map it into Zp*. Because
 * totient(totient(p)) ~= 10^9, this should take relatively few
 * iterations to find a new generator. 
 */

#include "cyclic.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <assert.h>
#include <string.h>
#include <math.h>

#include <gmp.h>

#include "../lib/includes.h"
#include "../lib/xalloc.h"
#include "../lib/logger.h"
#include "../lib/blacklist.h"

#include "state.h"
#include "aesrand.h"

#define LSRC "cyclic"

typedef struct cyclic_group {
	uint64_t prime;
	uint64_t known_primroot;
	size_t num_prime_factors;	// number of unique prime factors of (prime-1)
	uint64_t prime_factors[10];	// unique prime factors of (prime-1)
} cyclic_group_t;

struct cyclic_iterator {
	const cyclic_group_t *group;
	uint64_t prime;
	uint64_t primroot;
	uint64_t num_addrs;
	uint64_t current;
	uint64_t start;
	uint64_t stop;
};

// We will pick the first cyclic group from this list that is
// larger than the number of IPs in our whitelist. E.g. for an
// entire Internet scan, this would be cyclic32
// Note: this list should remain ordered by size (primes) ascending.
static cyclic_group_t groups[] = {
{ // 2^16 + 1
	.prime = 65537,
	.known_primroot = 3,
	.prime_factors = {2},
	.num_prime_factors = 1
},
{ // 2^24 + 43
	.prime = 16777259,
	.known_primroot = 2,
	.prime_factors = {2, 23, 103, 3541},
	.num_prime_factors = 4
},
{ // 2^28 + 3
	.prime = 268435459,
	.known_primroot = 2,
	.prime_factors = {2, 3, 19, 87211},
	.num_prime_factors = 4
},
{ // 2^32 + 15
	.prime = 4294967311,
	.known_primroot = 3,
	.prime_factors = {2, 3, 5, 131, 364289},
	.num_prime_factors = 5
}
};


#define COPRIME 1
#define NOT_COPRIME 0

// check whether two integers are coprime
static int check_coprime(uint64_t check, const cyclic_group_t *group)
{
	for (unsigned i=0; i < group->num_prime_factors; i++) {
		if (group->prime_factors[i] > check && !(group->prime_factors[i] % check)) {
			return NOT_COPRIME;
		} else if (group->prime_factors[i] < check && !(check % group->prime_factors[i])) {
			return NOT_COPRIME;
		} else if (group->prime_factors[i] == check) {
			return NOT_COPRIME;
		}
	}
	return COPRIME;
}

// find gen of cyclic group Z modulo PRIME
static uint64_t find_primroot(const cyclic_group_t *group)
{
	// what luck, rand() returns a uint32_t!
	uint32_t candidate = (uint32_t) aesrand_getword() & 0xFFFFFFFF;
	while(check_coprime(candidate, group) != COPRIME) {
		++candidate;
	}
	// pre-modded result is gigantic so use GMP
	mpz_t base, power, prime, primroot;
	mpz_init_set_d(base, (double) group->known_primroot);
	mpz_init_set_d(power, (double) candidate);
	mpz_init_set_d(prime, (double) group->prime);
	mpz_init(primroot);
	mpz_powm(primroot, base, power, prime);
	uint64_t retv = (uint64_t) mpz_get_ui(primroot);
	mpz_clear(base);
	mpz_clear(power);
	mpz_clear(prime);
	mpz_clear(primroot);
	return retv;
}

static uint64_t find_inverse(uint64_t primroot, uint64_t prime)
{
	// This does the extended Euclidean algorithm
	int64_t a = (int64_t) primroot;
	int64_t b = (int64_t) prime;
	int64_t x = 0LL, y = 1LL, last_x = 1LL, last_y = 0LL, q;
	int64_t temp;
	while (b != 0) {
		q = a / b;
		// (a, b) := (b, a % b)
		temp = b;  
		b = a % b;
		a = temp;
		// (x, last_x) := (last_x - q*x, x)
		temp = x;
		x = last_x - q*x;
		last_x = temp;
		// (y, last_y) := (last_y - q*y, y)       
		temp = y;
		y = last_y - q*y;
		last_y = temp;
	}
	x = last_x;
	y = last_y;
	// Now a*x + b*y = gcd(a, b)
	if (x < 0) {
		x += prime;
	}
	return (uint64_t) x;
}

static uint64_t find_stop_exponent(__attribute__((unused)) uint64_t generator,
				   uint64_t p, uint64_t shard_num,
				   uint64_t num_shards)
{
	// Number of elements in the group
	uint64_t order = p - 1;
	// Greatest Lower Bound on elements in each shard
	uint64_t elts_per_shard = (order / num_shards);
	// Exponent of the last element in this shard
	uint64_t largest_exponent = elts_per_shard * num_shards + shard_num;
	// But we don't want to double count the early elements, so if the extra
	// element in this shard pushed us back around mod p, roll back the exponent
	// by num_shards
	if (largest_exponent > order) {
		largest_exponent -= num_shards;
	}
	return largest_exponent;

}

// Given the first shard starts at begin, find the beginning of
// shard_num (shards are 1-indexed)
uint64_t find_start(uint64_t begin, uint64_t generator, uint64_t p,
		    uint64_t shard_num, 
		    __attribute__((unused)) uint64_t num_shards)
{
	uint64_t start = begin;
	// Tick the starting point forwards by g^(shard_num - 1)
	while (shard_num > 1) {
		start *= generator;
		start %= p;
		--shard_num;
	}
	return start;
}

// Given the first shard starts at begin, find the last element of this
// shard (shards are 1-indexed)
uint64_t find_stop(uint64_t begin, uint64_t generator, uint64_t p,
			  uint64_t shard_num, uint64_t num_shards)
{
	uint64_t stop = begin;
	uint64_t stop_exp = find_stop_exponent(generator, p, shard_num, num_shards);
	uint64_t inverse = find_inverse(generator, p);
	// g^p = g, so given s < p, we need to "go backwards" (p - s) ticks 
	// from g to get g^s
	uint32_t stop_offset = (uint32_t) (p - stop_exp);
	while (stop_offset) {
		stop *= inverse;
		stop %= p;
		--stop_offset;
	}
	return stop;
}

cyclic_iterator_t* cyclic_init(uint32_t primroot_, uint32_t current_)
{
	assert(!(!primroot_ && current_));
	uint64_t num_addrs, primroot, prime = 0, current;
	// Initialize blacklist
	if (blacklist_init(zconf.whitelist_filename, zconf.blacklist_filename,
			zconf.destination_cidrs, zconf.destination_cidrs_len,
			NULL, 0)) {
		return NULL;
	}
	num_addrs = blacklist_count_allowed();
	if (!num_addrs) {
		log_error("blacklist", "no addresses are eligible to be scanned in the "
				"current configuration. This may be because the "
				"blacklist being used by ZMap (%s) prevents "
				"any addresses from receiving probe packets.",
				zconf.blacklist_filename
			);
		exit(EXIT_FAILURE);
	}

	const cyclic_group_t *cur_group = NULL;
	for (uint32_t i=0; i<sizeof(groups)/sizeof(groups[0]); i++) {
		if (groups[i].prime > num_addrs) {
			cur_group = &groups[i];
			log_debug("cyclic", "prime: %lu", 
					cur_group->prime);
			log_debug("cyclic", "known generator: %lu",
					cur_group->known_primroot);

			prime = groups[i].prime;
			break;
		}
	}
	assert(prime);

	if (zconf.use_seed) {
		aesrand_init(zconf.seed+1);
	} else {
		aesrand_init(0);
	}
	if (!primroot_) {
		do {
			primroot = find_primroot(cur_group);
		} while (primroot >= (1LL << 32));
		log_debug(LSRC, "primitive root: %lld", primroot);
		current = (uint32_t) aesrand_getword() & 0xFFFFFFFF;
		log_debug(LSRC, "starting point: %lld", current);
	} else {
		primroot = primroot_;
		log_debug(LSRC, "primitive root %lld specified by caller",
				primroot);
		if (!current_) {
			current = (uint32_t) aesrand_getword() & 0xFFFFFFFF;
			log_debug(LSRC, "no cyclic starting point, "
					 "selected random startpoint: %lld",
					 current);
		} else {
			current = current_;
		    log_debug(LSRC, "starting point %lld specified by caller",
				    current);
		}
	}
	zconf.generator = primroot;
	// make sure current is an allowed ip
	cyclic_iterator_t *cycle = xmalloc(sizeof(cyclic_iterator_t));
	cycle->group = cur_group;
	cycle->prime = prime;
	cycle->primroot = primroot;
	cycle->num_addrs = num_addrs;
	cycle->current = current;
	cyclic_get_next_ip(cycle);

	return cycle;
}

uint32_t cyclic_get_curr_ip(cyclic_iterator_t *cycle)
{
	return (uint32_t) blacklist_lookup_index(cycle->current - 1);
}

uint32_t cyclic_get_primroot(cyclic_iterator_t *cycle)
{
	return (uint32_t) cycle->primroot;
}

static inline uint32_t cyclic_get_next_elem(cyclic_iterator_t *cycle)
{
	do {
		cycle->current *= cycle->primroot;
		cycle->current %= cycle->prime;
	} while (cycle->current >= (1LL << 32));
	return (uint32_t) cycle->current;
}

uint32_t cyclic_get_next_ip(cyclic_iterator_t *cycle)
{
	while (1) {
		uint32_t candidate = cyclic_get_next_elem(cycle);
		if (candidate-1 < cycle->num_addrs) {
			return blacklist_lookup_index(candidate-1);
		}
		zsend.blacklisted++;
	}
}

void cyclic_free(cyclic_iterator_t* c)
{
	if (c) {
		free(c);
	}
}

