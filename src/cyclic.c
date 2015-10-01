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
#include "../lib/logger.h"

// We will pick the first cyclic group from this list that is
// larger than the number of IPs in our whitelist. E.g. for an
// entire Internet scan, this would be cyclic32
// Note: this list should remain ordered by size (primes) ascending.

static cyclic_group_t groups[] = {
{ // 2^8 + 1
	.prime = 257,
	.known_primroot = 3,
	.prime_factors = {2},
	.num_prime_factors = 1
},
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

// Check whether an integer is coprime with (p - 1)
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

// Return a (random) number coprime with (p - 1) of the group,
// which is a generator of the additive group mod (p - 1)
static uint32_t find_primroot(const cyclic_group_t *group, aesrand_t *aes)
{
	uint32_t candidate = (uint32_t) ((aesrand_getword(aes) & 0xFFFFFFFF) % group->prime);
	if (candidate == 0) {
		++candidate;
	}
	while (check_coprime(candidate, group) != COPRIME) {
		++candidate;
		//special case where we need to restart check from begin
		if(candidate >= group->prime) { 
			candidate = 1;
		}
	}
	uint64_t retv = isomorphism(candidate, group);
	return retv;
}

const cyclic_group_t* get_group(uint64_t min_size)
{
	for(unsigned i = 0; i < sizeof(groups); ++i) {
		if (groups[i].prime > min_size) {
			return &groups[i];
		}
	}
	// Should not reach, final group should always be larger than 2^32
	assert(0);
}

cycle_t make_cycle(const cyclic_group_t* group, aesrand_t *aes)
{
	cycle_t cycle;
	cycle.group = group;
	cycle.generator = find_primroot(group, aes);
	cycle.offset = (uint32_t) (aesrand_getword(aes) & 0xFFFFFFFF);
	cycle.offset %= group->prime;
	return cycle;
}

uint64_t isomorphism(uint64_t additive_elt, const cyclic_group_t* mult_group)
{
	assert(additive_elt < mult_group->prime);
	mpz_t base, power, prime, primroot;
	mpz_init_set_ui(base, mult_group->known_primroot);
	mpz_init_set_ui(power, additive_elt);
	mpz_init_set_ui(prime, mult_group->prime);
	mpz_init(primroot);
	mpz_powm(primroot, base, power, prime);
	uint64_t retv = (uint64_t) mpz_get_ui(primroot);
	log_debug("zmap", "Isomorphism: %llu", retv);
	mpz_clear(base);
	mpz_clear(power);
	mpz_clear(prime);
	mpz_clear(primroot);
	return retv;
}
