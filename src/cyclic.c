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

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <gmp.h>

#include "../lib/logger.h"
#include "../lib/blacklist.h"

#include "state.h"
#include "aesrand.h"

#define LSRC "cyclic"
#define PRIME 4294967311 // 2^32 + 15
#define KNOWN_PRIMROOT 3

// distinct prime factors of 2^32 + 15
static const uint64_t psub1_f[] = { 2, 3, 5, 131, 364289 }; 

// selected primitive root that we'll use as the generator
static uint64_t primroot = 0;
static uint64_t current = 0;

static uint64_t num_addrs = 0;

#define COPRIME 1
#define NOT_COPRIME 0

// check whether two integers are coprime
static int check_coprime(uint64_t check)
{
	for (unsigned i=0; i < sizeof(psub1_f)/sizeof(psub1_f[0]); i++) {
		if (psub1_f[i] > check && !(psub1_f[i] % check)) {
			return NOT_COPRIME;
		} else if (psub1_f[i] < check && !(check % psub1_f[i])) {
			return NOT_COPRIME;
		} else if (psub1_f[i] == check) {
			return NOT_COPRIME;
		}
	}
	return COPRIME;
}

// find gen of cyclic group Z modulo PRIME
static uint64_t find_primroot(void)
{
	// what luck, rand() returns a uint32_t!
	uint32_t candidate = (uint32_t) aesrand_getword() & 0xFFFF;
	while(check_coprime(candidate) != COPRIME) {
		++candidate;
	}
	// pre-modded result is gigantic so use GMP
	mpz_t base, power, prime, primroot;
	mpz_init_set_d(base, (double) KNOWN_PRIMROOT);
	mpz_init_set_d(power, (double) candidate);
	mpz_init_set_d(prime, (double) PRIME);
	mpz_init(primroot);
	mpz_powm(primroot, base, power, prime);
	uint64_t retv = (uint64_t) mpz_get_ui(primroot);
	mpz_clear(base);
	mpz_clear(power);
	mpz_clear(prime);
	mpz_clear(primroot);
	return retv;
}

int cyclic_init(uint32_t primroot_, uint32_t current_)
{
	assert(!(!primroot_ && current_));

	if (zconf.use_seed) {
		aesrand_init(zconf.seed+1);
	} else {
		aesrand_init(0);
	}
	if (!primroot_) {
		do {
			primroot = find_primroot();
		} while (primroot >= (1LL << 32));
		log_debug(LSRC, "primitive root: %lld", primroot);
		current = (uint32_t) aesrand_getword() & 0xFFFF;
		log_debug(LSRC, "starting point: %lld", current);
	} else {
		primroot = primroot_;
		log_debug(LSRC, "primitive root %lld specified by caller",
				primroot);
		if (!current_) {
			current = (uint32_t) aesrand_getword() & 0xFFFF;
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
	if (blacklist_init_from_files(zconf.whitelist_filename,
							zconf.blacklist_filename)) {
	  return -1;
	}

	num_addrs = blacklist_count_allowed();
	// make sure current is an allowed ip
	cyclic_get_next_ip();

	return 0;
}

uint32_t cyclic_get_curr_ip(void)
{
	return (uint32_t) blacklist_lookup_index(current);
}

uint32_t cyclic_get_primroot(void)
{
	return (uint32_t) primroot;
}

static inline uint32_t cyclic_get_next_elem(void)
{
	do {
		current *= primroot;
		current %= PRIME;
	} while (current >= (1LL << 32));
	return (uint32_t) current;
}

uint32_t cyclic_get_next_ip(void)
{
	while (1) {
		uint32_t candidate = cyclic_get_next_elem();
		if (candidate < num_addrs) {
			return blacklist_lookup_index(candidate);
		}
		zsend.blacklisted++;
	}
}

