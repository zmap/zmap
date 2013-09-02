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

#define MAX_NBITS	32
#define NPRIMFACTORS	5

/*
 * Table of cyclic group parameters, keyed off of bitmask length.
 *
 * TODO: Flesh this out with more granularity below 16 bits.
 */
static const struct group_params {
	int nbits;
	uint64_t prime;		
	int known_primroot;
	uint64_t psub1_f[NPRIMFACTORS];
} group_params[MAX_NBITS+1] = {
	{ 32, 4294967311,	3,	{ 2, 3, 5,  131,  364289 }	},
	{ 31, 2147483713,	5,	{ 2, 3, 11, 251,  4051   }	},
	{ 30, 1073741831,	13,	{ 2, 5, 7,  1901, 8069   }	},
	{ 29, 536870923,	3,	{ 2, 3, 7,  23,   555767 }	},
	{ 28, 268435561,	37,	{ 2, 3, 5,  179,  12497  }	},
	{ 27, 134217781,	17,	{ 2, 3, 5,  179,  12497  }	},
	{ 26, 67109071,		3,	{ 2, 3, 5,  7,    319567 }	},
	{ 25, 33554509,		2,	{ 2, 3, 13, 29,   7417   }	},
	{ 24, 16777381,		7,	{ 2, 3, 5,  19,   14717  }	},
	{ 23, 8388691,		12,	{ 2, 3, 5,  19,   14717  }	},
	{ 22, 4194451,		3,	{ 2, 3, 5,  13,   239    }	},
	{ 21, 2097211,		2,	{ 2, 3, 5,  53,   1319   }	},
	{ 20, 1049011,		2,	{ 2, 3, 5,  73,   479    }	},
	{ 19, 524521,		22,	{ 2, 3, 5,  31,   47     }	},
	{ 18, 262261,		2,	{ 2, 3, 5,  31,   47     }	},
	{ 17, 131101,		17,	{ 2, 3, 5,  19,   23     }	},
	{ 16, 65551,		6,	{ 2, 3, 5,  19,   23	 }	},
	{ 16, 65551,		6,	{ 2, 3, 5,  19,   23	 }	},
	{ 16, 65551,		6,	{ 2, 3, 5,  19,   23	 }	},
	{ 16, 65551,		6,	{ 2, 3, 5,  19,   23	 }	},
	{ 16, 65551,		6,	{ 2, 3, 5,  19,   23	 }	},
	{ 16, 65551,		6,	{ 2, 3, 5,  19,   23	 }	},
	{ 16, 65551,		6,	{ 2, 3, 5,  19,   23	 }	},
	{ 16, 65551,		6,	{ 2, 3, 5,  19,   23	 }	},
	{ 16, 65551,		6,	{ 2, 3, 5,  19,   23	 }	},
	{ 16, 65551,		6,	{ 2, 3, 5,  19,   23	 }	},
	{ 16, 65551,		6,	{ 2, 3, 5,  19,   23	 }	},
	{ 16, 65551,		6,	{ 2, 3, 5,  19,   23	 }	},
	{ 16, 65551,		6,	{ 2, 3, 5,  19,   23	 }	},
	{ 16, 65551,		6,	{ 2, 3, 5,  19,   23	 }	},
	{ 16, 65551,		6,	{ 2, 3, 5,  19,   23	 }	},
	{ 16, 65551,		6,	{ 2, 3, 5,  19,   23	 }	},
	{ 16, 65551,		6,	{ 2, 3, 5,  19,   23	 }	},
};

struct cyclic_info {
	const struct group_params *params;
};

// selected primitive root that we'll use as the generator
static uint64_t primroot = 0;
static uint64_t current = 0;

#define COPRIME 1
#define NOT_COPRIME 0 

// check whether two integers are coprime
static int check_coprime(cyclic_t *cyclic, uint64_t check)
{
	const uint64_t	*psub1_f = cyclic->params->psub1_f;

	for (unsigned i=0; i < NPRIMFACTORS; i++) {
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
static uint64_t find_primroot(cyclic_t *cyclic)
{
	// what luck, rand() returns a uint32_t!
	uint32_t candidate = (uint32_t) aesrand_getword() & 0xFFFF;
	while(check_coprime(cyclic, candidate) != COPRIME) {
		++candidate;
	}
	// pre-modded result is gigantic so use GMP
	mpz_t base, power, prime, primroot;
	mpz_init_set_d(base, (double) cyclic->params->known_primroot);
	mpz_init_set_d(power, (double) candidate);
	mpz_init_set_d(prime, (double) cyclic->params->prime);
	mpz_init(primroot);
	mpz_powm(primroot, base, power, prime);
	uint64_t retv = (uint64_t) mpz_get_ui(primroot);
	mpz_clear(base);
	mpz_clear(power);
	mpz_clear(prime);
	mpz_clear(primroot);
	return retv;
}

cyclic_t *cyclic_init(uint32_t primroot_, uint32_t current_)
{
	cyclic_t *cyclic;

	assert(!(!primroot_ && current_));

	cyclic = calloc(1, sizeof(*cyclic));
	if (!cyclic) {
		log_fatal(LSRC, "could not allocate cyclic info");
	}

	cyclic->params = &group_params[zconf.nbits];

	if (zconf.use_seed) {
		aesrand_init(zconf.seed+1);
	} else {
		aesrand_init(0);
	}
	if (!primroot_) {
		do {
			primroot = find_primroot(cyclic);
		} while (primroot >= (1ULL << cyclic->params->nbits));
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

	// mask off the portion we are scanning
	zconf.startaddr &= ~((1LL << (cyclic->params->nbits)) - 1);

	// make sure current is an allowed ip
	cyclic_get_next_ip(cyclic);

	return cyclic;
}

uint32_t cyclic_get_curr_ip(void)
{
	return (uint32_t) htonl(zconf.startaddr + current);
}

uint32_t cyclic_get_primroot(void)
{
	return (uint32_t) primroot;
}

static inline uint32_t cyclic_get_next_elem(cyclic_t *cyclic)
{
	do {
		current *= primroot;
		current %= cyclic->params->prime;
	} while (current >= (1ULL << cyclic->params->nbits));
	return (uint32_t) current;
}

uint32_t cyclic_get_next_ip(cyclic_t *cyclic)
{
	while (1) {
		uint32_t next_elem = cyclic_get_next_elem(cyclic);
		uint32_t candidate = htonl(zconf.startaddr + next_elem);
		if (!blacklist_is_allowed(candidate)) {
			zsend.blacklisted++;
		} else {
			return candidate;
		}
	}
	return 0;
}

void cyclic_release(cyclic_t *cyclic)
{
	free(cyclic);
}
