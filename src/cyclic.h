/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef CYCLIC_H
#define CYCLIC_H

#include <stdint.h>
#include <stddef.h>

#include "aesrand.h"

// Represents a multiplicative cyclic group (Z/pZ)*
typedef struct cyclic_group {
	uint64_t prime;			// p
	uint64_t known_primroot;	// Known primitive root of (Z/pZ)*
	size_t num_prime_factors;	// Length of num_prime_factors
	uint64_t prime_factors[10];	// Unique prime factors of (p-1)
} cyclic_group_t;

// Represents a cycle in a group
typedef struct cycle {
	const cyclic_group_t* group;
	uint64_t generator;
	uint32_t offset;
} cycle_t;

// Get a cyclic_group_t of at least min_size.
// Pointer into static data, do not free().
const cyclic_group_t* get_group(uint64_t min_size);

// Generate cycle (find generator and inverse)
cycle_t make_cycle(const cyclic_group_t* group, aesrand_t *aes);

// Perform the isomorphism from (Z/pZ)+ to (Z/pZ)*
// Given known primitive root of (Z/pZ)* n, with x in (Z/pZ)+, do:
//	f(x) = n^x mod p
//
// The isomorphism in the reverse direction is discrete log, and is
// therefore hard.
uint64_t isomorphism(uint64_t additive_elt, const cyclic_group_t* mult_group);

#endif
