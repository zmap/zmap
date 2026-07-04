/*
 * CacheSet Copyright 2026 Jakob Wiesmann
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */
#include "cacheset.h"

#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include <Judy.h>

struct cacheset_s {
	Pvoid_t judy;
	uint64_t *ring;
	size_t maxsize;
	size_t currsize;
	size_t head;
};

cacheset *cacheset_init(size_t maxitems)
{
	assert(maxitems > 0);
	cacheset *retv = malloc(sizeof(cacheset));
	assert(retv);
	memset(retv, 0, sizeof(cacheset));
	retv->ring = calloc(maxitems, sizeof(uint64_t));
	assert(retv->ring);
	retv->maxsize = maxitems;
	retv->currsize = 0;
	retv->head = 0;
	retv->judy = NULL;

	return retv;
}

int cacheset_check(cacheset *cs, uint64_t key)
{
	assert(cs);
	int rc;
	J1T(rc, cs->judy, key);

	return rc;
}

int cacheset_add(cacheset *cs, uint64_t key)
{
	assert(cs);
	int rc;
	J1T(rc, cs->judy, key); // check if key already in set
	if (rc == 1) {
		return 1;
	}

	// check if set is full, if so replace the oldest entry
	if (cs->currsize == cs->maxsize) {
		uint64_t old_key = cs->ring[cs->head];
		J1U(rc, cs->judy, old_key);
		assert(rc == 1);
		cs->currsize--;
	}

	J1S(rc, cs->judy, key);
	assert(rc == 1);
	cs->ring[cs->head] = key;
	cs->head = (cs->head + 1) % cs->maxsize;
	cs->currsize++;

	return 0;
}

void cacheset_free(cacheset *cs)
{
	assert(cs);
	Word_t rc;
	J1FA(rc, cs->judy);
	free(cs->ring);
	free(cs);
}
