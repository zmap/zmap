/*
 * CacheSet Copyright 2026 Jakob Wiesmann
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef CACHESET_H
#define CACHESET_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cacheset_s cacheset;

// initialize new cache set with a maximum capacity.
// returns NULL on alloc failure.
cacheset *cacheset_init(size_t maxitems);

// test whether a given key is in the cache.
// return 1 if present and 0 if not.
int cacheset_check(cacheset *cs, uint64_t key);

// insert a key into the set.
// if the cache is full, the oldest entry is evicted.
// returns 0 if the key was newly inserted, or 1 if the key was already present.
int cacheset_add(cacheset *cs, uint64_t key);

// free memory used by cacheset
void cacheset_free(cacheset *cs);

#ifdef __cplusplus
}
#endif

#endif
