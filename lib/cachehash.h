/*
 * CacheHash Copyright 2014 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef CACHEHASH_H
#define CACHEHASH_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cachehash_s cachehash;
// function defintion for cachehash callbacks
typedef void (cachehash_process_cb)(void *data);
// initialize new cache hash
cachehash* cachehash_init(size_t maxitems, cachehash_process_cb *cb);
// return item from cachehash without changing its location in LL
void* cachehash_has(cachehash *ch, const void *key, size_t keylen);
// return item from cachehash and move to front
void* cachehash_get(cachehash *ch, const void *key, size_t keylen);
// add item to the cachehash
void cachehash_put(cachehash *ch, const void *key, size_t keylen, void *value);
// free memory used by a cachehash. unusable until new initialization
void cachehash_free(cachehash *ch, cachehash_process_cb *cb);
// evict the LRU if the cachehash is full
void* cachehash_evict_if_full(cachehash *ch);
// iterate over all values in the cache hash in MRU -> LRU order
void cachehash_iter(cachehash *ch, cachehash_process_cb *cb);
// print out hash cache to stdout assuming that all keys and values
// are null-terminated ASCII strings
void cachehash_debug_dump(cachehash *ch);
// change the callback function for the cachehash
void cachehash_set_evict_cb(cachehash *ch, cachehash_process_cb *cb);

#ifdef __cplusplus
}
#endif

#endif /* CACHEHASH_H */

