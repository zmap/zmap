/*
 * CacheHash Copyright 2014 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include "cachehash.h"

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include <Judy.h>

#define EVICTION_NEEDED 1
#define EVICTION_UNNEC 0

// doubly-linked-list node
typedef struct node {
	struct node *next;
	struct node *prev;
	void *key;
	size_t keylen;
	void *data;
} node_t;

// data structure that contains the enterity of a linked list
// we typedef this as cachehash in cachehash.h s.t. external interface is clean
struct cachehash_s {
	Pvoid_t judy;
	void *malloced;
	node_t *start;
	node_t *end;
	node_t *curr_end;
	size_t maxsize;
	size_t currsize;
	cachehash_process_cb *evict_cb;
};

cachehash *cachehash_init(size_t maxitems, cachehash_process_cb *cb)
{
	assert(maxitems > 0);
	cachehash *retv = malloc(sizeof(cachehash));
	assert(retv);
	memset(retv, 0, sizeof(cachehash));
	// allocate nodes all at once to avoid fragmented memory
	node_t *nodes = calloc(maxitems, sizeof(node_t));
	retv->malloced = nodes;
	assert(nodes);
	retv->start = nodes;
	retv->curr_end = nodes;
	retv->end = &nodes[maxitems - 1];
	retv->maxsize = maxitems;
	retv->currsize = 0;
	// initial node
	nodes[0].next = &nodes[1];
	// middle nodes
	for (unsigned int i = 1; i < maxitems - 1; i++) {
		nodes[i].prev = &nodes[i - 1];
		nodes[i].next = &nodes[i + 1];
	}
	// last node
	nodes[maxitems - 1].prev = &nodes[maxitems - 2];
	retv->evict_cb = cb;
	return retv;
}

void cachehash_set_evict_cb(cachehash *ch, cachehash_process_cb *cb)
{
	ch->evict_cb = cb;
}

// is the hashcache full?
static inline int eviction_needed(cachehash *ch)
{
	assert(ch);
	return ch->currsize == ch->maxsize;
}

// completely evict the LRU object
// does not cb to user w/ object
static inline void *evict(cachehash *ch)
{

	assert(ch);
	node_t *last = ch->end;
	// remove item from judy array
	int rc;
	JHSD(rc, ch->judy, last->key, last->keylen);
	// we should never end up with something in the linked list
	// that's not in the judy array.
	assert(rc);
	// reset linked list node
	void *retv = last->data;
	last->data = NULL;
	free(last->key);
	last->key = NULL;
	last->keylen = 0;
	ch->currsize--;
	ch->curr_end = ch->end;
	return retv;
}

static inline void use(cachehash *ch, node_t *n)
{

	assert(ch);
	assert(n);
	//if first node, nothing to do and return
	if (n == ch->start) {
		return;
	}
	// remove from current spot in linked list
	node_t *prev = n->prev;
	n->prev->next = n->next;
	// if last node then no next, but must update LL
	if (n->next) {
		n->next->prev = prev;
	} else {
		ch->end = prev;
	}
	// front of list
	n->next = ch->start;
	ch->start->prev = n;
	ch->start = n;
	n->prev = NULL;
}

static inline node_t *judy_get(cachehash *ch, void *key, size_t keylen)
{
	assert(ch);
	assert(key);
	assert(keylen);
	Word_t *v_;
	JHSG(v_, ch->judy, key, keylen);
	if (!v_) {
		return NULL;
	}
	return (node_t *)*v_;
}

void *cachehash_has(cachehash *ch, const void *key, size_t keylen)
{
	assert(ch);
	assert(key);
	assert(keylen);
	node_t *n = judy_get(ch, (void *)key, keylen);
	if (n) {
		return n->data;
	} else {
		return NULL;
	}
}

void *cachehash_get(cachehash *ch, const void *key, size_t keylen)
{
	assert(ch);
	assert(key);
	assert(keylen);

	node_t *n = judy_get(ch, (void *)key, keylen);
	if (n) {
		use(ch, n);
		return n->data;
	} else {
		return NULL;
	}
}

void *cachehash_evict_if_full(cachehash *ch)
{
	assert(ch);
	if (eviction_needed(ch) == EVICTION_UNNEC) {
		return NULL;
	}
	return evict(ch);
}

void cachehash_put(cachehash *ch, const void *key, size_t keylen, void *value)
{
	assert(ch);
	assert(key);
	assert(keylen);

	void *evicted = cachehash_evict_if_full(ch);
	if (evicted && ch->evict_cb) {
		ch->evict_cb(evicted);
		ch->curr_end = ch->end;
	}
	// create new node

	node_t *n;
	void *newkey = malloc(keylen);
	n = ch->curr_end;
	memcpy(newkey, key, keylen);

	n->key = newkey;
	n->keylen = keylen;
	n->data = value;
	//n->prev = ch->curr_end->prev;
	//n->next = ch->curr_end->next;

	if (ch->curr_end != ch->end) {
		ch->curr_end = ch->curr_end->next;
		ch->curr_end->prev = n;
	}

	use(ch, n);
	ch->currsize++;
	// add to judy array
	Word_t *v_;
	JHSI(v_, ch->judy, (void *)key, keylen);
	// key should not already be in hash table
	assert(!*v_);
	*v_ = (Word_t)n;
}

// print out entire state.
void cachehash_debug_dump(cachehash *ch)
{
	printf("Statistics:\n");
	printf("\tcurrent size: %lu\n", ch->currsize);
	printf("\tmaximum size: %lu\n", ch->maxsize);
	printf("\n");
	printf("Linked List:\n");
	size_t i = 0;
	node_t *n = ch->start;

	do {
		if (n->key) {
			printf("\t%lu: %s -> %s\n", i++, (char *)n->key,
			       (char *)n->data);
		} else {
			printf("\t%lu: EMPTY\n", i++);
		}
		n = n->next;
	} while (n);
}

void cachehash_free(cachehash *ch, cachehash_process_cb *cb)
{
	assert(ch);
	int rc;
	JHSFA(rc, ch->judy);
	node_t *n = ch->start;
	do {
		if (n->key) {
			free(n->key);
			if (cb) {
				cb(n->data);
			}
		}
		n = n->next;
	} while (n);
	free(ch->malloced);
	free(ch);
}

void cachehash_iter(cachehash *ch, cachehash_process_cb *cb)
{
	node_t *n = ch->start;
	do {
		if (n->key) {
			cb(n->data);
		} else {
			break;
		}
		n = n->next;
	} while (n);
}
