#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../lib/constraint.h"
#include "../lib/logger.h"
#include "../lib/xalloc.h"

//
// Efficient address-space constraints  (AH 7/2013)
//
// This module uses a tree-based representation to efficiently
// manipulate and query constraints on the address space to be
// scanned.  It provides a value for every IP address, and these
// values are applied by setting them for network prefixes.  Order
// matters: setting a value replaces any existing value for that
// prefix or subsets of it.  We use this to implement network
// whitelisting and blacklisting.
//
// Think of setting values in this structure like painting
// subnets with different colors.  We can paint subnets black to
// exclude them and white to allow them.  Only the top color shows.
// This makes for potentially very powerful constraint specifications.
//
// Internally, this is implemented using a binary tree, where each
// node corresponds to a network prefix.  (E.g., the root is
// 0.0.0.0/0, and its children, if present, are 0.0.0.0/1 and
// 128.0.0.0/1.)  Each leaf of the tree stores the value that applies
// to every address within the leaf's portion of the prefix space.
//
// As an optimization, after all values are set, we look up the
// value or subtree for every /16 prefix and cache them as an array.
// This lets subsequent lookups bypass the bottom half of the tree.
//

/*
 * Constraint Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

typedef struct node {
	struct node *l;
	struct node *r;
	value_t value;
	uint64_t count;
} node_t;

// As an optimization, we precompute lookups for every prefix of this
// length:
#define RADIX_LENGTH 20

struct _constraint {
	node_t *root;     // root node of the tree
	uint32_t *radix;  // array of prefixes (/RADIX_LENGTH) that are painted
			  // paint_value
	size_t radix_len; // number of prefixes in radix array
	int painted;      // have we precomputed counts for each node?
	value_t paint_value; // value for which we precomputed counts
};

// Tree operations respect the invariant that every node that isn't a
// leaf has exactly two children.
#define IS_LEAF(node) ((node)->l == NULL)

// Allocate a new leaf with the given value
static node_t *_create_leaf(value_t value)
{
	node_t *node = xmalloc(sizeof(node_t));
	node->l = NULL;
	node->r = NULL;
	node->value = value;
	return node;
}

// Free the subtree rooted at node.
static void _destroy_subtree(node_t *node)
{
	if (node == NULL)
		return;
	_destroy_subtree(node->l);
	_destroy_subtree(node->r);
	free(node);
}

// Convert from an internal node to a leaf.
static void _convert_to_leaf(node_t *node)
{
	assert(node);
	assert(!IS_LEAF(node));
	_destroy_subtree(node->l);
	_destroy_subtree(node->r);
	node->l = NULL;
	node->r = NULL;
}

// Recursive function to set value for a given network prefix within
// the tree.  (Note: prefix must be in host byte order.)
static void _set_recurse(node_t *node, uint32_t prefix, int len, value_t value)
{
	assert(node);
	assert(0 <= len && len <= 256);

	if (len == 0) {
		// We're at the end of the prefix; make this a leaf and set the
		// value.
		if (!IS_LEAF(node)) {
			_convert_to_leaf(node);
		}
		node->value = value;
		return;
	}

	if (IS_LEAF(node)) {
		// We're not at the end of the prefix, but we hit a leaf.
		if (node->value == value) {
			// A larger prefix has the same value, so we're done.
			return;
		}
		// The larger prefix has a different value, so we need to
		// convert it into an internal node and continue processing on
		// one of the leaves.
		node->l = _create_leaf(node->value);
		node->r = _create_leaf(node->value);
	}

	// We're not at the end of the prefix, and we're at an internal
	// node.  Recurse on the left or right subtree.
	if (prefix & 0x80000000) {
		_set_recurse(node->r, prefix << 1, len - 1, value);
	} else {
		_set_recurse(node->l, prefix << 1, len - 1, value);
	}

	// At this point, we're an internal node, and the value is set
	// by one of our children or its descendent.  If both children are
	// leaves with the same value, we can discard them and become a left.
	if (IS_LEAF(node->r) && IS_LEAF(node->l) &&
	    node->r->value == node->l->value) {
		node->value = node->l->value;
		_convert_to_leaf(node);
	}
}

// Set the value for a given network prefix, overwriting any existing
// values on that prefix or subsets of it.
// (Note: prefix must be in host byte order.)
void constraint_set(constraint_t *con, uint32_t prefix, int len, value_t value)
{
	assert(con);
	_set_recurse(con->root, prefix, len, value);
	con->painted = 0;
}

// Return the value pertaining to an address, according to the tree
// starting at given root.  (Note: address must be in host byte order.)
static int _lookup_ip(node_t *root, uint32_t address)
{
	assert(root);
	node_t *node = root;
	uint32_t mask = 0x80000000;
	for (;;) {
		if (IS_LEAF(node)) {
			return node->value;
		}
		if (address & mask) {
			node = node->r;
		} else {
			node = node->l;
		}
		mask >>= 1;
	}
}

// Return the value pertaining to an address.
// (Note: address must be in host byte order.)
value_t constraint_lookup_ip(constraint_t *con, uint32_t address)
{
	assert(con);
	return _lookup_ip(con->root, address);
}

// Return the nth painted IP address.
static int _lookup_index(node_t *root, uint64_t n)
{
	assert(root);
	node_t *node = root;
	uint32_t ip = 0;
	uint32_t mask = 0x80000000;
	for (;;) {
		if (IS_LEAF(node)) {
			return ip | n;
		}
		if (n < node->l->count) {
			node = node->l;
		} else {
			n -= node->l->count;
			node = node->r;
			ip |= mask;
		}
		mask >>= 1;
	}
}

// For a given value, return the IP address with zero-based index n.
// (i.e., if there are three addresses with value 0xFF, looking up index 1
// will return the second one).
// Note that the tree must have been previously painted with this value.
uint32_t constraint_lookup_index(constraint_t *con, uint64_t index,
				 value_t value)
{
	assert(con);
	if (!con->painted || con->paint_value != value) {
		constraint_paint_value(con, value);
	}

	uint64_t radix_idx = index / (1 << (32 - RADIX_LENGTH));
	if (radix_idx < con->radix_len) {
		// Radix lookup
		uint32_t radix_offset =
		    index % (1 << (32 - RADIX_LENGTH)); // TODO: bitwise maths
		return con->radix[radix_idx] | radix_offset;
	}

	// Otherwise, do the "slow" lookup in tree.
	// Note that tree counts do NOT include things in the radix,
	// so we subtract these off here.
	index -= con->radix_len * (1 << (32 - RADIX_LENGTH));
	assert(index < con->root->count);
	return _lookup_index(con->root, index);
}

// Implement count_ips by recursing on halves of the tree.  Size represents
// the number of addresses in a prefix at the current level of the tree.
// If paint is specified, each node will have its count set to the number of
// leaves under it set to value.
// If exclude_radix is specified, the number of addresses will exlcude prefixes
// that are a /RADIX_LENGTH or larger
static uint64_t _count_ips_recurse(node_t *node, value_t value, uint64_t size,
				   int paint, int exclude_radix)
{
	assert(node);
	uint64_t n;
	if (IS_LEAF(node)) {
		if (node->value == value) {
			n = size;
			// Exclude prefixes already included in the radix
			if (exclude_radix &&
			    size >= (1 << (32 - RADIX_LENGTH))) {
				n = 0;
			}
		} else {
			n = 0;
		}
	} else {
		n = _count_ips_recurse(node->l, value, size >> 1, paint,
				       exclude_radix) +
		    _count_ips_recurse(node->r, value, size >> 1, paint,
				       exclude_radix);
	}
	if (paint) {
		node->count = n;
	}
	return n;
}

// Return a node that determines the values for the addresses with
// the given prefix.  This is either the internal node that
// corresponds to the end of the prefix or a leaf node that
// encompasses the prefix. (Note: prefix must be in host byte order.)
static node_t *_lookup_node(node_t *root, uint32_t prefix, int len)
{
	assert(root);
	assert(0 <= len && len <= 32);

	node_t *node = root;
	uint32_t mask = 0x80000000;
	int i;

	for (i = 0; i < len; i++) {
		if (IS_LEAF(node)) {
			return node;
		}
		if (prefix & mask) {
			node = node->r;
		} else {
			node = node->l;
		}
		mask >>= 1;
	}
	return node;
}

// For each node, precompute the count of leaves beneath it set to value.
// Note that the tree can be painted for only one value at a time.
void constraint_paint_value(constraint_t *con, value_t value)
{
	assert(con);
	log_debug("constraint", "Painting value %lu", value);

	// Paint everything except what we will put in radix
	_count_ips_recurse(con->root, value, (uint64_t)1 << 32, 1, 1);

	// Fill in the radix array with a list of addresses
	uint32_t i;
	con->radix_len = 0;
	for (i = 0; i < (1 << RADIX_LENGTH); i++) {
		uint32_t prefix = i << (32 - RADIX_LENGTH);
		node_t *node = _lookup_node(con->root, prefix, RADIX_LENGTH);
		if (IS_LEAF(node) && node->value == value) {
			// Add this prefix to the radix
			con->radix[con->radix_len++] = prefix;
		}
	}
	log_debug("constraint", "%lu IPs in radix array, %lu IPs in tree",
		  con->radix_len * (1 << (32 - RADIX_LENGTH)),
		  con->root->count);
	con->painted = 1;
	con->paint_value = value;
}

// Return the number of addresses that have a given value.
uint64_t constraint_count_ips(constraint_t *con, value_t value)
{
	assert(con);
	if (con->painted && con->paint_value == value) {
		return con->root->count +
		       con->radix_len * (1 << (32 - RADIX_LENGTH));
	} else {
		return _count_ips_recurse(con->root, value, (uint64_t)1 << 32,
					  0, 0);
	}
}

// Initialize the tree.
// All addresses will initially have the given value.
constraint_t *constraint_init(value_t value)
{
	constraint_t *con = xmalloc(sizeof(constraint_t));
	con->root = _create_leaf(value);
	con->radix = xcalloc(sizeof(uint32_t), 1 << RADIX_LENGTH);
	con->painted = 0;
	return con;
}

// Deinitialize and free the tree.
void constraint_free(constraint_t *con)
{
	assert(con);
	log_debug("constraint", "Cleaning up");
	_destroy_subtree(con->root);
	free(con->radix);
	free(con);
}

/*
int main(void)
{
	log_init(stderr, LOG_DEBUG);

	constraint_t *con = constraint_init(0);
	constraint_set(con, ntohl(inet_addr("128.128.0.0")), 1, 22);
	constraint_set(con, ntohl(inet_addr("128.128.0.0")), 1, 1);
	constraint_set(con, ntohl(inet_addr("128.0.0.0")), 1, 1);
	constraint_set(con, ntohl(inet_addr("10.0.0.0")), 24, 1);
	constraint_set(con, ntohl(inet_addr("10.0.0.0")), 24, 0);
	constraint_set(con, ntohl(inet_addr("10.11.12.0")), 24, 1);
	constraint_set(con, ntohl(inet_addr("141.212.0.0")), 16, 0);

	for (int x=1; x < 2; x++) {
		if (x == 1) {
			constraint_optimize(con);
		}

		printf("count(0)=%ld\n", constraint_count_ips(con, 0));
		printf("count(1)=%ld\n", constraint_count_ips(con, 1));
		printf("%d\n",
constraint_lookup_ip(con,ntohl(inet_addr("10.11.12.0"))));
		assert(constraint_count_ips(con, 0) + constraint_count_ips(con,
1) == (uint64_t)1 << 32);

		uint32_t i=0, count=0;
		do {
			if (constraint_lookup_ip(con, i))
	count++;
		} while (++i != 0);
		printf("derived count(1)=%u\n", count);
	}

	constraint_free(con);
}
*/
