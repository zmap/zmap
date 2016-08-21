/*
 * Blacklist Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include "blacklist.h"

#include <errno.h>
#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "constraint.h"
#include "logger.h"
#include "xalloc.h"

#define ADDR_DISALLOWED 0
#define ADDR_ALLOWED 1

typedef struct bl_linked_list {
		bl_cidr_node_t *first;
		bl_cidr_node_t *last;
		uint32_t len;
} bl_ll_t;

static constraint_t *constraint = NULL;

// keep track of the prefixes we've tried to BL/WL
// for logging purposes
static bl_ll_t *blacklisted_cidrs = NULL;
static bl_ll_t *whitelisted_cidrs = NULL;

void bl_ll_add(bl_ll_t *l, struct in_addr addr, uint16_t p)
{
	assert(l);
	bl_cidr_node_t *new = xmalloc(sizeof(bl_cidr_node_t));
	new->next = NULL;
	new->ip_address = addr.s_addr;
	new->prefix_len = p;
	if (!l->first) {
			l->first = new;
	} else {
			l->last->next = new;
	}
	l->last = new;
	l->len++;
}

bl_cidr_node_t *get_blacklisted_cidrs(void)
{
	return blacklisted_cidrs->first;
}

bl_cidr_node_t *get_whitelisted_cidrs(void)
{
	return whitelisted_cidrs->first;
}


uint32_t blacklist_lookup_index(uint64_t index) {
	return ntohl(constraint_lookup_index(constraint, index, ADDR_ALLOWED));
}

// check whether a single IP address is allowed to be scanned.
//		1 => is allowed
//		0 => is not allowed
int blacklist_is_allowed(uint32_t s_addr) {
	return constraint_lookup_ip(constraint, ntohl(s_addr)) == ADDR_ALLOWED;
}

static void _add_constraint(struct in_addr addr, int prefix_len, int value)
{
	constraint_set(constraint, ntohl(addr.s_addr), prefix_len, value);
	if (value == ADDR_ALLOWED) {
		bl_ll_add(whitelisted_cidrs, addr, prefix_len);
	} else if (value == ADDR_DISALLOWED) {
		bl_ll_add(blacklisted_cidrs, addr, prefix_len);
	} else {
		log_fatal("blacklist", "unknown type of blacklist operation specified");
	}
}

// blacklist a CIDR network allocation
// e.g. blacklist_add("128.255.134.0", 24)
void blacklist_prefix(char *ip, int prefix_len)
{
	struct in_addr addr;
	addr.s_addr = inet_addr(ip);
	_add_constraint(addr, prefix_len, ADDR_DISALLOWED);
}

// whitelist a CIDR network allocation
void whitelist_prefix(char *ip, int prefix_len)
{
	struct in_addr addr;
	addr.s_addr = inet_addr(ip);
	_add_constraint(addr, prefix_len, ADDR_ALLOWED);
}

static int init_from_string(char *ip, int value)
{
	int prefix_len = 32;
	char *slash = strchr(ip, '/');
	if (slash) {  // split apart network and prefix length
		*slash = '\0';
		char *end;
		char *len = slash+1;
		errno = 0;
		prefix_len = strtol(len, &end, 10);
		if (end == len || errno != 0 || prefix_len < 0 || prefix_len > 32) {
			log_fatal("constraint", "'%s' is not a valid prefix length", len);
			return -1;
		}
	}
	struct in_addr addr;
	int ret = -1;
	if (inet_aton(ip, &addr) == 0) {
		// Not an IP and not a CIDR block, try dns resolution
		struct addrinfo hint, *res;
		memset(&hint, 0, sizeof(hint));
		hint.ai_family = PF_INET;
		int r = getaddrinfo(ip, NULL, &hint, &res);
		if (r) {
			log_error("constraint", "'%s' is not a valid IP "
				  "address or hostname", ip);
			return -1;
		}
		// Got some addrinfo, let's see what happens
		for (struct addrinfo *aip = res; aip; aip = aip->ai_next) {
			if (aip->ai_family != AF_INET) {
				continue;
			}
			struct sockaddr_in *sa = (struct sockaddr_in *) aip->ai_addr;
			memcpy(&addr, &sa->sin_addr, sizeof(addr));
			log_debug("constraint", "%s retrieved by hostname",
				  inet_ntoa(addr));
			ret = 0;
			_add_constraint(addr, prefix_len, value);
		}
	} else {
		_add_constraint(addr, prefix_len, value);
		return 0;
	}
	return ret;
}

static int init_from_file(char *file, const char *name, int value, int ignore_invalid_hosts)
{
	FILE *fp;
	char line[1000];

	fp = fopen(file, "r");
	if (fp == NULL) {
		log_fatal(name, "unable to open %s file: %s: %s",
				name, file, strerror(errno));
	}

	while (fgets(line, sizeof(line), fp) != NULL) {
		char *comment = strchr(line, '#');
		if (comment) {
			*comment = '\0';
		}
		char ip[33];
		if ((sscanf(line, "%32s", ip)) == EOF) {
			continue;
		}
		if (init_from_string(ip, value)) {
			if (!ignore_invalid_hosts) {
				log_fatal(name, "unable to parse %s file: %s",
						name, file);
			}
		}
	}
	fclose(fp);

	return 0;
}

static void init_from_array(char **cidrs, size_t len, int value, int ignore_invalid_hosts)
{
	for (int i=0; i < (int) len; i++) {
		int ret = init_from_string(cidrs[i], value);
				if (ret && !ignore_invalid_hosts) {
					log_fatal("constraint",
							"Unable to init from CIDR list");
				}
	}
}

uint64_t blacklist_count_allowed(void)
{
	assert(constraint);
	return constraint_count_ips(constraint, ADDR_ALLOWED);
}

uint64_t blacklist_count_not_allowed(void)
{
	assert(constraint);
	return constraint_count_ips(constraint, ADDR_DISALLOWED);
}

// network order
uint32_t blacklist_ip_to_index(uint32_t ip)
{
	assert(constraint);
	uint32_t ip_hostorder = ntohl(ip);
	return constraint_lookup_ip(constraint, ip_hostorder);
}


// Initialize address constraints from whitelist and blacklist files.
// Either can be set to NULL to omit.
int blacklist_init(char *whitelist_filename, char *blacklist_filename,
		char **whitelist_entries, size_t whitelist_entries_len,
		char **blacklist_entries, size_t blacklist_entries_len,
		int ignore_invalid_hosts)
{
	assert(!constraint);

	blacklisted_cidrs = xcalloc(1, sizeof(bl_ll_t));
	whitelisted_cidrs = xcalloc(1, sizeof(bl_ll_t));

	if (whitelist_filename && whitelist_entries) {
		log_warn("whitelist", "both a whitelist file and destination addresses "
					"were specified. The union of these two sources "
					"will be utilized.");
	}
	if (whitelist_filename || whitelist_entries_len > 0) {
		// using a whitelist, so default to allowing nothing
		constraint = constraint_init(ADDR_DISALLOWED);
		log_debug("constraint", "blacklisting 0.0.0.0/0");
		if (whitelist_filename) {
			init_from_file(whitelist_filename, "whitelist", ADDR_ALLOWED,
					ignore_invalid_hosts);
		}
		if (whitelist_entries) {
			init_from_array(whitelist_entries,
					whitelist_entries_len, ADDR_ALLOWED,
					ignore_invalid_hosts);
		}
	} else {
		// no whitelist, so default to allowing everything
		log_debug("blacklist", "no whitelist file or whitelist entries provided");
		constraint = constraint_init(ADDR_ALLOWED);
	}
	if (blacklist_filename) {
		init_from_file(blacklist_filename, "blacklist",
				ADDR_DISALLOWED, ignore_invalid_hosts);
	}
	if (blacklist_entries) {
		init_from_array(blacklist_entries,
				blacklist_entries_len, ADDR_DISALLOWED,
				ignore_invalid_hosts);
	}
	init_from_string(strdup("0.0.0.0"), ADDR_DISALLOWED);
	constraint_paint_value(constraint, ADDR_ALLOWED);
	uint64_t allowed = blacklist_count_allowed();
	log_debug("constraint", "%lu addresses (%0.0f%% of address "
			"space) can be scanned",
			allowed, allowed*100./((long long int)1 << 32));
	if (!allowed) {
		log_error("blacklist", "no addresses are eligible to be scanned in the "
			  "current configuration. This may be because the "
			  "blacklist being used by ZMap (%s) prevents "
			  "any addresses from receiving probe packets.",
			  blacklist_filename
			);
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

