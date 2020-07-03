/*
 * Blocklist Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include "blocklist.h"

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
static bl_ll_t *blocklisted_cidrs = NULL;
static bl_ll_t *allowlisted_cidrs = NULL;

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

bl_cidr_node_t *get_blocklisted_cidrs(void) { return blocklisted_cidrs->first; }

bl_cidr_node_t *get_allowlisted_cidrs(void) { return allowlisted_cidrs->first; }

uint32_t blocklist_lookup_index(uint64_t index)
{
	return ntohl(constraint_lookup_index(constraint, index, ADDR_ALLOWED));
}

// check whether a single IP address is allowed to be scanned.
//		1 => is allowed
//		0 => is not allowed
int blocklist_is_allowed(uint32_t s_addr)
{
	return constraint_lookup_ip(constraint, ntohl(s_addr)) == ADDR_ALLOWED;
}

static void _add_constraint(struct in_addr addr, int prefix_len, int value)
{
	constraint_set(constraint, ntohl(addr.s_addr), prefix_len, value);
	if (value == ADDR_ALLOWED) {
		bl_ll_add(allowlisted_cidrs, addr, prefix_len);
	} else if (value == ADDR_DISALLOWED) {
		bl_ll_add(blocklisted_cidrs, addr, prefix_len);
	} else {
		log_fatal("blocklist",
			  "unknown type of blocklist operation specified");
	}
}

// blocklist a CIDR network allocation
// e.g. blocklist_add("128.255.134.0", 24)
void blocklist_prefix(char *ip, int prefix_len)
{
	struct in_addr addr;
	addr.s_addr = inet_addr(ip);
	_add_constraint(addr, prefix_len, ADDR_DISALLOWED);
}

// allowlist a CIDR network allocation
void allowlist_prefix(char *ip, int prefix_len)
{
	struct in_addr addr;
	addr.s_addr = inet_addr(ip);
	_add_constraint(addr, prefix_len, ADDR_ALLOWED);
}

static int init_from_string(char *ip, int value)
{
	int prefix_len = 32;
	char *slash = strchr(ip, '/');
	if (slash) { // split apart network and prefix length
		*slash = '\0';
		char *end;
		char *len = slash + 1;
		errno = 0;
		prefix_len = strtol(len, &end, 10);
		if (end == len || errno != 0 || prefix_len < 0 ||
		    prefix_len > 32) {
			log_fatal("constraint",
				  "'%s' is not a valid prefix length", len);
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
			log_error("constraint",
				  "'%s' is not a valid IP "
				  "address or hostname",
				  ip);
			return -1;
		}
		// Got some addrinfo, let's see what happens
		for (struct addrinfo *aip = res; aip; aip = aip->ai_next) {
			if (aip->ai_family != AF_INET) {
				continue;
			}
			struct sockaddr_in *sa =
			    (struct sockaddr_in *)aip->ai_addr;
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

static int init_from_file(char *file, const char *name, int value,
			  int ignore_invalid_hosts)
{
	FILE *fp;
	char line[1000];

	fp = fopen(file, "r");
	if (fp == NULL) {
		log_fatal(name, "unable to open %s file: %s: %s", name, file,
			  strerror(errno));
	}

	while (fgets(line, sizeof(line), fp) != NULL) {
		char *comment = strchr(line, '#');
		if (comment) {
			*comment = '\0';
		}
		// hostnames can be up to 255 bytes
		char ip[256];
		if ((sscanf(line, "%256s", ip)) == EOF) {
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

static void init_from_array(char **cidrs, size_t len, int value,
			    int ignore_invalid_hosts)
{
	for (int i = 0; i < (int)len; i++) {
		int ret = init_from_string(cidrs[i], value);
		if (ret && !ignore_invalid_hosts) {
			log_fatal("constraint",
				  "Unable to init from CIDR list");
		}
	}
}

uint64_t blocklist_count_allowed(void)
{
	assert(constraint);
	return constraint_count_ips(constraint, ADDR_ALLOWED);
}

uint64_t blocklist_count_not_allowed(void)
{
	assert(constraint);
	return constraint_count_ips(constraint, ADDR_DISALLOWED);
}

// network order
uint32_t blocklist_ip_to_index(uint32_t ip)
{
	assert(constraint);
	uint32_t ip_hostorder = ntohl(ip);
	return constraint_lookup_ip(constraint, ip_hostorder);
}

// Initialize address constraints from allowlist and blocklist files.
// Either can be set to NULL to omit.
int blocklist_init(char *allowlist_filename, char *blocklist_filename,
		   char **allowlist_entries, size_t allowlist_entries_len,
		   char **blocklist_entries, size_t blocklist_entries_len,
		   int ignore_invalid_hosts)
{
	assert(!constraint);

	blocklisted_cidrs = xcalloc(1, sizeof(bl_ll_t));
	allowlisted_cidrs = xcalloc(1, sizeof(bl_ll_t));

	if (allowlist_filename && allowlist_entries) {
		log_warn("allowlist",
			 "both a allowlist file and destination addresses "
			 "were specified. The union of these two sources "
			 "will be utilized.");
	}
	if (allowlist_filename || allowlist_entries_len > 0) {
		// using a allowlist, so default to allowing nothing
		constraint = constraint_init(ADDR_DISALLOWED);
		log_debug("constraint", "blocklisting 0.0.0.0/0");
		if (allowlist_filename) {
			init_from_file(allowlist_filename, "allowlist",
				       ADDR_ALLOWED, ignore_invalid_hosts);
		}
		if (allowlist_entries) {
			init_from_array(allowlist_entries,
					allowlist_entries_len, ADDR_ALLOWED,
					ignore_invalid_hosts);
		}
	} else {
		// no allowlist, so default to allowing everything
		log_debug("blocklist",
			  "no allowlist file or allowlist entries provided");
		constraint = constraint_init(ADDR_ALLOWED);
	}
	if (blocklist_filename) {
		init_from_file(blocklist_filename, "blocklist", ADDR_DISALLOWED,
			       ignore_invalid_hosts);
	}
	if (blocklist_entries) {
		init_from_array(blocklist_entries, blocklist_entries_len,
				ADDR_DISALLOWED, ignore_invalid_hosts);
	}
	init_from_string(strdup("0.0.0.0"), ADDR_DISALLOWED);
	constraint_paint_value(constraint, ADDR_ALLOWED);
	uint64_t allowed = blocklist_count_allowed();
	log_debug("constraint",
		  "%lu addresses (%0.0f%% of address "
		  "space) can be scanned",
		  allowed, allowed * 100. / ((long long int)1 << 32));
	if (!allowed) {
		log_error("blocklist",
			  "no addresses are eligible to be scanned in the "
			  "current configuration. This may be because the "
			  "blocklist being used by ZMap (%s) prevents "
			  "any addresses from receiving probe packets.",
			  blocklist_filename);
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}
