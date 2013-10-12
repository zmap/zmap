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
#include "constraint.h"
#include "logger.h"

#define ADDR_DISALLOWED 0
#define ADDR_ALLOWED 1

static constraint_t *constraint = NULL;

uint32_t blacklist_lookup_index(uint64_t index) {
	return ntohl(constraint_lookup_index(constraint, index, ADDR_ALLOWED));
}

// check whether a single IP address is allowed to be scanned.
//		1 => is allowed
//		0 => is not allowed
int blacklist_is_allowed(uint32_t s_addr) {
	return constraint_lookup_ip(constraint, ntohl(s_addr)) == ADDR_ALLOWED;
}

// blacklist a CIDR network allocation
// e.g. blacklist_add("128.255.134.0", 24)
void blacklist_prefix(char *ip, int prefix_len)
{
	assert(constraint);
	constraint_set(constraint, ntohl(inet_addr(ip)), prefix_len, ADDR_DISALLOWED);
}

// whitelist a CIDR network allocation
void whitelist_prefix(char *ip, int prefix_len)
{
	assert(constraint);
	constraint_set(constraint, ntohl(inet_addr(ip)), prefix_len, ADDR_ALLOWED);
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
	if (inet_aton(ip, &addr) == 0) {
		log_error("constraint", "'%s' is not a valid IP address", ip);
		return -1;
	}
	constraint_set(constraint, ntohl(addr.s_addr), prefix_len, value);
	const char *name;
	if (value == ADDR_DISALLOWED)
		name = "blacklisting";
	else
		name = "whitelisting";
	log_trace(name, "%s %s/%i",
			  name, ip, prefix_len);
	return 0;
}


static int init_from_file(char *file, const char *name, int value)
{
	FILE *fp;
	char line[1000];

	fp = fopen(file, "r");
	if (fp == NULL) {
		log_fatal(name, "Unable to open %s file: %s: %s", name, file, strerror(errno));
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
			log_fatal(name, "unable to parse %s file: %s", name, file);
		}
	}
	fclose(fp);

	return 0;
}

static void init_from_array(char **cidrs, size_t len, int value)
{
	for (int i=0; i < (int) len; i++) {
		init_from_string(cidrs[i], value);
	}
}

uint64_t blacklist_count_allowed()
{
	assert(constraint);
	return constraint_count_ips(constraint, ADDR_ALLOWED);
}

uint64_t blacklist_count_not_allowed()
{
	assert(constraint);
	return constraint_count_ips(constraint, ADDR_DISALLOWED);
}

// Initialize address constraints from whitelist and blacklist files.
// Either can be set to NULL to omit.
int blacklist_init(char *whitelist_filename, char *blacklist_filename,
		char **whitelist_entries, size_t whitelist_entries_len,
		char **blacklist_entries, size_t blacklist_entries_len)
{
	assert(!constraint);
	if (whitelist_filename && whitelist_entries) {
		log_warn("whitelist", "both a whitelist file and destination addresses "
					"were specified. The union of these two sources "
					"will be utilized.");
	}
	if (whitelist_filename || whitelist_entries) {
		// using a whitelist, so default to allowing nothing
		constraint = constraint_init(ADDR_DISALLOWED);
		log_trace("whitelist", "blacklisting 0.0.0.0/0");
		if (whitelist_filename) {
			init_from_file(whitelist_filename, "whitelist", ADDR_ALLOWED);
		}
		if (whitelist_entries) {
			init_from_array(whitelist_entries,
					whitelist_entries_len, ADDR_ALLOWED);
		}
	} else {
		// no whitelist, so default to allowing everything
		constraint = constraint_init(ADDR_ALLOWED);
	}
	if (blacklist_filename) {
		init_from_file(blacklist_filename, "blacklist", ADDR_DISALLOWED);
	}
	if (blacklist_entries) {
		init_from_array(blacklist_entries, blacklist_entries_len, ADDR_DISALLOWED);
	}
	constraint_paint_value(constraint, ADDR_ALLOWED);
	uint64_t allowed = blacklist_count_allowed();
	log_debug("blacklist", "%lu addresses allowed to be scanned (%0.0f%% of address space)", 
			  allowed, allowed*100./((long long int)1 << 32));
	return EXIT_SUCCESS;
}

