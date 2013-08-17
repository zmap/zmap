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

static int init(char *file, const char *name, int value)
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
		int prefix_len = 32;
		char *slash = strchr(ip, '/');
		if (slash) {  // split apart network and prefix length 
			*slash = '\0';
			char *end;
			char *len = slash+1;
			errno = 0;			
			prefix_len = strtol(len, &end, 10);
			if (end == len || errno != 0 || prefix_len < 0 || prefix_len > 32) {
				log_fatal(name, "Unable to parse %s file: %s ('%s' is not a valid prefix length)",  name, file, len);
			}
		}
		struct in_addr addr;
		if (inet_aton(ip, &addr) == 0) {
			log_fatal(name,  "Unable to parse %s file: %s ('%s' is not a valid IP address)",  name, file, ip);
		}
		constraint_set(constraint, ntohl(addr.s_addr), prefix_len, value);
		log_trace(name, "%sing %s/%i",
				  name, ip, prefix_len);
	}
	fclose(fp);

	return 0;
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
int blacklist_init_from_files(char *whitelist_filename, char *blacklist_filename)
{
	assert(!constraint);
	if (whitelist_filename) {
		// using a whitelist, so default to allowing nothing
		constraint = constraint_init(ADDR_DISALLOWED);
		log_trace("whitelist", "blacklisting 0.0.0.0/0");
		init(whitelist_filename, "whitelist", ADDR_ALLOWED);
	} else {
		// no whitelist, so default to allowing everything
		constraint = constraint_init(ADDR_ALLOWED);
	}
	if (blacklist_filename) {
		init(blacklist_filename, "blacklist", ADDR_DISALLOWED);
	}
	constraint_optimize(constraint);
	uint64_t allowed = blacklist_count_allowed();
	#if UINTPTR_MAX == 0xffffffff
		log_debug("blacklist", "%lu addresses allowed to be scanned (%0.0f%% of address space)", allowed, allowed*100./(1LL << 32));
	#elif UINTPTR_MAX == 0xffffffffffffffff
		log_debug("blacklist", "%lu addresses allowed to be scanned (%0.0f%% of address space)", allowed, allowed*100./(1L << 32));
	#endif
	return 0;
}
