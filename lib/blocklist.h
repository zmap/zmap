/*
 * Copyright 2021 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdlib.h>
#include <stdint.h>

#ifndef BLACKLIST_H
#define BLACKLIST_H

typedef struct bl_cidr_node {
	uint32_t ip_address;
	int prefix_len;
	struct bl_cidr_node *next;
} bl_cidr_node_t;

uint32_t blocklist_lookup_index(uint64_t index);

int blocklist_is_allowed(uint32_t s_addr);

void blocklist_prefix(char *ip, int prefix_len);

void allowlist_prefix(char *ip, int prefix_len);

int blocklist_init(char *allowlist, char *blocklist, char **allowlist_entries,
		   size_t allowlist_entries_len, char **blocklist_entries,
		   size_t blocklist_entries_len, int ignore_invalid_hosts);

uint64_t blocklist_count_allowed();

uint64_t blocklist_count_not_allowed();

uint32_t blocklist_ip_to_index(uint32_t ip);

bl_cidr_node_t *get_blocklisted_cidrs(void);
bl_cidr_node_t *get_allowlisted_cidrs(void);

#endif
