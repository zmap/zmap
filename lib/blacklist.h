#include <stdlib.h>
#include <stdint.h>

#ifndef BLACKLIST_H
#define BLACKLIST_H

typedef struct bl_cidr_node {
        uint32_t ip_address;
	int prefix_len;
        struct bl_cidr_node *next;
} bl_cidr_node_t;

uint32_t blacklist_lookup_index(uint64_t index);

int blacklist_is_allowed(uint32_t s_addr);

void blacklist_prefix(char *ip, int prefix_len);

void whitelist_prefix(char *ip, int prefix_len);

int blacklist_init(char *whitelist, char *blacklist,
		char **whitelist_entries,
		size_t whitelist_entries_len,
		char **blacklist_entries,
		size_t blacklist_entries_len);

uint64_t blacklist_count_allowed();

uint64_t blacklist_count_not_allowed();

bl_cidr_node_t *get_blacklisted_cidrs(void);
bl_cidr_node_t *get_whitelisted_cidrs(void);

#endif
