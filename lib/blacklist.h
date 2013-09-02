#include <stdint.h>

#ifndef BLACKLIST_H
#define BLACKLIST_H

#define ADDR_DISALLOWED 0
#define ADDR_ALLOWED 1

int blacklist_is_allowed(uint32_t s_addr);
void blacklist_prefix(char *ip, int prefix_len);
void whitelist_prefix(char *ip, int prefix_len);
int blacklist_load_from_files(char *whitelist, char*blacklist);
uint64_t blacklist_count_allowed();
uint64_t blacklist_count_not_allowed();
void blacklist_init(int);
void blacklist_optimize(void);
void blacklist_free(void);

#endif
