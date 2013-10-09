#include <stdint.h>
#include <unistd.h>
#include <hiredis/hiredis.h>

#ifndef REDIS_ZHELPERS_H
#define REDIS_ZHELPERS_H

#define T_TCP 0
#define T_LOCAL 1

typedef struct redisconf {
	int type;
	char *path;
	char *server;
	uint16_t port;
	char *list_name;
} redisconf_t;

redisconf_t *redis_parse_connstr(char *connstr);

int redis_init(char*);

int redis_close(void);

int redis_existconf(const char*);

int redis_flush(void);

int redis_delconf(const char*);

int redis_setconf(const char*, char*);

int redis_getconf(const char*, char*, size_t);

long redis_get_sizeof_list(const char*);

long redis_get_sizeof_set(const char*);

int redis_lpush(char*, void*, int, size_t);

int redis_lpull(char*, void*, int, size_t, int*);

int redis_spull(char*, void*, int, size_t, int*);

int redis_spush(char*, void*, int, size_t);

redisContext* redis_get_context(void);

uint32_t redis_getconf_uint32_t(const char*);

int redis_setconf_uint32_t(const char*, uint32_t);

#endif // _REDIS_ZHELPERS_H
