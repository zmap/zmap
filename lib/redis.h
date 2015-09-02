#include <stdint.h>
#include <unistd.h>
#include <hiredis/hiredis.h>

#ifndef REDIS_ZHELPERS_H
#define REDIS_ZHELPERS_H

#ifdef __cplusplus
extern "C" {
#endif

#define T_TCP 0
#define T_LOCAL 1

#define ZMAP_REDIS_SUCCESS 0
#define ZMAP_REDIS_EMPTY 1
#define ZMAP_REDIS_ERROR -1

#define ZMAP_REDIS_ERRLEN 1024

typedef struct redisconf {
	int type;
	char *path;
	char *server;
	uint16_t port;
	char *list_name;
	char error[ZMAP_REDIS_ERRLEN];
} redisconf_t;

int redis_parse_connstr(char *connstr, redisconf_t* redis_conf);

int redis_existconf(redisContext*, const char*);

int redis_flush(redisContext*);

int redis_delconf(redisContext*, const char*);

int redis_setconf(redisContext*, const char*, char*);

int redis_getconf(redisContext*, const char*, char*, size_t);

long redis_get_sizeof_list(redisContext*, const char*);

long redis_get_sizeof_set(redisContext*, const char*);

int redis_lpush(redisContext*, char*, void*, int, size_t);

int redis_lpull(redisContext*, char*, void*, int, size_t, int*);

int redis_spull(redisContext*, char*, void*, int, size_t, int*);

int redis_spush(redisContext*, char*, void*, int, size_t);

int redis_lpull_one(redisContext *rctx, char *queuename, void **buf, size_t *len);
int redis_spull_one(redisContext *rctx, char *queuename, void **buf, size_t *len);

int redis_lpush_one(redisContext *rctx, char *queuename, void *buf, size_t len);
int redis_spush_one(redisContext *rctx, char *queuename, void *buf, size_t len);

int redis_lpush_strings(redisContext *rctx, char *redisqueuename, char **buf, int num);
int redis_spush_strings(redisContext *rctx, char *redisqueuename, char **buf, int num);

redisContext* redis_connect(char *connstr);
redisContext* redis_connect_from_conf(redisconf_t* rconf);

int redis_close(redisContext *rctx);

uint32_t redis_getconf_uint32_t(redisContext*, const char*);
int redis_setconf_uint32_t(redisContext*, const char*, uint32_t);

#ifdef __cplusplus
}
#endif

#endif // _REDIS_ZHELPERS_H
