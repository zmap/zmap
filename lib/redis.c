/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include "redis.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <assert.h>

#include <hiredis/hiredis.h>

#include "logger.h"
#include "xalloc.h"

#define REDIS_TIMEOUT 2

#undef  MIN
#define MIN(X,Y) ((X) < (Y) ? (X) : (Y))

int redis_parse_connstr(char *connstr, redisconf_t* redis_conf)
{
	memset(redis_conf->error, 0, ZMAP_REDIS_ERRLEN);
	if (!strncmp("tcp://", connstr, 6)) {
		// Zero-out the error message
		char *servername = xmalloc(strlen(connstr));
		char *list_name = xmalloc(strlen(connstr));
		uint32_t port;
		if (sscanf(connstr, "tcp://%[^:]:%u/%s", servername,
						&port, list_name) != 3) {
			char *back = stpncpy(&redis_conf->error[0], "unable to "
				"parse redis connection string. This should be of the form "
				"tcp://server:port/list-name for TCP connections. All fields"
				" are required.", ZMAP_REDIS_ERRLEN);
			*back = '\0';
			return ZMAP_REDIS_ERROR;
		}
		redis_conf->type = T_TCP;
		redis_conf->server = servername;
		redis_conf->port = port;
		redis_conf->list_name = list_name;
		redis_conf->path = NULL;
	} else if (!strncmp("local://", connstr, 8)) {
		// looking for something along the lines of
		// local:///tmp/redis.sock/list-name
		// or local:///tmp/redis.sock/
		char *path = xmalloc(strlen(connstr));
		char *list_name = xmalloc(strlen(connstr));
		connstr = connstr + (size_t) 8;
		char *listname = strrchr(connstr, '/');
		if (listname == NULL) {
			char *back = stpncpy(&redis_conf->error[0],
					"bad local url (missing a slash)",
					ZMAP_REDIS_ERRLEN);
			*back = '\0';
			return ZMAP_REDIS_ERROR;
		}

		// Check if we have a list or not
		listname += 1;
		if (*listname != '\0') {
			redis_conf->list_name = list_name;
		} else {
			redis_conf->list_name = NULL;
		}

		// Get the hostname
		connstr[strrchr(connstr, '/') - connstr] = '\0';
		strcpy(path, connstr);
		strcpy(list_name, listname);
		redis_conf->type = T_LOCAL;
		redis_conf->path = path;
		redis_conf->server = NULL;
		redis_conf->port = 0;
	} else {
		char *back = stpncpy(&redis_conf->error[0],
				"redis connection string does not being with "
				"tcp:// or local://", ZMAP_REDIS_ERRLEN);
		*back = '\0';
		return ZMAP_REDIS_ERROR;
	}
	return ZMAP_REDIS_SUCCESS;
}

redisContext* redis_connect(char *connstr)
{
	assert(connstr);
	redisconf_t rconf;
	redisconf_t *c = &rconf;
	// handle old behavior where we only connected to a specific
	// socket that we #defined.
	if (!connstr) {
		c->type = T_LOCAL;
		c->path = strdup("/tmp/redis.sock");
	} else {
		int retv = redis_parse_connstr(connstr, c);
		log_error("redis", "Could not connect: %s", c->error);
		if (retv != ZMAP_REDIS_ERROR) {
			return NULL;
		}
	}
	return redis_connect_from_conf(c);
}

redisContext* redis_connect_from_conf(redisconf_t* c)
{
	assert(c);
	struct timeval timeout;
	timeout.tv_sec = REDIS_TIMEOUT;
	timeout.tv_usec = 0;
	if (c->type == T_LOCAL) {
		return (redisContext*) redisConnectUnixWithTimeout(c->path,
			timeout);
	} else {
		return (redisContext*) redisConnectWithTimeout(c->server,
			c->port, timeout);
	}
}

int redis_close(redisContext* rctx) {
	assert(rctx);
	redisFree(rctx);
	return 0;
}

static int chkerr(redisContext *rctx, redisReply *reply)
{
	assert(rctx);
	if (reply == NULL || reply->type == REDIS_REPLY_ERROR) {
		log_error("redis", "an error occurred when retrieving item from redis: %s",
				rctx->errstr);
		if (reply) {
			freeReplyObject(reply);
		}
		return ZMAP_REDIS_ERROR;
	}
	return 0;
}

int redis_flush(redisContext* rctx)
{
	assert(rctx);
	redisReply *reply = redisCommand(rctx, "FLUSHDB");
	if (chkerr(rctx, reply)) {
		return ZMAP_REDIS_ERROR;
	}
	freeReplyObject(reply);
	return 0;
}

int redis_existconf(redisContext* rctx, const char *name)
{
	assert(rctx);
	redisReply *reply = redisCommand(rctx, "EXISTS %s", name);
	if (chkerr(rctx, reply)) {
		return ZMAP_REDIS_ERROR;
	}
	int v = reply->integer;
	freeReplyObject(reply);
	return v;
}

int redis_delconf(redisContext* rctx, const char *name)
{
	assert(rctx);
	redisReply *reply = redisCommand(rctx, "DEL %s", name);
	if (chkerr(rctx, reply)) {
		return ZMAP_REDIS_ERROR;
	}
	freeReplyObject(reply);
	return 0;
}

int redis_setconf(redisContext* rctx, const char *name, char *value)
{
	assert(rctx);
	redisReply *reply = redisCommand(rctx, "SET %s %s", name, value);
	if (chkerr(rctx, reply)) {
		return ZMAP_REDIS_ERROR;
	}
	freeReplyObject(reply);
	return 0;
}

int redis_getconf(redisContext* rctx, const char *name, char *buf, size_t maxlen)
{
	assert(rctx);
	redisReply *reply = redisCommand(rctx, "GET %s", name);
	if (chkerr(rctx, reply)) {
		return ZMAP_REDIS_ERROR;
	}
	strncpy(buf, reply->str, maxlen - 1);
	buf[maxlen - 1] = '\0';
	freeReplyObject(reply);
	return 0;
}

uint32_t redis_getconf_uint32_t(redisContext* rctx, const char *key)
{
	assert(rctx);
	char buf[50];
	assert(redis_getconf(rctx, key, buf, 50) == 0);
	return (uint32_t) atoi(buf);
}

int redis_setconf_uint32_t(redisContext* rctx, const char *key, uint32_t value)
{
	assert(rctx);
	char buf[50];
	sprintf(buf, "%u", value);
	return redis_setconf(rctx, key, buf);
}


static long redis_get_sizeof(redisContext* rctx, const char *cmd, const char *name)
{
	assert(rctx);
	redisReply *reply = redisCommand(rctx, "%s %s", cmd, name);
	assert(reply);
	assert(reply->type == REDIS_REPLY_INTEGER);
	long rtr = reply->integer;
	freeReplyObject(reply);
	return rtr;
}

long redis_get_sizeof_list(redisContext* rctx, const char *name)
{
	return redis_get_sizeof(rctx, "LLEN", name);
}

long redis_get_sizeof_set(redisContext* rctx, const char *name)
{
	return redis_get_sizeof(rctx, "SCARD", name);
}

int redis_pull(redisContext* rctx, char *redisqueuename, void *buf,
		int maxload, size_t obj_size, int *numloaded, const char* cmd)
{
	assert(rctx);
	long elems_in_redis = redis_get_sizeof_list(rctx, redisqueuename);
	long num_to_add = MIN(elems_in_redis, maxload);
	log_debug("redis", "redis load called on %s. Transferring %li of %li elements "
			"to in-memory queue.",
			redisqueuename, num_to_add, elems_in_redis);
	for (int i = 0; i < num_to_add; i++) {
		redisAppendCommand(rctx, "%s %s", cmd, redisqueuename);
	}
	for (int i = 0; i < num_to_add; i++) {
		redisReply *reply = NULL;
		int rc = redisGetReply(rctx, (void **) &reply);
		if (chkerr(rctx, reply)) {
			return ZMAP_REDIS_ERROR;
		}
		if (rc != REDIS_OK || reply == NULL) {
			log_error("redis", "unknown error, could not get reply");
			if (reply) {
				freeReplyObject(reply);
			}
			return ZMAP_REDIS_ERROR;
		}
		if (reply->type != REDIS_REPLY_STRING) {
			log_error("redis", "unxpected reply type from redis");
			freeReplyObject(reply);
			return ZMAP_REDIS_ERROR;
		}
		if ((size_t) reply->len != obj_size) {
			freeReplyObject(reply);
			log_error("redis", "response object length mismatch");
			return ZMAP_REDIS_ERROR;
		}
		memcpy((void*)((intptr_t)buf+i*obj_size), reply->str, obj_size);
		freeReplyObject(reply);
		*numloaded = i + 1;
	}
	return ZMAP_REDIS_SUCCESS;
}

int redis_lpull(redisContext* rctx, char *redisqueuename, void *buf,
		int maxload, size_t obj_size, int *numloaded)
{
	return redis_pull(rctx, redisqueuename, buf, maxload, obj_size, numloaded,
			"LPOP");
}

int redis_spull(redisContext* rctx, char *redisqueuename, void *buf,
		int maxload, size_t obj_size, int *numloaded)
{
	return redis_pull(rctx, redisqueuename, buf,
			maxload, obj_size, numloaded, "SRAND");
}

static int redis_pull_one(redisContext *rctx, char *queuename, void **buf,
		size_t *len, const char *cmd)
{
	assert(rctx);
	redisReply *reply = redisCommand(rctx, "%s %s", cmd, queuename);
	if (chkerr(rctx, reply)) {
		return ZMAP_REDIS_ERROR;
	}
	if (reply->type == REDIS_REPLY_NIL) {
		freeReplyObject(reply);
		return ZMAP_REDIS_EMPTY;
	}
	assert(reply->type == REDIS_REPLY_STRING);
	*len = reply->len;
	void *temp = (char*) malloc(*len);
	assert(temp);
	*buf = temp;
	memcpy(temp, reply->str, *len);
	freeReplyObject(reply);
	return ZMAP_REDIS_SUCCESS;
}

int redis_lpull_one(redisContext *rctx, char *queuename, void **buf,
		size_t *len)
{
	return redis_pull_one(rctx, queuename, buf, len, "LPOP");
}

int redis_spull_one(redisContext *rctx, char *queuename, void **buf,
		size_t *len)
{
	return redis_pull_one(rctx, queuename, buf, len, "SRAND");
}

static int redis_push(redisContext* rctx, char *redisqueuename,
		void *buf, int num, size_t len, const char *cmd)
{
	assert(rctx);
	for (int i=0; i < num; i++) {
		void* load = (void*)((intptr_t)buf + i*len);
		int rc = redisAppendCommand(rctx, "%s %s %b",
				cmd, redisqueuename, load, len);
		if (rc != REDIS_OK || rctx->err) {
			log_error("redis", "%s", rctx->errstr);
			return ZMAP_REDIS_ERROR;
		}
	}
	redisReply *reply = NULL;
	for (int i = 0; i < num; i++) {
		int rc = redisGetReply(rctx, (void**) &reply);
		if (chkerr(rctx, reply)) {
			return ZMAP_REDIS_ERROR;
		}
		if (rc != REDIS_OK || reply == NULL) {
			if (reply) {
				freeReplyObject(reply);
			}
			return ZMAP_REDIS_ERROR;
		}
		if (reply->type == REDIS_REPLY_ERROR) {
			log_error("redis", "%s", rctx->errstr);
			freeReplyObject(reply);
			return ZMAP_REDIS_ERROR;
		}
		freeReplyObject(reply);
	}
	return ZMAP_REDIS_SUCCESS;
}

int redis_lpush(redisContext* rctx, char *redisqueuename,
		void *buf, int num, size_t len)
{
	return redis_push(rctx, redisqueuename, buf, num, len, "RPUSH");
}

int redis_spush(redisContext* rctx, char *redisqueuename,
		void *buf, int num, size_t len)
{
	return redis_push(rctx, redisqueuename, buf, num, len, "SADD");
}

static int redis_push_one(redisContext *rctx, char *queuename, void *buf,
		size_t len, const char *cmd)
{
	assert(rctx);
	redisReply *reply = redisCommand(rctx, "%s %s %b", cmd, queuename, buf, len);
	if (chkerr(rctx, reply)) {
		return ZMAP_REDIS_ERROR;
	}
	freeReplyObject(reply);
	return ZMAP_REDIS_SUCCESS;
}

int redis_lpush_one(redisContext *rctx, char *queuename,
		void *buf, size_t len)
{
	return redis_push_one(rctx, queuename, buf, len, "RPUSH");
}

int redis_spush_one(redisContext *rctx, char *queuename,
		void *buf, size_t len)
{
	return redis_push_one(rctx, queuename, buf, len, "SADD");
}

static int redis_push_strings(redisContext* rctx, char *redisqueuename,
		char **buf, int num, const char *cmd)
{
	assert(rctx);
	for (int i = 0; i < num; i++) {
		int rc = redisAppendCommand(rctx, "%s %s %s", cmd, redisqueuename, buf[i]);
		if (rc != REDIS_OK || rctx->err) {
			log_error("redis", "%s", rctx->errstr);
			return ZMAP_REDIS_ERROR;
		}
	}
	redisReply *reply = NULL;
	for (int i = 0; i < num; i++) {
		if (redisGetReply(rctx, (void**) &reply) != REDIS_OK || rctx->err) {
			log_error("redis", "%s", rctx->errstr);
			if (reply) {
				freeReplyObject(reply);
			}
			return ZMAP_REDIS_ERROR;
		}
		if (reply->type == REDIS_REPLY_ERROR) {
			log_error("redis", "%s", rctx->errstr);
			freeReplyObject(reply);
			return ZMAP_REDIS_ERROR;
		}
		freeReplyObject(reply);
	}
	return ZMAP_REDIS_SUCCESS;

}

int redis_lpush_strings(redisContext* rctx, char *redisqueuename, char **buf, int num)
{
	return redis_push_strings(rctx, redisqueuename, buf, num, "RPUSH");
}

int redis_spush_strings(redisContext* rctx, char *redisqueuename, char **buf, int num)
{
	return redis_push_strings(rctx, redisqueuename, buf, num, "SADD");
}
