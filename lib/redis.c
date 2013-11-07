/*
 * ZMap Redis Helpers Copyright 2013 Regents of the University of Michigan 
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

#define REDIS_TIMEOUT 2

#undef  MIN
#define MIN(X,Y) ((X) < (Y) ? (X) : (Y))

static redisContext *rctx;

redisconf_t *redis_parse_connstr(char *connstr)
{
	redisconf_t *retv = malloc(sizeof(redisconf_t));
	if (!strncmp("tcp://", connstr, 6)) {
		char *servername = malloc(strlen(connstr));
		assert(servername);
		char *list_name = malloc(strlen(connstr));
		assert(list_name);
		uint32_t port;
		if (sscanf(connstr, "tcp://%[^:]:%u/%s", servername,
						&port, list_name) != 3) {
			log_fatal("redis", "unable to parse redis connection string. This "
					"should be of the form tcp://server:port/list-name "
					"for TCP connections. All fields are required.");
		}
		retv->type = T_TCP;
		retv->server = servername;
		retv->port = port;
		retv->list_name = list_name;
		retv->path = NULL;
	} else if (!strncmp("local://", connstr, 8)) {
		// looking for something along the lines of
		// local:///tmp/redis.sock/list-name
		char *path = malloc(strlen(connstr));
		assert(path);
		char *list_name = malloc(strlen(connstr));
		assert(list_name);
		connstr = connstr + (size_t) 8;
		char *listname = strrchr(connstr, '/') + (size_t) 1;
		connstr[strrchr(connstr, '/') - connstr] = '\0';
		strcpy(path, connstr);
		strcpy(list_name, listname);
		retv->type = T_LOCAL;
		retv->list_name = list_name;
		retv->path = path;
		retv->server = NULL;
		retv->port = 0;
	} else {
		log_fatal("redis", "unable to parse connection string. does not begin with "
			"local:// or tcp:// as expected");
	}
	return retv;
}

static redisContext* redis_connect(char *connstr)
{
	redisconf_t *c;
	// handle old behavior where we only connected to a specific
	// socket that we #defined.
	if (!connstr) {
		c = malloc(sizeof(redisconf_t));
		assert(c);
		c->type = T_LOCAL;
		c->path = strdup("/tmp/redis.sock");
	} else {
		c = redis_parse_connstr(connstr);
		assert(c);
	}
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

static int chkerr(redisReply *reply)
{
	assert(rctx);
	if (reply == NULL || reply->type == REDIS_REPLY_ERROR) {
		log_error("redis", "an error occurred when "
				"retreiving item from redis: %s",
				rctx->errstr);
		if (reply) {
			freeReplyObject(reply);
		}
		return -1;
	}
	return 0;
}

int redis_init(char *connstr)
{
	rctx = redis_connect(connstr);
	if (!rctx) {
		return -1;
	}
	return 0;
}

int redis_close(void)
{
	redisFree(rctx);
	return 0;
}

redisContext* redis_get_context(void)
{
	return rctx;
}

int redis_flush(void)
{
	redisReply *reply = (redisReply*) redisCommand(rctx, "FLUSHDB");
	if (chkerr(reply)) {
		return -1;
	}
	freeReplyObject(reply);
	return 0;
}

int redis_existconf(const char *name)
{
	assert(rctx);
	redisReply *reply = (redisReply*) redisCommand(rctx, "EXISTS %s", name);
	if (chkerr(reply)) {
		return -1;
	}
	int v = reply->integer;
	freeReplyObject(reply);
	return v;
}

int redis_delconf(const char *name)
{
	assert(rctx);
	redisReply *reply = (redisReply*) redisCommand(rctx, "DEL %s", name);
	if (chkerr(reply)) {
		return -1;
	}
	freeReplyObject(reply);
	return 0;
}

int redis_setconf(const char *name, char *value)
{
	assert(rctx);
	redisReply *reply = (redisReply*) redisCommand(rctx, "SET %s %s",
			name, value);
	if (chkerr(reply)) {
		return -1;
	}
	freeReplyObject(reply);
	return 0;
}

int redis_getconf(const char *name, char *buf, size_t maxlen)
{
	assert(rctx);
	redisReply *reply = (redisReply*) redisCommand(rctx, "GET %s", name);
	if (chkerr(reply)) {
		return -1;
	}
	strncpy(buf, reply->str, maxlen);
	freeReplyObject(reply);
	return 0;
}

uint32_t redis_getconf_uint32_t(const char *key)
{
	assert(rctx);
	char buf[50];
	redis_getconf(key, buf, 50);
	return atoi(buf);
}

int redis_setconf_uint32_t(const char *key, uint32_t value)
{
	assert(rctx);
	char buf[50];
	sprintf(buf, "%u", value);
	return redis_setconf(key, buf);
}


static long redis_get_sizeof(const char *cmd, const char *name)
{
	assert(rctx);
	redisReply *reply;
	reply = (redisReply*) redisCommand(rctx, "%s %s", cmd, name);
	assert(reply);
	assert(reply->type == REDIS_REPLY_INTEGER);
	long rtr = reply->integer;
	freeReplyObject(reply);
	return rtr;
}

long redis_get_sizeof_list(const char *name)
{
	return redis_get_sizeof("LLEN", name);
}

long redis_get_sizeof_set(const char *name)
{
	return redis_get_sizeof("SCARD", name);
}

int redis_pull(char *redisqueuename, void *buf, 
		int maxload, size_t obj_size, int *numloaded, const char* cmd)
{
	assert(rctx);
	long elems_in_redis = redis_get_sizeof_list(redisqueuename);
	long num_to_add = MIN(elems_in_redis, maxload);
	log_info("redis", "INFO: redis load called on %s. Transfering %li "
			"of %li elements to in-memory queue.",
			redisqueuename,
			num_to_add, elems_in_redis);
	for(int i=0; i < num_to_add; i++) {
		redisAppendCommand(rctx, "%s %s", cmd, redisqueuename);
	}
	for(int i=0; i < num_to_add; i++) {
		redisReply *reply;
		int rc = redisGetReply(rctx, (void**) &reply);
		if (rc != REDIS_OK) {
			log_fatal("redis", "response from redis != REDIS_OK");
			return -1;
		}
		if (!reply) {
			log_fatal("redis", "no reply provided by redis.");
			return -1;
		}
		if (reply->type != REDIS_REPLY_STRING) {
			log_fatal("redis", 
					"unxpected reply type from redis.");
			return -1;
		}
		if ((size_t)reply->len != obj_size) {
			log_fatal("redis", "ERROR: unexpected lengthed "
					"object provided by redis.\n");
			return -1;
		}
		memcpy((void*)((intptr_t)buf+i*obj_size), reply->str, obj_size);
		freeReplyObject(reply);
	}
	*numloaded = num_to_add;
	return 0;
}

int redis_lpull(char *redisqueuename, void *buf, 
		int maxload, size_t obj_size, int *numloaded)
{
	return redis_pull(redisqueuename, buf, 
			maxload, obj_size, numloaded, "LPOP");
}

int redis_spull(char *redisqueuename, void *buf, 
		int maxload, size_t obj_size, int *numloaded)
{
	return redis_pull(redisqueuename, buf, 
			maxload, obj_size, numloaded, "SRAND");
}

static int redis_push(char *redisqueuename, 
		void *buf, int num, size_t len, const char *cmd) 
{
	assert(rctx);
	for (int i=0; i < num; i++) {
		void* load = (void*)((intptr_t)buf + i*len);	
		int rc = redisAppendCommand(rctx, "%s %s %b", 
				cmd, redisqueuename, load, len);
		if (rc != REDIS_OK || rctx->err) {
			log_fatal("redis", "%s", rctx->errstr);
			return -1;
		}
	}
	redisReply *reply;
	for (int i=0; i < num; i++) {
		if (redisGetReply(rctx, (void**) &reply) != REDIS_OK 
				|| rctx->err) {
			log_fatal("redis","%s", rctx->errstr);
			return -1;
		}
		if (reply->type == REDIS_REPLY_ERROR) {
			log_fatal("redis", "%s", rctx->errstr);
			return -1;
		}
		freeReplyObject(reply);
	}
	return 0;
}

int redis_lpush(char *redisqueuename, 
		void *buf, int num, size_t len) 
{
	return redis_push(redisqueuename, buf, num, len, "RPUSH");
}

int redis_spush(char *redisqueuename, 
		void *buf, int num, size_t len) 
{
	return redis_push(redisqueuename, buf, num, len, "SADD");
}

