/*
 * ZMap Copyright 2013 Regents of the University of Michigan 
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../../lib/zdlibc/logger.h"
#include "../../lib/zdlibc/redis.h"

#include "output_modules.h"

#define UNUSED __attribute__((unused))

typedef struct scannable_t {
	in_addr_t ip_address;
	uint8_t source;
} scannable_t;

#define QUEUE_NAME "zmap_results"
#define BUFFER_SIZE 500
#define SOURCE_ZMAP 0

static scannable_t* buffer;
static int buffer_fill = 0;

int redismodule_init(UNUSED struct state_conf *conf)
{
	buffer = calloc(BUFFER_SIZE, sizeof(scannable_t));
	assert(buffer);
	buffer_fill = 0;
	return redis_init();
}

int redismodule_flush(void)
{
	if (redis_lpush(QUEUE_NAME, buffer,
			buffer_fill, sizeof(scannable_t))) {
		return EXIT_FAILURE;
	}
	buffer_fill = 0;
	return EXIT_SUCCESS;
}

int redismodule_newip(ipaddr_n_t saddr, UNUSED ipaddr_n_t daddr,
        UNUSED port_n_t sport, UNUSED port_n_t dport,
        UNUSED const char *response_type, int is_repeat,
        UNUSED int in_cooldown, UNUSED const u_char *packet)
{
	if (!is_repeat) {
		buffer[buffer_fill].ip_address = saddr;
		buffer[buffer_fill].source = SOURCE_ZMAP;

		if (++buffer_fill == BUFFER_SIZE) {
			if (redismodule_flush()) {
				return EXIT_FAILURE;
			}
		}
	}
	return EXIT_SUCCESS;
}

int redismodule_close(UNUSED struct state_conf* c, 
        UNUSED struct state_send* s,
		UNUSED struct state_recv* r)
{
	if (redismodule_flush()) {
		return EXIT_FAILURE;
	}
	if (redis_close()) {
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

output_module_t module_redis = {
	.name = "redis",
	.init = &redismodule_init,
	.start = NULL,
	.update = NULL,
	.update_interval = 0,
	.close = &redismodule_close,
	.success_ip = &redismodule_newip,
	.other_ip = NULL
};

