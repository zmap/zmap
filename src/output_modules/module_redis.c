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

#include "../../lib/logger.h"
#include "../../lib/redis.h"

#include "output_modules.h"

#define UNUSED __attribute__((unused))

#define BUFFER_SIZE 500
#define SOURCE_ZMAP 0

static uint32_t *buffer;
static int buffer_fill = 0;
static char *queue_name = NULL;

static int redismodule_init(struct state_conf *conf, char **fields, int fieldlens)
{
	assert(fieldlens == 1);
	buffer = calloc(BUFFER_SIZE, sizeof(uint32_t));
	assert(buffer);
	buffer_fill = 0;
	return redis_init(conf->output_args);
}

static int redismodule_flush(void)
{
	if (redis_lpush((char *)queue_name, buffer,
			buffer_fill, sizeof(uint32_t))) {
		return EXIT_FAILURE;
	}
	buffer_fill = 0;
	return EXIT_SUCCESS;
}

static int redismodule_process(fieldset_t *fs)
{
	field_t *f = &(fs->fields[0]);
	buffer[buffer_fill] = (uint32_t) f->value.num;
	if (++buffer_fill == BUFFER_SIZE) {
		if (redismodule_flush()) {
			return EXIT_FAILURE;
		}
	}
	return EXIT_SUCCESS;
}

static int redismodule_close(UNUSED struct state_conf* c, 
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
	.name = "redis-packed",
	.init = &redismodule_init,
	.start = NULL,
	.update = NULL,
	.update_interval = 0,
	.close = &redismodule_close,
	.process_ip = &redismodule_process
};

