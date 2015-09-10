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
#include "../../lib/xalloc.h"
#include "../../lib/redis.h"

#include "output_modules.h"

#define UNUSED __attribute__((unused))

#define BUFFER_SIZE 500

static uint32_t *buffer;
static int buffer_fill = 0;
static char *queue_name = NULL;
static int field_index = -1;
static redisContext* rctx = NULL;

int redismodule_init(struct state_conf *conf, char **fields, int fieldlens)
{
	buffer = xcalloc(BUFFER_SIZE, sizeof(uint32_t));
	buffer_fill = 0;
	for (int i=0; i < fieldlens; i++) {
		if (!strcmp(fields[i], "saddr-raw")) {
			field_index = i;
			break;
		}
	}
	if (field_index < 0) {
		log_fatal("redis-module", "saddr-raw not included in output-fields");
	}

	redisconf_t rconf;
	memset(&rconf, 0, sizeof(redisconf_t));
	char *connect_string = NULL;
	if (conf->output_args) {
		connect_string = conf->output_args;
	} else {
		connect_string = strdup("local:///tmp/redis.sock/zmap_output");
	}

	if (redis_parse_connstr(connect_string, &rconf) != ZMAP_REDIS_SUCCESS) {
		log_error("redis-module", "configuration error: %s", rconf.error);
		return EXIT_FAILURE;
	}

	if (rconf.list_name) {
		queue_name = rconf.list_name;
	} else {
		queue_name = strdup("zmap_output");
	}

	if (rconf.type == T_TCP) {
		log_info("redis-module", "{type: TCP, server: %s, "
				"port: %u, list: %s}", rconf.server,
				rconf.port, rconf.list_name);
	} else {
		log_info("redis-module", "{type: LOCAL, path: %s, "
				"list: %s}", rconf.path, queue_name);
	}

	rctx = redis_connect_from_conf(&rconf);
	if (!rctx) {
		log_error("redis-module", "could not connect to redis");
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

static int redismodule_flush(void)
{
	if (redis_lpush(rctx, (char *)queue_name, buffer,
			buffer_fill, sizeof(uint32_t))) {
		return EXIT_FAILURE;
	}
	buffer_fill = 0;
	return EXIT_SUCCESS;
}

int redismodule_process(fieldset_t *fs)
{
	field_t *f = &(fs->fields[field_index]);
	buffer[buffer_fill] = (uint32_t) f->value.num;
	if (++buffer_fill == BUFFER_SIZE) {
		if (redismodule_flush()) {
			return EXIT_FAILURE;
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
	if (redis_close(rctx)) {
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
    .supports_dynamic_output = NO_DYNAMIC_SUPPORT,
	.close = &redismodule_close,
	.process_ip = &redismodule_process,
	.helptext = "Flushes to redis the ip address as packed binary integer in network order\n"
};
