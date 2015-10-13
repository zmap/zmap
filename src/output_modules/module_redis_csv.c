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
#include <inttypes.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../../lib/logger.h"
#include "../../lib/xalloc.h"
#include "../../lib/redis.h"

#include "output_modules.h"

#define UNUSED __attribute__((unused))

#define BUFFER_SIZE 1000

static char **buffer;
static int buffer_fill = 0;
static char *queue_name = NULL;
static redisContext *rctx = NULL;

int rediscsvmodule_init(struct state_conf *conf, UNUSED char **fields, UNUSED int fieldlens)
{
	// This function leaks memory but not much
	buffer = xcalloc(BUFFER_SIZE, sizeof(char*));
	buffer_fill = 0;
	redisconf_t c;
	redisconf_t *rconf = &c;
	char *connect_string = NULL;
	if (conf->output_args) {
		log_debug("redis-csv", "output args %s", conf->output_args);
		connect_string = conf->output_args;
	} else {
		connect_string = strdup("local:///tmp/redis.sock/zmap");
	}
	if (redis_parse_connstr(connect_string, rconf) != ZMAP_REDIS_SUCCESS) {
		log_error("redis-csv", "error parsing connect string (%s)",
				rconf->error);
		return EXIT_FAILURE;
	}
	if (rconf->type == T_TCP) {
		log_info("redis-csv", "{type: TCP, server: %s, "
				"port: %u, list: %s}", rconf->server,
				rconf->port, rconf->list_name);
	} else {
		log_info("redis-csv", "{type: LOCAL, path: %s, "
				"list: %s}", rconf->path, rconf->list_name);
	}

	if (rconf && rconf->list_name) {
		queue_name = rconf->list_name;
	} else {
		queue_name = strdup("zmap");
	}

	// generate field names CSV list to be logged.
	char *fieldstring = xcalloc(1000, fieldlens);
	memset(fieldstring, 0, sizeof(fields));
        for (int i=0; i < fieldlens; i++) {
                if (i) {
                        strcat(fieldstring, ", ");
                }
		strcat(fieldstring, fields[i]);
        }
	log_info("redis-csv", "the following fields will be output to redis: %s.",
			fieldstring);
	free(fields);

	rctx = redis_connect_from_conf(rconf);
	if (!rctx) {
		log_error("redis-csv", "could not connect to redis");
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

static int rediscsvmodule_flush(void)
{
	if (redis_lpush_strings(rctx, (char*) queue_name, buffer, buffer_fill)) {
		return EXIT_FAILURE;
	}
	for (int i=0; i < buffer_fill; i++) {
		free(buffer[i]);
	}
	buffer_fill = 0;
	return EXIT_SUCCESS;
}

#define INT_STR_LEN 20 // len(9223372036854775807) == 19

static size_t guess_csv_string_length(fieldset_t *fs)
{
	size_t len = 0;
	for (int i=0; i < fs->len; i++) {
		field_t *f = &(fs->fields[i]);
		if (f->type == FS_STRING) {
			len += strlen(f->value.ptr);
			len += 2; // potential quotes
		} else if (f->type == FS_UINT64) {
			len += INT_STR_LEN;
		} else if (f->type == FS_BINARY) {
			len += 2*f->len;
		} else if (f->type == FS_NULL) {
			// do nothing
		} else {
			log_fatal("csv", "received unknown output type "
					"(not str, binary, null, or uint64_t)");
		}
	}
	// estimated length + number of commas
	return len + (size_t) len + 256;
}

static void hex_encode_str(char *f, unsigned char* readbuf, size_t len)
{
	char *temp = f;
	for(size_t i=0; i < len; i++) {
		sprintf(temp, "%02x", readbuf[i]);
		temp += (size_t) 2*sizeof(char);
	}
}

void make_csv_string(fieldset_t *fs, char *out, size_t len)
{
	memset(out, 0, len);
	for (int i=0; i < fs->len; i++) {
		char *temp = out + (size_t) strlen(out);
		field_t *f = &(fs->fields[i]);
	char *dataloc = temp;
		if (i) { // only add comma if not first element
			sprintf(temp, ",");
		dataloc += (size_t) 1;
		}
		if (f->type == FS_STRING) {
			if (strlen(dataloc) + strlen((char*) f->value.ptr) >= len) {
				log_fatal("redis-csv", "out of memory---will overflow");
			}
			if (strchr((char*) f->value.ptr, ',')) {
				sprintf(dataloc, "\"%s\"", (char*) f->value.ptr);
			} else {
				sprintf(dataloc, "%s", (char*) f->value.ptr);
			}
		} else if (f->type == FS_UINT64) {
			if (strlen(dataloc) + INT_STR_LEN >= len) {
				log_fatal("redis-csv", "out of memory---will overflow");
			}
			sprintf(dataloc, "%" PRIu64, (uint64_t) f->value.num);
		} else if (f->type == FS_BINARY) {
			if (strlen(dataloc) + 2*f->len >= len) {
				log_fatal("redis-csv", "out of memory---will overflow");
			}
			hex_encode_str(out, (unsigned char*) f->value.ptr, f->len);
		} else if (f->type == FS_NULL) {
			// do nothing
		} else {
			log_fatal("redis-csv", "received unknown output type");
		}
	}
}

int rediscsvmodule_process(fieldset_t *fs)
{
	size_t reqd_space = guess_csv_string_length(fs);
	char *x = xmalloc(reqd_space);
	make_csv_string(fs, x, reqd_space);
	buffer[buffer_fill] = x;
	// if full, flush all to redis
	if (++buffer_fill == BUFFER_SIZE) {
		if (rediscsvmodule_flush()) {
			return EXIT_FAILURE;
		}
	}
	return EXIT_SUCCESS;
}

int rediscsvmodule_close(UNUSED struct state_conf* c,
		UNUSED struct state_send *s,
		UNUSED struct state_recv *r)
{
	if (rediscsvmodule_flush()) {
		return EXIT_FAILURE;
	}
	if (redis_close(rctx)) {
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

output_module_t module_redis_csv = {
	.name = "redis-csv",
	.init = &rediscsvmodule_init,
	.start = NULL,
	.update = NULL,
	.update_interval = 0,
	.close = &rediscsvmodule_close,
	.process_ip = &rediscsvmodule_process,
    .supports_dynamic_output = NO_DYNAMIC_SUPPORT,
	.helptext = "Outputs one or more output fields in csv, and then flushes out to redis. \n"
    "By default, the probe module does not filter out duplicates or limit to successful fields, \n"
    "but rather includes all received packets. Fields can be controlled by \n"
    "setting --output-fileds. Filtering out failures and duplicate packets can \n"
    "be achieved by setting an --output-filter."
};
