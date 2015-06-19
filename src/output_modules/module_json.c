/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>

#include "../../lib/includes.h"
#include "../../lib/xalloc.h"

#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#include <json.h>

#include "../../lib/logger.h"

#include "output_modules.h"
#include "../probe_modules/probe_modules.h"

static FILE *file = NULL;

int json_output_file_init(struct state_conf *conf, UNUSED char **fields, 
		UNUSED int fieldlens)
{
	assert(conf);
    if (!conf->output_filename) {
		file = stdout;
    } else if (!strcmp(conf->output_filename, "-")) {
		file = stdout;
	} else {
		if (!(file = fopen(conf->output_filename, "w"))) {
			log_fatal("output-json", "could not open JSON output file %s",
					conf->output_filename);
		}
	} 
	check_and_log_file_error(file, "json");
    return EXIT_SUCCESS;
}

static void json_output_file_store_data(json_object *obj, const char* name, 
		const u_char *packet, size_t buflen)
{
	char *buf = xmalloc((buflen*2)+1);
	for (int i=0; i < (int) buflen; i++) {
		snprintf(buf + (i*2), 3, "%.2x", packet[i]);
	}
	buf[buflen*2] = 0;
	json_object_object_add(obj, name, json_object_new_string(buf));
	free(buf);
}

int json_output_file_ip(fieldset_t *fs)
{
	if (!file) {
		return EXIT_SUCCESS;
	}
	json_object *obj = json_object_new_object();
	for (int i=0; i < fs->len; i++) {
		field_t *f = &(fs->fields[i]);
		if (f->type == FS_STRING) {
			json_object_object_add(obj, f->name,
					json_object_new_string((char *) f->value.ptr));
		} else if (f->type == FS_UINT64) {
			json_object_object_add(obj, f->name,
					json_object_new_int((int) f->value.num));
		} else if (f->type == FS_BINARY) {
			json_output_file_store_data(obj, f->name,
					(const u_char*) f->value.ptr, f->len);
		} else if (f->type == FS_NULL) {
			// do nothing
		} else {
			log_fatal("json", "received unknown output type");
		}
	}

	fprintf(file, "%s\n", json_object_to_json_string(obj));
	fflush(file);
	check_and_log_file_error(file, "json");
	json_object_put(obj);
	return EXIT_SUCCESS;
}

int json_output_file_close(UNUSED struct state_conf* c,
		UNUSED struct state_send* s, UNUSED struct state_recv* r)
{
	if (file) {
		fflush(file);
		fclose(file);
	}
	return EXIT_SUCCESS;
}

output_module_t module_json_file = {
	.name = "json",
	.init = &json_output_file_init,
	.filter_duplicates = 0, // framework should not filter out duplicates
	.filter_unsuccessful = 0,  // framework should not filter out unsuccessful
	.start = NULL,
	.update = NULL,
	.update_interval = 0,
	.close = &json_output_file_close,
	.process_ip = &json_output_file_ip,
	.helptext = "Outputs one or more output fileds as a json valid file. By default, the \n"
	"probe module does not filter out duplicates or limit to successful fields, \n"
	"but rather includes all received packets. Fields can be controlled by \n"
	"setting --output-fields. Filtering out failures and duplicate pakcets can \n"
	"be achieved by setting an --output-filter."
};
