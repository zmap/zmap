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
#include <errno.h>

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
			log_fatal("output-json", "could not open JSON output file (%s): %s",
					conf->output_filename, strerror(errno));
		}
	}
	check_and_log_file_error(file, "json");
	return EXIT_SUCCESS;
}

char *hex_encode(unsigned char *packet, int buflen)
{
	char *buf = xmalloc(2*buflen + 1);
	for (int i=0; i < buflen; i++) {
		snprintf(buf + (i*2), 3, "%.2x", packet[i]);
	}
	buf[buflen*2] = 0;
	return buf;
}

json_object *fs_to_jsonobj(fieldset_t *fs);
json_object *repeated_to_jsonobj(fieldset_t *fs);

json_object *field_to_jsonobj(field_t *f)
{
	if (f->type == FS_STRING) {
		return json_object_new_string((char *) f->value.ptr);
	} else if (f->type == FS_UINT64) {
		return json_object_new_int64(f->value.num);
	} else if (f->type == FS_BOOL) {
		return json_object_new_boolean(f->value.num);
	} else if (f->type == FS_BINARY) {
		char *encoded = hex_encode(f->value.ptr, f->len);
		json_object *t = json_object_new_string(encoded);
		free(encoded);
		return t;
	} else if (f->type == FS_NULL) {
		return NULL;
	} else if (f->type == FS_FIELDSET) {
		return fs_to_jsonobj((fieldset_t*) f->value.ptr);
	} else if (f->type == FS_REPEATED) {
		return repeated_to_jsonobj((fieldset_t*) f->value.ptr);
	} else {
		log_fatal("json", "received unknown output type: %i", f->type);
	}
}

json_object *repeated_to_jsonobj(fieldset_t *fs)
{
	json_object *obj = json_object_new_array();
	for (int i=0; i < fs->len; i++) {
		field_t *f = &(fs->fields[i]);
		json_object_array_add(obj, field_to_jsonobj(f));
	}
	return obj;
}

json_object *fs_to_jsonobj(fieldset_t *fs)
{
	json_object *obj = json_object_new_object();
	for (int i=0; i < fs->len; i++) {
		field_t *f = &(fs->fields[i]);
		json_object_object_add(obj, f->name, field_to_jsonobj(f));
	}
	return obj;
}

int json_output_to_file(fieldset_t *fs)
{
	if (!file) {
		return EXIT_SUCCESS;
	}
	json_object *record = fs_to_jsonobj(fs);
	fprintf(file, "%s\n", json_object_to_json_string(record));
	fflush(file);
	check_and_log_file_error(file, "json");
	json_object_put(record);
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

int print_json_fieldset(fieldset_t *fs)
{
	json_object *record = fs_to_jsonobj(fs);
	fprintf(stdout, "%s\n", json_object_to_json_string(record));
	json_object_put(record);
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
	.process_ip = &json_output_to_file,
	.supports_dynamic_output = DYNAMIC_SUPPORT,
	.helptext = "Outputs one or more output fileds as a json valid file. By default, the \n"
	"probe module does not filter out duplicates or limit to successful fields, \n"
	"but rather includes all received packets. Fields can be controlled by \n"
	"setting --output-fields. Filtering out failures and duplicate pakcets can \n"
	"be achieved by setting an --output-filter."
};

