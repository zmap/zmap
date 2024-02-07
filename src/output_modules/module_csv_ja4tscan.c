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
#include <errno.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <inttypes.h>

#include "../../lib/logger.h"
#include "../fieldset.h"

#include "output_modules.h"

static FILE *file = NULL;
char *csv_filename = NULL;
char **global_field_names = NULL;
int global_field_count = 0;

static void csv_post_process(void)
{
	if (csv_filename) {
		printf("Results written to %s\n", csv_filename);
		printf("Post processing...\n");
	}

	printf("global_field_count: %d\n", global_field_count);
	for (int i = 0; i < global_field_count; i++) {
		printf("global_field_names[%d]: %s\n", i, global_field_names[i]);
	}

	char *line = NULL;
	size_t len = 0;
	ssize_t read;
	FILE *fp = fopen(csv_filename, "r");
	if (fp == NULL) {
		log_fatal("csv",
			  "could not open CSV output file for post processing");
	}
	if ((read = getline(&line, &len, fp)) == -1) {
		log_fatal("csv",
			  "could not read first line of CSV output file");
	}
	printf("First line: %s\n", line);

	// Find column with saddr
	
}

int csv_init(struct state_conf *conf, const char **fields, int fieldlens)
{
	assert(conf);
	global_field_count = fieldlens; // Store the count of fields
	global_field_names = malloc(sizeof(char *) * global_field_count);

	if (conf->output_filename) {
		// set value on csv_filename
		csv_filename = conf->output_filename;
		if (!strcmp(conf->output_filename, "-")) {
			file = stdout;
		} else {
			if (!(file = fopen(conf->output_filename, "w"))) {
				log_fatal(
				    "csv",
				    "could not open CSV output file (%s): %s",
				    conf->output_filename, strerror(errno));
			}
		}
	} else {
		file = stdout;
		log_debug("csv", "no output file selected, will use stdout");
	}
	if (!conf->no_header_row) {
		log_debug("csv", "more than one field, will add headers");
		for (int i = 0; i < fieldlens; i++) {
			if (i) {
				fprintf(file, ",");
			}
			fprintf(file, "%s", fields[i]);
			global_field_names[i] = strdup(fields[i]);
		}
		fprintf(file, "\n");
	}
	check_and_log_file_error(file, "csv");
	return EXIT_SUCCESS;
}

int csv_close(__attribute__((unused)) struct state_conf *c,
	      __attribute__((unused)) struct state_send *s,
	      __attribute__((unused)) struct state_recv *r)
{
	if (file) {
		fflush(file);
		fclose(file);
	}
	csv_post_process();
	return EXIT_SUCCESS;
}

static void hex_encode(FILE *f, unsigned char *readbuf, size_t len)
{
	for (size_t i = 0; i < len; i++) {
		fprintf(f, "%02x", readbuf[i]);
	}
	check_and_log_file_error(f, "csv");
}

int csv_process(fieldset_t *fs)
{
	if (!file) {
		return EXIT_SUCCESS;
	}
	for (int i = 0; i < fs->len; i++) {
		field_t *f = &(fs->fields[i]);
		if (i) {
			fprintf(file, ",");
		}
		if (f->type == FS_STRING) {
			if (strchr((char *)f->value.ptr, ',')) {
				fprintf(file, "\"%s\"", (char *)f->value.ptr);
			} else {
				fprintf(file, "%s", (char *)f->value.ptr);
			}
		} else if (f->type == FS_UINT64) {
			fprintf(file, "%" PRIu64, (uint64_t)f->value.num);
		} else if (f->type == FS_BOOL) {
			fprintf(file, "%" PRIi32, (int)f->value.num);
		} else if (f->type == FS_BINARY) {
			hex_encode(file, (unsigned char *)f->value.ptr, f->len);
		} else if (f->type == FS_NULL) {
			// do nothing
		} else {
			log_fatal("csv", "received unknown output type");
		}
	}
	fprintf(file, "\n");
	fflush(file);
	check_and_log_file_error(file, "csv");
	return EXIT_SUCCESS;
}

output_module_t module_csv_file = {
    .name = "csv",
    .init = &csv_init,
    .start = NULL,
    .update = NULL,
    .update_interval = 0,
    .close = &csv_close,
    .process_ip = &csv_process,
    .supports_dynamic_output = NO_DYNAMIC_SUPPORT,
    .helptext =
	"Outputs one or more output fields as a comma-delimited file. By default, the "
	"probe module does not filter out duplicates or limit to successful fields, "
	"but rather includes all received packets. Fields can be controlled by "
	"setting --output-fields. Filtering out failures and duplicate packets can "
	"be achieved by setting an --output-filter."};
