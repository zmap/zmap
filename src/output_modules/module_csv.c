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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>

#include "../../lib/logger.h"
#include "../fieldset.h"

#include "output_modules.h"

static FILE *file = NULL;

int csv_init(struct state_conf *conf, fielddefset_t *fds)
{
	assert(conf);
	if (conf->output_filename) {
		if (!strcmp(conf->output_filename, "-")) {
			file = stdout;
		} else {
			if (!(file = fopen(conf->output_filename, "w"))) {
				log_fatal("csv", "could not open output file (%s)",
					conf->output_filename);
			}
		}
	}
	//// add output headers
	(void)fds;
	//for (int i=0; i < fds->len; i++) {
	//	if (i) {
	//		fprintf(file, ", ");
	//	}
	//	fprintf(file, "%s", fds->fielddefs[i].name);
	//}	
	return EXIT_SUCCESS;
}

int csv_close(__attribute__((unused)) struct state_conf* c, 
	__attribute__((unused)) struct state_send* s, 
	__attribute__((unused)) struct state_recv* r)
{
	if (file) {
		fflush(file);
		fclose(file);
	}
	return EXIT_SUCCESS;
}

static void hex_encode(FILE *f, unsigned char* readbuf, size_t len) 
{ 
	for(size_t i=0; i < len; i++) { 
		fprintf(f, "%02x", readbuf[i]); 
	} 
}

int csv_process(fieldset_t *fs)
{
	for (int i=0; i < fs->len; i++) {
		field_t *f = &(fs->fields[i]);
		if (i) {
			fprintf(file, ", ");
		}
		if (f->type == FS_STRING) {
			fprintf(file, "%s", (char*) f->value); 
		} else if (f->type == FS_UINT64) {
			fprintf(file, "%lu", (uint64_t) f->value); 
		} else if (f->type == FS_BINARY) {
			hex_encode(file, (unsigned char*) f->value, f->len);
		} else {
			log_fatal("csv", "received unknown output type");
		}
	}
	fprintf(file, "\n");
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
};

