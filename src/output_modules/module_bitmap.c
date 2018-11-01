/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
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
static uint64_t bitmap_buffer_size = 0x100000000 / 8;
static uint64_t * bitmap_buffer;

int bitmap_init(struct state_conf *conf, char **fields, int fieldlens)
{
	assert(conf);
	if (conf->output_filename) {
		if (!strcmp(conf->output_filename, "-")) {
			file = stdout;
		} else {
			if (!(file = fopen(conf->output_filename, "w"))) {
				log_fatal(
				    "bitmap",
				    "could not open BITMAP output file (%s): %s",
				    conf->output_filename, strerror(errno));
			}
		}
	} else {
		file = stdout;
		log_info("bitmap", "no output file selected, will use stdout");
	}
	check_and_log_file_error(file, "bitmap");

	bitmap_buffer = (uint64_t *) malloc(bitmap_buffer_size);
	if (bitmap_buffer == NULL) {
		log_error("bitmap", "buffer allocation fail");
		return EXIT_FAILURE;
	}
	memset(bitmap_buffer, 0, bitmap_buffer_size);
	return EXIT_SUCCESS;
}

int bitmap_close(__attribute__((unused)) struct state_conf *c,
	      __attribute__((unused)) struct state_send *s,
	      __attribute__((unused)) struct state_recv *r)
{
	if (file) {
		fwrite(bitmap_buffer, bitmap_buffer_size, 1, file);
		fflush(file);
		fclose(file);
		free(bitmap_buffer);
	}
	return EXIT_SUCCESS;
}

int bitmap_process(fieldset_t *fs)
{
	if (!file) {
		return EXIT_SUCCESS;
	}

	uint32_t ip = ntohl(fs->fields[0].value.num & 0xffffffff);

	bitmap_buffer[ip / 64] |= 1 << (ip % 64);
	check_and_log_file_error(file, "bitmap");
	return EXIT_SUCCESS;
}

output_module_t module_bitmap_file = {
    .name = "bitmap",
    .filter_duplicates = 0,   // framework should not filter out duplicates
    .filter_unsuccessful = 0, // framework should not filter out unsuccessful
    .init = &bitmap_init,
    .start = NULL,
    .update = NULL,
    .update_interval = 0,
    .close = &bitmap_close,
    .process_ip = &bitmap_process,
    .supports_dynamic_output = NO_DYNAMIC_SUPPORT,
    .helptext =
	"Outputs the bitmap of the whole ipv4 address space, each bit represents one \n"
	"ip address, 1 indicating the existence corresponding ip address, 0 indicating \n"
	"the absence." };
