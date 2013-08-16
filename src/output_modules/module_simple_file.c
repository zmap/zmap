/*
 * ZMap Copyright 2013 Regents of the University of Michigan 
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */


#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <logger.h>

#include "output_modules.h"

#define UNUSED __attribute__((unused))

static FILE *file = NULL;

int simplefile_init(struct state_conf *conf)
{
	assert(conf);
	if (conf->output_filename) {
		if (!strcmp(conf->output_filename, "-")) {
			file = stdout;
		} else {
			if (!(file = fopen(conf->output_filename, "w"))) {
				perror("Couldn't open output file");
				exit(EXIT_FAILURE);
			}
		}
	}
	return EXIT_SUCCESS;
}

int simplefile_synack_newip(ipaddr_n_t saddr, UNUSED ipaddr_n_t daddr,
		UNUSED const char *response_type,
		int is_repeat, UNUSED int in_cooldown, UNUSED const u_char *packet,
		UNUSED size_t buflen)
{	
	if (file && !is_repeat) {
		struct in_addr addr;
		addr.s_addr = saddr;
		fprintf(file, "%s\n", inet_ntoa(addr));
	}
	fflush(file);
	return EXIT_SUCCESS;
}

int simplefile_close(UNUSED struct state_conf* c, 
	UNUSED struct state_send* s, 
	UNUSED struct state_recv* r)
{
	if (file) {
		fflush(file);
		fclose(file);
	}
	return EXIT_SUCCESS;
}

output_module_t module_simple_file = {
	.name = "simple_file",
	.init = &simplefile_init,
	.start = NULL,
	.update = NULL,
	.update_interval = 0,
	.close = &simplefile_close,
	.success_ip = &simplefile_synack_newip,
	.other_ip = NULL,
};
