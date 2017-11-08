/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <sched.h>
#include <errno.h>
#include <pwd.h>
#include <time.h>
#include <getopt.h>

#include <pcap/pcap.h>
#include <json.h>
#include <pthread.h>

#include "../lib/includes.h"
#include "../lib/blacklist.h"
#include "../lib/logger.h"
#include "../lib/random.h"
#include "../lib/util.h"
#include "../lib/xalloc.h"

#include "aesrand.h"
#include "send.h"
#include "recv.h"
#include "state.h"
#include "monitor.h"
#include "get_gateway.h"
#include "filter.h"
#include "summary.h"

#include "output_modules/output_modules.h"
#include "probe_modules/probe_modules.h"
#include "output_modules/module_json.h"
#include "ztopt.h"

int test_recursive_fieldsets(void)
{
	fieldset_t *outer = fs_new_fieldset();
	fieldset_t *inner = fs_new_fieldset();

	fieldset_t *repeated = fs_new_repeated_string(0);
	assert(repeated->type == FS_REPEATED);
	assert(repeated->len == 0);
	assert(repeated->inner_type == FS_STRING);
	for (int i = 0; i < 10; i++) {
		fs_add_string(repeated, NULL, (char *)"hello world!", 0);
	}
	fs_add_repeated(outer, (char *)"repeatedstuff", repeated);
	fs_add_string(outer, "name", strdup("value"), 0);
	fs_add_string(inner, "name2", strdup("value2"), 0);
	fs_add_fieldset(outer, "inner", inner);

	print_json_fieldset(outer);
	fs_free(outer);

	return EXIT_SUCCESS;
}

int main(UNUSED int argc, UNUSED char **argv)
{
	struct gengetopt_args_info args;
	struct cmdline_parser_params *params;
	params = cmdline_parser_params_create();
	assert(params);
	params->initialize = 1;
	params->override = 0;
	params->check_required = 0;

	if (cmdline_parser_ext(argc, argv, &args, params) != 0) {
		exit(EXIT_SUCCESS);
	}

	// Handle help text and version
	if (args.help_given) {
		cmdline_parser_print_help();
		exit(EXIT_SUCCESS);
	}
	if (args.version_given) {
		cmdline_parser_print_version();
		exit(EXIT_SUCCESS);
	}

	for (int i = 0; i < 100000000; i++)
		test_recursive_fieldsets();
	return EXIT_SUCCESS;
}
