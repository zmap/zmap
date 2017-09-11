/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

/*
 * ZBlacklist is a simple utility that (1) excludes IP addresses on a specified
 * blacklist from being scanned, and (2) ensures the uniqueness of output
 * addresses such that no host is scanned twice. ZBlacklist takes in a list
 * of addresses on stdin and outputs addresses that are acceptable to scan
 * on stdout. The utility uses the blacklist data structures from ZMap for
 * checking scan eligibility and a paged bitmap for duplicate prevention.
 */

#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <assert.h>
#include <sched.h>
#include <errno.h>
#include <pwd.h>
#include <time.h>

#include "../lib/includes.h"
#include "../lib/blacklist.h"
#include "../lib/logger.h"
#include "../lib/pbm.h"

#include "zbopt.h"

// struct zbl_stats {
//	uint32_t cidr_entries;
//	uint32_t allowed_addrs;
//	uint32_t input_addrs;
//	uint32_t uniq_input_addrs;
//	uint32_t blocked_addrs;
//	uint32_t output_addrs;
//	uint32_t duplicates;
//};

#undef MIN
#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))

// allow 1mb lines + newline + \0
#define MAX_LINE_LENGTH 1024 * 1024 + 2

static inline char *zmin(char *a, char *b)
{
	if (a && !b)
		return a;
	else if (b && !a)
		return b;
	else
		return MIN(a, b);
}

struct zbl_conf {
	char *blacklist_filename;
	char *whitelist_filename;
	char *log_filename;
	int check_duplicates;
	int ignore_blacklist_errors;
	int ignore_input_errors;
	int verbosity;
	int disable_syslog;
	// struct zbl_stats stats;
};

#define SET_IF_GIVEN(DST, ARG)                                                 \
	{                                                                      \
		if (args.ARG##_given) {                                        \
			(DST) = args.ARG##_arg;                                \
		};                                                             \
	}
#define SET_BOOL(DST, ARG)                                                     \
	{                                                                      \
		if (args.ARG##_given) {                                        \
			(DST) = 1;                                             \
		};                                                             \
	}

int main(int argc, char **argv)
{
	struct zbl_conf conf;
	conf.verbosity = 3;
	memset(&conf, 0, sizeof(struct zbl_conf));
	int no_dupchk_pres = 0;
	conf.ignore_blacklist_errors = 0;
	conf.ignore_input_errors = 0;

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

	// Set the log file and metadata file
	if (args.log_file_given) {
		conf.log_filename = strdup(args.log_file_arg);
	}
	if (args.verbosity_given) {
		conf.verbosity = args.verbosity_arg;
	}

	// Blacklist and whitelist
	if (args.blacklist_file_given) {
		conf.blacklist_filename = strdup(args.blacklist_file_arg);
	}
	if (args.whitelist_file_given) {
		conf.whitelist_filename = strdup(args.whitelist_file_arg);
	}

	// Read the boolean flags
	SET_BOOL(no_dupchk_pres, no_duplicate_checking);
	conf.check_duplicates = !no_dupchk_pres;
	SET_BOOL(conf.ignore_blacklist_errors, ignore_blacklist_errors);
	SET_BOOL(conf.ignore_input_errors, ignore_input_errors);
	SET_BOOL(conf.disable_syslog, disable_syslog);

	// initialize logging
	FILE *logfile = stderr;
	if (conf.log_filename) {
		logfile = fopen(conf.log_filename, "w");
		if (!logfile) {
			fprintf(
			    stderr,
			    "FATAL: unable to open specified logfile (%s)\n",
			    conf.log_filename);
			exit(1);
		}
	}
	if (log_init(logfile, conf.verbosity, !conf.disable_syslog,
		     "zblacklist")) {
		fprintf(stderr, "FATAL: unable able to initialize logging\n");
		exit(1);
	}

	if (!conf.blacklist_filename && !conf.whitelist_filename) {
		log_fatal("zblacklist",
			  "must specify either a whitelist or blacklist file");
	}

	// parse blacklist
	if (conf.blacklist_filename) {
		log_debug("zblacklist", "blacklist file at %s to be used",
			  conf.blacklist_filename);
	} else {
		log_debug("zblacklist", "no blacklist file specified");
	}
	if (conf.blacklist_filename &&
	    access(conf.blacklist_filename, R_OK) == -1) {
		log_fatal("zblacklist",
			  "unable to read specified blacklist file (%s)",
			  conf.blacklist_filename);
	}
	if (conf.whitelist_filename) {
		log_debug("zblacklist", "whitelist file at %s to be used",
			  conf.whitelist_filename);
	} else {
		log_debug("zblacklist", "no whitelist file specified");
	}
	if (conf.whitelist_filename &&
	    access(conf.whitelist_filename, R_OK) == -1) {
		log_fatal("zblacklist",
			  "unable to read specified whitelist file (%s)",
			  conf.whitelist_filename);
	}

	if (blacklist_init(conf.whitelist_filename, conf.blacklist_filename,
			   NULL, 0, NULL, 0, conf.ignore_blacklist_errors)) {
		log_fatal("zmap", "unable to initialize blacklist / whitelist");
	}
	// initialize paged bitmap
	uint8_t **seen = NULL;
	if (conf.check_duplicates) {
		seen = pbm_init();
		if (!seen) {
			log_fatal("zblacklist",
				  "unable to initialize paged bitmap");
		}
	}
	// process addresses
	char *line = malloc(MAX_LINE_LENGTH);
	assert(line);
	char *original = malloc(MAX_LINE_LENGTH);
	assert(original);
	while (fgets(line, MAX_LINE_LENGTH, stdin) != NULL) {
		size_t len = strlen(line);
		if (len >= (MAX_LINE_LENGTH - 1)) {
			log_fatal("zblacklist",
				  "received line longer than max length: %i",
				  MAX_LINE_LENGTH);
		}
		// remove new line
		memcpy(original, line, len + 1);
		char *n =
		    zmin(zmin(zmin(zmin(strchr(line, '\n'), strchr(line, ',')),
				   strchr(line, '\t')),
			      strchr(line, ' ')),
			 strchr(line, '#'));
		assert(n);
		n[0] = 0;
		log_debug("zblacklist", "input value %s", line);
		// parse into int
		struct in_addr addr;
		if (!inet_aton(line, &addr)) {
			log_warn("zblacklist", "invalid input address: %s",
				 line);
			if (!conf.ignore_input_errors) {
				printf("%s", original);
			}
			continue;
		}
		if (conf.check_duplicates) {
			if (pbm_check(seen, ntohl(addr.s_addr))) {
				log_debug("zblacklist",
					  "%s is a duplicate: skipped", line);
				continue;
			} else {
				log_debug("zblacklist",
					  "%s not a duplicate: skipped", line);
			}
		} else {
			log_debug("zblacklist", "no duplicate checking for %s",
				  line);
		}
		// check if in blacklist
		if (blacklist_is_allowed(addr.s_addr)) {
			if (conf.check_duplicates) {
				if (!pbm_check(seen, ntohl(addr.s_addr))) {
					pbm_set(seen, ntohl(addr.s_addr));
					printf("%s", original);
				}
			} else {
				printf("%s", original);
			}
		}
	}
	return EXIT_SUCCESS;
}
