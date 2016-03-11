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
#include <getopt.h>
#include <assert.h>

#include "iterator.h"
#include "../lib/includes.h"
#include "../lib/blacklist.h"
#include "../lib/logger.h"
#include "../lib/random.h"
#include "validate.h"
#include "zitopt.h"

struct zit_conf {
	char *blacklist_filename;
	char *whitelist_filename;
	char *log_filename;
	int check_duplicates;
	int ignore_errors;
	int verbosity;
	// sharding options
	uint8_t shard_num;
	uint8_t total_shards;
	uint64_t seed;
	aesrand_t *aes;
};

#define SET_BOOL(DST,ARG) \
   { if (args.ARG##_given) { (DST) = 1; }; }

int main(int argc, char **argv)
{
	struct zit_conf conf;

	memset(&conf, 0, sizeof(struct zit_conf));
	conf.verbosity = 3;
	int no_dupchk_pres = 0;
  conf.ignore_errors = 0;

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
  SET_BOOL(conf.ignore_errors, ignore_blacklist_errors);

	// initialize logging
	FILE *logfile = stderr;
	if (conf.log_filename) {
		logfile = fopen(conf.log_filename, "w");
		if (!logfile) {
			fprintf(stderr, "FATAL: unable to open specified logfile (%s)\n",
					conf.log_filename);
			exit(1);
		}
	}
	if (log_init(logfile, conf.verbosity, 1, "ziterate")) {
		fprintf(stderr, "FATAL: unable able to initialize logging\n");
		exit(1);
	}

	if (!conf.blacklist_filename && !conf.whitelist_filename) {
		log_fatal("ziterate", "must specify either a whitelist or blacklist file");
	}

	// parse blacklist
	if (conf.blacklist_filename) {
		log_debug("ziterate", "blacklist file at %s to be used", conf.blacklist_filename);
	} else {
		log_debug("ziterate", "no blacklist file specified");
	}
	if (conf.blacklist_filename && access(conf.blacklist_filename, R_OK) == -1) {
		log_fatal("ziterate", "unable to read specified blacklist file (%s)",
				conf.blacklist_filename);
	}
	if (conf.whitelist_filename) {
		log_debug("ziterate", "whitelist file at %s to be used", conf.whitelist_filename);
	} else {
		log_debug("ziterate", "no whitelist file specified");
	}
	if (conf.whitelist_filename && access(conf.whitelist_filename, R_OK) == -1) {
		log_fatal("ziterate", "unable to read specified whitelist file (%s)",
				conf.whitelist_filename);
	}

	if (blacklist_init(conf.whitelist_filename, conf.blacklist_filename,
			NULL, 0, NULL, 0, conf.ignore_errors)) {
		log_fatal("ziterate", "unable to initialize blacklist / whitelist");
	}

	// Set up sharding
	conf.shard_num = 0;
	conf.total_shards = 1;
	if ((args.shard_given || args.shards_given) && !args.seed_given) {
		log_fatal("ziterate", "Need to specify seed if sharding a scan");
	}
	if (args.shard_given ^ args.shards_given) {
		log_fatal("ziterate",
			  "Need to specify both shard number and total number of shards");
	}
	if (args.shard_given) {
  //XXX		enforce_range("shard", args.shard_arg, 0, 254);
    conf.shard_num = args.shard_arg;
	}
	if (args.shards_given) {
 //XXX		enforce_range("shards", args.shards_arg, 1, 254);
    conf.total_shards = args.shards_arg;
	}
	// Check for a random seed
	if (args.seed_given) {
		conf.seed = args.seed_arg;
	} else {
		// generate a seed randomly
		if (!random_bytes(&conf.seed, sizeof(uint64_t))) {
			log_fatal("ziterate", "unable to generate random bytes "
 					"needed for seed");
		}
  }
	if (conf.shard_num >= conf.total_shards) {
		log_fatal("ziterate", "With %hhu total shards, shard number (%hhu)"
			  " must be in range [0, %hhu)", conf.total_shards,
			  conf.shard_num, conf.total_shards);
	}
	validate_init();
	conf.aes = aesrand_init_from_seed(conf.seed);
	log_debug("ziterate", "Initializing sharding (%d shards, shard number %d, seed %d)", conf.total_shards, conf.shard_num, conf.seed);
	/*
		* XXX: this currently segfaults.  iterator.c's iterator_init calls cylic.c's make_cycle:
		*
		*   it->cycle = make_cycle(group, zconf.aes);
		*
		* cyclic.c's make_cycle calls find_primroot:
		*
		*   cycle.generator = find_primroot(group, aes);
		*
		* which calls cyclic.c's find_primroot:
		*
		*   uint32_t candidate = (uint32_t) ((aesrand_getword(aes) & 0xFFFFFFFF) % group->prime);
		*
		* which calls aesrand.c's aesrand_getword call, which segfaults here
		*
		*   memcpy(aes->input, aes->output, sizeof(aes->input));
		*/
	iterator_t *it = iterator_init(conf.seed, conf.shard_num, conf.total_shards);
	shard_t *shard = get_shard(it, 1);
	uint32_t next_ip = shard_get_cur_ip(shard);

	while (next_ip != 0) {
		next_ip = shard_get_cur_ip(shard);

		/* TODO
		// check if in blacklist
		if (blacklist_is_allowed(addr.s_addr)) {
				printf("%s", original);
		}
		*/
	}

	return EXIT_SUCCESS;
}