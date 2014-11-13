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

//struct zbl_stats {
//	uint32_t cidr_entries;
//	uint32_t allowed_addrs;
//	uint32_t input_addrs;
//	uint32_t uniq_input_addrs;
//	uint32_t blocked_addrs;
//	uint32_t output_addrs;
//	uint32_t duplicates;
//};

struct zbl_conf {
	char *blacklist_filename;
	char *whitelist_filename;
	char *metadata_filename;
	char *log_filename;
	int check_duplicates;
	int ignore_errors;
	int verbosity;
	//struct zbl_stats stats;
};

int main(int argc, char **argv)
{
	struct zbl_conf conf; 
	conf.verbosity = 3;
	memset(&conf, 0, sizeof(struct zbl_conf));
	int no_dupchk_pres;
	int ignore_bl_errs;
	struct option longopts[] = {
		{"no-duplicate-checking",  no_argument,	   &no_dupchk_pres, 0   },
		{"ignore-blacklist-errors",no_argument,	   &ignore_bl_errs, 1   },
		{"log-file",			   required_argument, NULL,			'l' },
		{"blacklist-file",		 required_argument, NULL,			'b' },
		{"whitelist-file",		 required_argument, NULL,			'w' },
		{"verbosity",			  required_argument, NULL,			'v' },
		{0, 0, 0, 0 }
	};
	// move longopt options into global configuration
	while (1) {
		int option_index = 0;
		int c = getopt_long(argc, argv, "l:b:w:v:", longopts, &option_index);
		if (c == -1) {
			break;
		}
		switch (c) {
			case 0:
				if (longopts[option_index].flag != 0) {
					break;
				}
			case 'm':
				conf.metadata_filename = strdup(optarg);
				break;
			case 'l':
				conf.log_filename = strdup(optarg);
				break;
			case 'b':
				conf.blacklist_filename = strdup(optarg);
				break;
			case 'w':
				conf.whitelist_filename = strdup(optarg);
				break;
			case 'v':
				conf.verbosity = atoi(optarg);
				break;

			default:
				fprintf(stderr, "FATAL: unknown state entered in getopt\n");
				exit(EXIT_FAILURE);
		}
	}
	conf.check_duplicates = (!no_dupchk_pres);
	conf.ignore_errors = ignore_bl_errs;	
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
	if (log_init(logfile, conf.verbosity, 1, "zblacklist")) {
		fprintf(stderr, "FATAL: unable able to initialize logging\n");
		exit(1);
	}

	if (!conf.blacklist_filename && !conf.whitelist_filename) {
		log_fatal("zblacklist", "must specify either a whitelist or blacklist file");
	}
   
	// parse blacklist
	if (conf.blacklist_filename) {
		log_debug("zblacklist", "blacklist file at %s to be used", conf.blacklist_filename);
	} else {
		log_debug("zblacklist", "no blacklist file specified");
	}
	if (conf.blacklist_filename && access(conf.blacklist_filename, R_OK) == -1) {
		log_fatal("zblacklist", "unable to read specified blacklist file (%s)",
				conf.blacklist_filename);
	}
	if (conf.whitelist_filename) {
		log_debug("zblacklist", "whitelist file at %s to be used", conf.whitelist_filename);
	} else {
		log_debug("zblacklist", "no whitelist file specified");
	}
	if (conf.whitelist_filename && access(conf.whitelist_filename, R_OK) == -1) {
		log_fatal("zblacklist", "unable to read specified whitelist file (%s)",
				conf.whitelist_filename);
	}

	if (blacklist_init(conf.whitelist_filename, conf.blacklist_filename,
			NULL, 0, NULL, 0, conf.ignore_errors)) {
		log_fatal("zmap", "unable to initialize blacklist / whitelist");
	}
	// initialize paged bitmap
	uint8_t **seen = NULL;
	if (conf.check_duplicates) {
		seen = pbm_init();
		if (!seen) {
			log_fatal("zblacklist", "unable to initialize paged bitmap");
		}
	}
	// process addresses	
	char line[1000]; 
	while (fgets(line, sizeof(line), stdin) != NULL) {
		// remove new line
		char *n = strchr(line, '\n');
		assert(n);
		n[0] = 0;
		log_trace("zblacklist", "input value %s", line);
		// parse into int
		struct in_addr addr;
		if (!inet_aton(line, &addr)) {
			log_warn("zblacklist", "invalid input address: %s", line);
		}
		if (conf.check_duplicates) {
			if (pbm_check(seen, ntohl(addr.s_addr))) {
				log_trace("zblacklist", "%s is a duplicate: skipped", line);
				continue;
			} else {
				log_trace("zblacklist", "%s not a duplicate: skipped", line);
			}
		} else {
				log_trace("zblacklist", "no duplicate checking for %s", line);
		}
		// check if in blacklist
		if (blacklist_is_allowed(addr.s_addr)) {
			if (conf.check_duplicates) {
				if (!pbm_check(seen, ntohl(addr.s_addr))) {
					pbm_set(seen, ntohl(addr.s_addr));
					printf("%s\n", line);
				}
			} else {
				printf("%s\n", line);
			}
		}	}
	return EXIT_SUCCESS;
}

