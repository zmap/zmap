/*
 * ZMapv6 Copyright 2016 Chair of Network Architectures and Services
 * Technical University of Munich
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "../lib/logger.h"

#define LOGGER_NAME "ipv6_target_file"

static FILE *fp;

int ipv6_target_file_init(char *file)
{
	fp = fopen(file, "r");
	if (fp == NULL) {
		log_fatal(LOGGER_NAME, "unable to open %s file: %s: %s",
				LOGGER_NAME, file, strerror(errno));
		return 1;
	}

	return 0;
}

int ipv6_target_file_get_ipv6(struct in6_addr *dst)
{
    // ipv6_target_file_init() needs to be called before ipv6_target_file_get_ipv6()
	assert(fp);

	char line[100];

	if (fgets(line, sizeof(line), fp) != NULL) {
		// Remove newline
		char *pos;
		if ((pos = strchr(line, '\n')) != NULL) {
			*pos = '\0';
		}
		int rc = inet_pton(AF_INET6, line, dst);
		if (rc != 1) {
			log_fatal(LOGGER_NAME, "could not parse IPv6 address from line: %s: %s", line, strerror(errno));
			return 1;
		}
	} else {
		return 1;
	}

	return 0;
}

int ipv6_target_file_deinit()
{
	fclose(fp);
	fp = NULL;

	return 0;
}

