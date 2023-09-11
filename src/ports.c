/*
 * ZMap Copyright 2023 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

/*
 * ZIterate is a simple utility that will iteratate over the IPv4
 * space in a pseudo-random fashion, utilizing the sharding capabilities * of
 * ZMap.
 */

#define _GNU_SOURCE

#include <stdlib.h>

#include "state.h"
#include "../lib/pbm.h"
#include "../lib/logger.h"

static void add_port(struct port_conf *ports, int port)
{
	if (port < 0 || port > 0xFFFF) {
		log_fatal("ports", "invalid target port specified: %i", port);
	}
	ports->ports[ports->port_count] = port;
	if (ports->port_bitmap) {
		bm_set(ports->port_bitmap, port);
	}
	ports->port_count++;
}

void parse_ports(char *portdef, struct port_conf *ports)
{
	if (!strcmp(portdef, "*")) {
		for (int i = 0; i <= 0xFFFF; i++) {
			add_port(ports, i);
		}
		return;
	}
	char *next = strtok(portdef, ",");
	while (next != NULL) {
		char *dash = strchr(next, '-');
		if (dash) { // range
			*dash = '\0';
			int first = atoi(next);
			int last = atoi(dash + 1);
			if (last > 0xFFFF) {
				log_fatal("ports",
					  "invalid target port specified: %i",
					  last);
			}
			for (int i = first; i <= last; i++) {
				add_port(ports, i);
			}
		} else {
			add_port(ports, atoi(next));
		}
		next = strtok(NULL, ",");
	}
}
