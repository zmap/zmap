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

void parse_ports(char *portdef, struct port_conf *ports) {
	if (!strcmp(portdef, "*")) {
		for (uint16_t i = 0; i < 0xFFFF; i++) {
			ports->ports[i] = i;
			if (ports->port_bitmap) {
				bm_set(ports->port_bitmap, i);
			}
		}
		ports->port_count = 0xFFFF;
		return;
	}
	char *next = strtok(portdef, ",");
	while (next != NULL) {
		uint16_t port = (uint16_t) atoi(next);
		ports->ports[zconf.ports->port_count] = port;
		ports->port_count++;
		if (ports->port_bitmap) {
			bm_set(ports->port_bitmap, port);
		}
		next = strtok(NULL, ",");
	}
}
