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

void parse_ports(char *portdef, struct port_conf *ports) {
	if (!strcmp(portdef, "*")) {
		for (uint16_t i; i < 0xFFFF; i++) {
			zconf.ports->ports[i] = i;
		}
		zconf.ports->port_count = 0xFFFF;
		return
	}
	char *next = strtok(args.target_ports_arg, ",");
	while (next != NULL) {
		uint16_t port = (uint16_t) atoi(next);
		enforce_range("target-port", port, 0, 0xFFFF);
		zconf.ports->ports[zconf.ports->port_count] = port;
		zconf.ports->port_count++;
		next = strtok(NULL, ",");
	}
}
