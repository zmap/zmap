/*
 * ZMap Copyright 2013 Regents of the University of Michigan 
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include <stdio.h>
#include <string.h>

#include "probe_modules.h"

extern probe_module_t module_tcp_synscan;
extern probe_module_t module_icmp_echo;
extern probe_module_t module_udp;
// ADD YOUR MODULE HERE

probe_module_t* probe_modules[] = {
	&module_tcp_synscan,
	&module_icmp_echo,
	&module_udp
	// ADD YOUR MODULE HERE
};


probe_module_t* get_probe_module_by_name(const char* name)
{
	for (int i=0; i < (int) (sizeof(probe_modules)/sizeof(probe_modules[0])); i++) {
		if (!strcmp(probe_modules[i]->name, name)) {
			return probe_modules[i];
		}
	}
	return NULL;
}

void print_probe_modules(void)
{
	for (int i=0; i < (int) (sizeof(probe_modules)/sizeof(probe_modules[0])); i++) {
		printf("%s\n", probe_modules[i]->name);
	}
}
