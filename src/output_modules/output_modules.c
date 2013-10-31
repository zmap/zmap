/*
 * ZMap Copyright 2013 Regents of the University of Michigan 
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include <stdio.h>
#include <string.h>

#include "output_modules.h"

extern output_module_t module_csv_file;

#ifdef REDIS
extern output_module_t module_redis;
extern output_module_t module_csv_redis;
#endif

#ifdef JSON
extern output_module_t module_json_file;
#endif

output_module_t* output_modules[] = {
	&module_csv_file,
#ifdef REDIS
	&module_redis,
	&module_csv_redis,
#endif
#ifdef JSON
	&module_json_file
#endif
	// ADD YOUR MODULE HERE
};

output_module_t* get_output_module_by_name(const char* name)
{
    int num_modules = (int) (sizeof(output_modules)/sizeof(output_modules[0]));
	for (int i=0; i < num_modules; i++) {
		if (!strcmp(output_modules[i]->name, name)) {
			return output_modules[i];
		}
	}
	return NULL;
}

void print_output_modules(void)
{
    int num_modules = (int) (sizeof(output_modules)/sizeof(output_modules[0]));
	for (int i=0; i < num_modules; i++) {
		printf("%s\n", output_modules[i]->name);
	}
}

