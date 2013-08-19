/*
 * ZMap Copyright 2013 Regents of the University of Michigan 
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include "cidr.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <assert.h>
#include <string.h>
#include <math.h>

#include "../lib/logger.h"
#include "../lib/blacklist.h"

#include "state.h"
#include "aesrand.h"


static uint32_t current = 0;

int cidr_init(uint32_t current_)
{
	// uint32_t val = current_;
	// val = ((val << 8) & 0xFF00FF00 ) | ((val >> 8) & 0xFF00FF ); 
	// current = (val << 16) | (val >> 16);
	current = current_-1;

	return 0;
}

uint32_t cidr_get_next_ip(void)
{
	// while (1) {
		uint32_t val = current++;
		val = ((val << 8) & 0xFF00FF00 ) | ((val >> 8) & 0xFF00FF ); 
	// 	printf("get candidate");
	// 	uint32_t candidate  = current++;
	// 	if (!blacklist_is_allowed(candidate)) {
	// 		zsend.blacklisted++;
	// 	} else {
	// 		return candidate;
	// 	}
	// }

	return (val << 16) | (val >> 16);
}

uint32_t cidr_get_curr_ip(void)
{
	uint32_t val = current;
	val = ((val << 8) & 0xFF00FF00 ) | ((val >> 8) & 0xFF00FF ); 
	return  (val << 16) | (val >> 16);
}

//Split CIDR
char** cidr_split(char* a_str, const char* s)
{
	char ** res  = NULL;
	char *  p    = strtok (a_str, s);
	int n_spaces = 0;


	/* split string and append tokens to 'res' */

	while (p) {
	  res = realloc (res, sizeof (char*) * ++n_spaces);

	  if (res == NULL)
	    exit (-1); /* memory allocation failed */

	  res[n_spaces-1] = p;

	  p = strtok (NULL, ".");
	}


	/* realloc one extra element for the last NULL */

	res = realloc (res, sizeof (char*) * (n_spaces+1));
	res[n_spaces] = 0;


	return res;
}