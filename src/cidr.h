/*
 * ZMap Copyright 2013 Regents of the University of Michigan 
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include <stdint.h>

#ifndef _CIDR_H
#define _CIDR_H

int cidr_init(uint32_t);

// get next IP address to scan
uint32_t cidr_get_next_ip(void);

// what IP address was returned last
uint32_t cidr_get_curr_ip(void);

// Split CIDR
char** cidr_split(char*, const char*);

#endif
