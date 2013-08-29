/*
 * ZMap Copyright 2013 Regents of the University of Michigan 
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include <stdint.h>

#ifndef AESRAND_H
#define AESRAND_H

void aesrand_init(uint32_t seed);

uint64_t aesrand_getword(void);

#endif
