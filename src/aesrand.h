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

typedef struct aesrand aesrand_t;

aesrand_t* aesrand_init_from_random();

aesrand_t* aesrand_init_from_seed(uint64_t);

uint64_t aesrand_getword(aesrand_t *aes);

aesrand_t* aesrand_free(aesrand_t *aes);

#endif
