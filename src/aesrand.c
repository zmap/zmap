/*
 * ZMap Copyright 2013 Regents of the University of Michigan 
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>

#include "../lib/rijndael-alg-fst.h"
#include "../lib/random.h"
#include "../lib/logger.h"

#define AES_ROUNDS 10
#define AES_BLOCK_WORDS  4
#define AES_KEY_BYTES 16
#define OUTPUT_BYTES 16

static uint32_t aes_input[AES_BLOCK_WORDS];
static uint32_t aes_sched[(AES_ROUNDS+1)*4];
static uint8_t aes_output[OUTPUT_BYTES];
static int init = 0;

void aesrand_init(uint32_t seed)
{
	memset(&aes_input, 0, sizeof(aes_input));
	uint8_t key[AES_KEY_BYTES];
	if (seed) {
		memset(key, 0, AES_KEY_BYTES*sizeof(uint8_t));
		memcpy(key, &seed, sizeof(uint32_t));
	} else {
		if (!random_bytes(key, AES_KEY_BYTES)) {
    		log_fatal("aesrand", "couldn't get random bytes");
  		}
	}
	if (rijndaelKeySetupEnc(aes_sched, key, AES_KEY_BYTES*8) != AES_ROUNDS) {
		log_fatal("aesrand", "could not initialize AES key");
	}
	memset(aes_output, 0, OUTPUT_BYTES*sizeof(uint8_t));
	init = 1;
}

uint64_t aesrand_getword(void)
{
	assert(init);
	memcpy(aes_input, aes_output, sizeof(aes_input));
	rijndaelEncrypt(aes_sched, AES_ROUNDS,
		(uint8_t *)aes_input, aes_output);
	uint64_t retval;
	memcpy(&retval, aes_output, sizeof(retval)); 
	return retval;
}

