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

#include "rijndael-alg-fst.h"
#include "random.h"
#include "logger.h"
#include "xalloc.h"

#include "aesrand.h"

#define AES_ROUNDS 10
#define AES_BLOCK_WORDS  4
#define AES_KEY_BYTES 16
#define AES_KEY_BITS (AES_KEY_BYTES*8)
#define OUTPUT_BYTES 16

struct aesrand {
	uint32_t input[AES_BLOCK_WORDS];
	uint32_t sched[(AES_ROUNDS+1)*4];
	uint8_t output[OUTPUT_BYTES];
};

static aesrand_t* _aesrand_init(uint8_t *key)
{
	aesrand_t *aes = xmalloc(sizeof(aesrand_t));
	memset(&aes->input, 0, AES_BLOCK_WORDS*4);
	if (rijndaelKeySetupEnc(aes->sched, key, AES_KEY_BITS) != AES_ROUNDS) {
		log_fatal("aesrand", "could not initialize AES key");
	}
	memset(aes->output, 0, OUTPUT_BYTES);
	return aes;
}

aesrand_t* aesrand_init_from_seed(uint64_t seed)
{
	uint8_t key[AES_KEY_BYTES];
	memset(key, 0, AES_KEY_BYTES);
	for (uint8_t i = 0; i < sizeof(seed); ++i) {
		key[i] = (uint8_t) ((seed >> 8*i) & 0xFF);
	}
	return _aesrand_init(key);
}

aesrand_t* aesrand_init_from_random()
{
	uint8_t key[AES_KEY_BYTES];
	if (!random_bytes(key, AES_KEY_BYTES)) {
		log_fatal("aesrand", "Couldn't get random bytes");
	}
	return _aesrand_init(key);
}

uint64_t aesrand_getword(aesrand_t *aes)
{
	memcpy(aes->input, aes->output, sizeof(aes->input));
	rijndaelEncrypt(aes->sched, AES_ROUNDS,
		(uint8_t *)aes->input, aes->output);
	uint64_t retval;
	memcpy(&retval, aes->output, sizeof(retval));
	return retval;
}
