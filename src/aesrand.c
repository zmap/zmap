/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>

#include "../lib/logger.h"
#include "../lib/aes128.h"
#include "../lib/random.h"
#include "../lib/xalloc.h"

#include "aesrand.h"

struct aesrand {
	uint32_t input[AES128_BLOCK_BYTES / sizeof(uint32_t)];
	uint8_t output[AES128_BLOCK_BYTES];
	bool remaining;
	aes128_ctx_t *aes128;
};

static aesrand_t *_aesrand_init(uint8_t *key)
{
	aesrand_t *aes = xmalloc(sizeof(aesrand_t));
	memset(aes, 0, sizeof(*aes));
	aes->aes128 = aes128_init(key);
	return aes;
}

aesrand_t *aesrand_init_from_seed(uint64_t seed)
{
	uint8_t key[AES128_KEY_BYTES];
	memset(key, 0, sizeof(key));
	for (size_t i = 0; i < sizeof(seed); ++i) {
		key[i] = (uint8_t)((seed >> 8 * i) & 0xFF);
	}
	return _aesrand_init(key);
}

aesrand_t *aesrand_init_from_random(void)
{
	uint8_t key[AES128_KEY_BYTES];
	if (!random_bytes(key, sizeof(key))) {
		log_fatal("aesrand", "Couldn't get random bytes");
	}
	return _aesrand_init(key);
}

uint64_t aesrand_getword(aesrand_t *aes)
{
	uint64_t retval;

	if (aes->remaining) {
		memcpy(&retval, &aes->output[sizeof(retval)], sizeof(retval));
		aes->remaining = false;
		return retval;
	}

	memcpy(aes->input, aes->output, sizeof(aes->input));
	aes128_encrypt_block(aes->aes128, (uint8_t *)aes->input, aes->output);
	memcpy(&retval, aes->output, sizeof(retval));
	aes->remaining = true;
	return retval;
}
