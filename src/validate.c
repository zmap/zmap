/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include <stdint.h>
#include <assert.h>
#include "../lib/aes128.h"
#include "../lib/random.h"
#include "../lib/logger.h"
#include "validate.h"

static aes128_ctx_t *aes128 = NULL;

void validate_init(void)
{
	uint8_t key[AES128_KEY_BYTES];
	if (!random_bytes(key, sizeof(key))) {
		log_fatal("validate", "couldn't get random bytes");
	}
	aes128 = aes128_init(key);
}

void validate_gen(const uint32_t src, const uint32_t dst,
		  const uint16_t dst_port, uint8_t output[VALIDATE_BYTES])
{
	validate_gen_ex(src, dst, (uint32_t)dst_port, 0, output);
}

void validate_gen_ex(const uint32_t input0, const uint32_t input1,
		     const uint32_t input2, const uint32_t input3,
		     uint8_t output[VALIDATE_BYTES])
{
	assert(aes128);

	uint32_t aes_input[AES128_BLOCK_BYTES / sizeof(uint32_t)];
	aes_input[0] = input0;
	aes_input[1] = input1;
	aes_input[2] = input2;
	aes_input[3] = input3;
	aes128_encrypt_block(aes128, (uint8_t *)aes_input, output);
}
