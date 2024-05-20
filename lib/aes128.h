/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef ZMAP_AES_H
#define ZMAP_AES_H

#include <stdint.h>

#define AES128_KEY_BYTES 16
#define AES128_BLOCK_BYTES 16

typedef struct aes128_ctx aes128_ctx_t;

aes128_ctx_t *aes128_init(uint8_t const *key);
void aes128_encrypt_block(aes128_ctx_t *ctx, uint8_t const *pt, uint8_t *ct);
void aes128_fini(aes128_ctx_t *ctx);

void aes128_selftest(void);

#endif
