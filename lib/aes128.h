/*
 * This file copyright 2024, Daniel Roethlisberger <daniel@roe.ch>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ZMAP_AES_H
#define ZMAP_AES_H

#include <stdint.h>

#define AES128_KEY_BYTES 16
#define AES128_BLOCK_BYTES 16

typedef struct aes128_ctx aes128_ctx_t;

aes128_ctx_t * aes128_init(uint8_t const *key);
void aes128_encrypt_block(aes128_ctx_t *ctx, uint8_t const *pt, uint8_t *ct);
void aes128_fini(aes128_ctx_t *ctx);

void aes128_selftest(void);

#endif
