/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include "aes128.h"

#include "../lib/rijndael-alg-fst.h"
#include "../lib/logger.h"

#include <stdbool.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#define AES128_ROUNDS 10
#define BITS_PER_BYTE 8

#ifdef AES_HW

#if defined(__x86_64__)
#define AES_HW_NAME "AES-NI"

#include <wmmintrin.h>
#include <cpuid.h>

static bool
aes128_hw_supported(void)
{
	static const uint32_t flag_cpuid_ecx_aesni = 0x02000000;
	uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0;
	__cpuid(1, eax, ebx, ecx, edx);
	return (ecx & flag_cpuid_ecx_aesni) != 0;
}

#if defined(__clang__)
#pragma clang attribute push(__attribute__((target("sse2,aes"))), apply_to = function)
#elif defined(__GNUC__)
#pragma GCC push_options
#pragma GCC target("sse2,aes")
#endif

struct aes128_hw_ctx {
	__m128i rk[AES128_ROUNDS + 1];
};

static __m128i
aes128_hw_round_key(__m128i rk, __m128i rc)
{
	rc = _mm_shuffle_epi32(rc, _MM_SHUFFLE(3, 3, 3, 3));
	rk = _mm_xor_si128(rk, _mm_slli_si128(rk, 4));
	rk = _mm_xor_si128(rk, _mm_slli_si128(rk, 4));
	rk = _mm_xor_si128(rk, _mm_slli_si128(rk, 4));
	return _mm_xor_si128(rk, rc);
}

static void
aes128_hw_key_sched(uint8_t const *key, struct aes128_hw_ctx *ctx)
{
	__m128i *rk = ctx->rk;
	rk[0] = _mm_loadu_si128((__m128i const *)key);
	rk[1] = aes128_hw_round_key(rk[0], _mm_aeskeygenassist_si128(rk[0], 0x01));
	rk[2] = aes128_hw_round_key(rk[1], _mm_aeskeygenassist_si128(rk[1], 0x02));
	rk[3] = aes128_hw_round_key(rk[2], _mm_aeskeygenassist_si128(rk[2], 0x04));
	rk[4] = aes128_hw_round_key(rk[3], _mm_aeskeygenassist_si128(rk[3], 0x08));
	rk[5] = aes128_hw_round_key(rk[4], _mm_aeskeygenassist_si128(rk[4], 0x10));
	rk[6] = aes128_hw_round_key(rk[5], _mm_aeskeygenassist_si128(rk[5], 0x20));
	rk[7] = aes128_hw_round_key(rk[6], _mm_aeskeygenassist_si128(rk[6], 0x40));
	rk[8] = aes128_hw_round_key(rk[7], _mm_aeskeygenassist_si128(rk[7], 0x80));
	rk[9] = aes128_hw_round_key(rk[8], _mm_aeskeygenassist_si128(rk[8], 0x1B));
	rk[10] = aes128_hw_round_key(rk[9], _mm_aeskeygenassist_si128(rk[9], 0x36));
}

static void
aes128_hw_enc_block(struct aes128_hw_ctx const *ctx, uint8_t const *pt, uint8_t *ct)
{
	__m128i const *rk = ctx->rk;
	__m128i block = _mm_loadu_si128((__m128i *)pt);
	block = _mm_xor_si128(block, rk[0]);
	block = _mm_aesenc_si128(block, rk[1]);
	block = _mm_aesenc_si128(block, rk[2]);
	block = _mm_aesenc_si128(block, rk[3]);
	block = _mm_aesenc_si128(block, rk[4]);
	block = _mm_aesenc_si128(block, rk[5]);
	block = _mm_aesenc_si128(block, rk[6]);
	block = _mm_aesenc_si128(block, rk[7]);
	block = _mm_aesenc_si128(block, rk[8]);
	block = _mm_aesenc_si128(block, rk[9]);
	block = _mm_aesenclast_si128(block, rk[10]);
	_mm_storeu_si128((__m128i *)ct, block);
}

#if defined(__clang__)
#pragma clang attribute pop
#elif defined(__GNUC__)
#pragma GCC pop_options
#endif

#elif defined(__aarch64__)
#define AES_HW_NAME "ARMv8 CE"

#ifdef __ARM_ACLE
#include <arm_acle.h>
#endif
#ifdef __ARM_NEON
#include <arm_neon.h>
#endif

#if defined(__APPLE__)
#include <sys/types.h>
#include <sys/sysctl.h>
#elif defined(__FreeBSD__)
#include <sys/auxv.h>
#ifndef HWCAP_NEON
#define HWCAP_NEON 0x00001000
#endif
#ifndef HWCAP2_AES
#define HWCAP2_AES 0x00000001
#endif
#elif defined(__linux__)
#include <sys/auxv.h>
#ifndef HWCAP_NEON
#define HWCAP_NEON 0x00000010
#endif
#ifndef HWCAP_AES
#define HWCAP_AES 0x00001000
#endif
#else
#warning "Runtime detection of AES hardware acceleration not implemented for platform"
#endif

static bool
aes128_hw_supported(void)
{
#if defined(__APPLE__)
	int value = 0;
	size_t value_len = sizeof(value);
	if (sysctlbyname("hw.optional.arm.FEAT_AES", &value, &value_len, NULL, 0) == -1) {
		return false;
	}
	assert(value_len == sizeof(value));
	return (value != 0);
#elif defined(__FreeBSD__)
	unsigned long hwcap = 0, hwcap2 = 0;
	elf_aux_info(AT_HWCAP, &hwcap, sizeof(hwcap));
	elf_aux_info(AT_HWCAP2, &hwcap2, sizeof(hwcap2));
	return ((hwcap & HWCAP_NEON) && (hwcap2 & HWCAP2_AES));
#elif defined(__linux__)
	unsigned long hwcap = getauxval(AT_HWCAP);
	return ((hwcap & HWCAP_NEON) && (hwcap & HWCAP_AES));
#else
	return true;
#endif
}

#if defined(__clang__)
#pragma clang attribute push(__attribute__((target("aes"))), apply_to = function)
#elif defined(__GNUC__)
#pragma GCC push_options
#pragma GCC target("+aes")
#endif

struct aes128_hw_ctx {
	uint8_t rk[AES128_ROUNDS + 1][AES128_KEY_BYTES];
};

// clang-format off
static uint8_t const sbox[256] = {
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};
// clang-format on

static uint8_t const rcon[AES128_ROUNDS + 1] = {0, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

static void
aes128_hw_key_sched(uint8_t const *key, struct aes128_hw_ctx *ctx)
{
	memcpy(ctx->rk[0], key, AES128_KEY_BYTES);
	for (size_t i = 1; i < AES128_ROUNDS + 1; i++) {
		ctx->rk[i][0] = ctx->rk[i - 1][0] ^ sbox[ctx->rk[i - 1][13]] ^ rcon[i];
		ctx->rk[i][1] = ctx->rk[i - 1][1] ^ sbox[ctx->rk[i - 1][14]];
		ctx->rk[i][2] = ctx->rk[i - 1][2] ^ sbox[ctx->rk[i - 1][15]];
		ctx->rk[i][3] = ctx->rk[i - 1][3] ^ sbox[ctx->rk[i - 1][12]];
		*(uint32_t *)&ctx->rk[i][4] = *(uint32_t *)&ctx->rk[i - 1][4] ^ *(uint32_t *)&ctx->rk[i][0];
		*(uint32_t *)&ctx->rk[i][8] = *(uint32_t *)&ctx->rk[i - 1][8] ^ *(uint32_t *)&ctx->rk[i][4];
		*(uint32_t *)&ctx->rk[i][12] = *(uint32_t *)&ctx->rk[i - 1][12] ^ *(uint32_t *)&ctx->rk[i][8];
	}
}

static void
aes128_hw_enc_block(struct aes128_hw_ctx const *ctx, uint8_t const *pt, uint8_t *ct)
{
	uint8x16_t block = vld1q_u8(pt);
	block = vaeseq_u8(block, vld1q_u8(ctx->rk[0]));
	block = vaesmcq_u8(block);
	block = vaeseq_u8(block, vld1q_u8(ctx->rk[1]));
	block = vaesmcq_u8(block);
	block = vaeseq_u8(block, vld1q_u8(ctx->rk[2]));
	block = vaesmcq_u8(block);
	block = vaeseq_u8(block, vld1q_u8(ctx->rk[3]));
	block = vaesmcq_u8(block);
	block = vaeseq_u8(block, vld1q_u8(ctx->rk[4]));
	block = vaesmcq_u8(block);
	block = vaeseq_u8(block, vld1q_u8(ctx->rk[5]));
	block = vaesmcq_u8(block);
	block = vaeseq_u8(block, vld1q_u8(ctx->rk[6]));
	block = vaesmcq_u8(block);
	block = vaeseq_u8(block, vld1q_u8(ctx->rk[7]));
	block = vaesmcq_u8(block);
	block = vaeseq_u8(block, vld1q_u8(ctx->rk[8]));
	block = vaesmcq_u8(block);
	block = vaeseq_u8(block, vld1q_u8(ctx->rk[9]));
	block = veorq_u8(block, vld1q_u8(ctx->rk[10]));
	vst1q_u8(ct, block);
}

#if defined(__clang__)
#pragma clang attribute pop
#elif defined(__GNUC__)
#pragma GCC pop_options
#endif

#else
#error "AES hardware acceleration not implemented for this architecture"
#endif

#endif // AES_HW

struct aes128_ctx {
	union {
		struct {
			uint32_t rk[(AES128_ROUNDS + 1) * 4];
		} sw;
#ifdef AES_HW
		struct aes128_hw_ctx hw;
#endif
	} u;
};

#ifdef AES_HW
static bool use_hw = false;
#endif
static pthread_once_t aes128_inited = PTHREAD_ONCE_INIT;

static void
aes128_init_once(void)
{
#ifdef AES_HW
	use_hw = aes128_hw_supported();
	if (use_hw) {
		log_debug("aes128", "AES hardware acceleration available, using " AES_HW_NAME);
	} else {
		log_debug("aes128", "AES hardware acceleration unavailable, using software AES");
	}
#else
	log_debug("aes128", "Built without AES hardware acceleration, using software AES");
#endif
}

aes128_ctx_t *
aes128_init(uint8_t const *key)
{
	pthread_once(&aes128_inited, aes128_init_once);

	aes128_ctx_t *ctx = (aes128_ctx_t *)malloc(sizeof(aes128_ctx_t));
	assert(ctx);
	memset(ctx, 0, sizeof(aes128_ctx_t));

#ifdef AES_HW
	if (use_hw) {
		aes128_hw_key_sched(key, &ctx->u.hw);
		return ctx;
	}
#endif

	int rv = rijndaelKeySetupEnc(ctx->u.sw.rk, key, AES128_KEY_BYTES * BITS_PER_BYTE);
	assert(rv == AES128_ROUNDS);
	return ctx;
}

void aes128_encrypt_block(aes128_ctx_t *ctx, uint8_t const *pt, uint8_t *ct)
{
#ifdef AES_HW
	if (use_hw) {
		aes128_hw_enc_block(&ctx->u.hw, pt, ct);
		return;
	}
#endif

	rijndaelEncrypt(ctx->u.sw.rk, AES128_ROUNDS, pt, ct);
}

void aes128_fini(aes128_ctx_t *ctx)
{
	free(ctx);
}

void aes128_selftest(void)
{
	// Test vector from appendix C of NIST FIPS-197.
	uint8_t const pt[AES128_BLOCK_BYTES] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
	uint8_t const key[AES128_KEY_BYTES] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
	uint8_t const expected_ct[AES128_BLOCK_BYTES] = {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a};

	uint8_t actual_ct[AES128_BLOCK_BYTES];
	memset(actual_ct, 0, sizeof(actual_ct));

	aes128_ctx_t *ctx = aes128_init(key);
	aes128_encrypt_block(ctx, pt, actual_ct);
	aes128_fini(ctx);

	if (memcmp(actual_ct, expected_ct, AES128_BLOCK_BYTES) != 0) {
		log_fatal("aes128", "AES self-test with NIST test vector failed");
	}
}
