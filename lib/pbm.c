#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "logger.h"

#define NUM_VALUES 0xFFFFFFFF
#define PAGE_SIZE 0xFFFF
#define NUM_PAGES (NUM_VALUES / PAGE_SIZE)
#define SIZE (8*sizeof(uint64_t))

uint64_t** pbm_init(void)
{
	uint64_t** retv = calloc(NUM_PAGES, sizeof(void*));
	if (!retv) {
		log_fatal("pbm", "unable to allocate memory for base page table");
	}
	return retv;
}

static int bm_check(uint64_t *bm, uint32_t v)
{
	return bm[v/SIZE] & (1<< (v % SIZE));
}

static void bm_set(uint64_t *bm, uint32_t v) 
{
	bm[v/SIZE] |= (1 << (v % SIZE));
}

int pbm_check(uint64_t **b, uint32_t v)
{
	uint32_t top = v >> 16;
	uint32_t bottom = v & PAGE_SIZE;
	return b[top] && bm_check(b[top], bottom);
}

void pbm_set(uint64_t **b, uint32_t v)
{
	uint32_t top = v >> 16;
	uint32_t bottom = v & PAGE_SIZE;
	if (!b[top]) {
		uint64_t *bm = malloc(PAGE_SIZE/8);
		if (!bm) {
			log_fatal("bpm", "unable to allocate memory for new bitmap page");
		}
		memset(bm, 0, PAGE_SIZE/8);
		b[top] = bm;
	}
	bm_set(b[top], bottom);
}

