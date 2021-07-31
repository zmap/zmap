/*
 * Copyright 2021 Regents of the University of Michigan
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

#include "xalloc.h"
#include "logger.h"

#include <stdlib.h>
#include <string.h>

static void die() __attribute__((noreturn));

void *xcalloc(size_t count, size_t size)
{
	void *res = calloc(count, size);
	if (res == NULL) {
		die();
	}
	return res;
}

void xfree(void *ptr) { free(ptr); }

void *xmalloc(size_t size)
{
	void *res = malloc(size);
	if (res == NULL) {
		die();
	}
	memset(res, 0, size);
	return res;
}

void *xrealloc(void *ptr, size_t size)
{
	void *res = realloc(ptr, size);
	if (res == NULL) {
		die();
	}
	return res;
}

void die() { log_fatal("zmap", "Out of memory"); }
