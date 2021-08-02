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

#include <pthread.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "xalloc.h"

static pthread_mutex_t **mutexes = NULL;

static pthread_mutex_t *get_mutex(int fd)
{
	assert(fd < 3 && "todo: implement generically");
	if (!mutexes) {
		mutexes = xmalloc(3 * sizeof(char *));
		assert(mutexes);
	}
	if (!mutexes[fd]) {
		mutexes[fd] = xmalloc(sizeof(pthread_mutex_t));
		assert(mutexes[fd]);
		pthread_mutex_init(mutexes[fd], NULL);
		assert(mutexes[fd]);
	}
	return mutexes[fd];
}

int lock_fd(int fd) { return pthread_mutex_lock(get_mutex(fd)); }

int unlock_fd(int fd) { return pthread_mutex_unlock(get_mutex(fd)); }

int lock_file(FILE *f)
{
	assert(f);
	return lock_fd(fileno(f));
}

int unlock_file(FILE *f)
{
	assert(f);
	return unlock_fd(fileno(f));
}
