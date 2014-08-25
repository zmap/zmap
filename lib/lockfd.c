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
		mutexes = xmalloc(3*sizeof(char*));
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

int lock_fd(int fd)
{
	return pthread_mutex_lock(get_mutex(fd));
}

int unlock_fd(int fd)
{
	return pthread_mutex_unlock(get_mutex(fd));
}

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
