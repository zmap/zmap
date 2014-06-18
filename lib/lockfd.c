#include <pthread.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static pthread_mutex_t **mutexes = NULL;

static pthread_mutex_t *get_mutex(int fd)
{
	assert(fd < 3 && "todo: implement generically");
	if (!mutexes) {
		mutexes = malloc(3*sizeof(char*));
		assert(mutexes);
		memset(mutexes, 0, 3*sizeof(char*));
	}
	if (!mutexes[fd]) {
		mutexes[fd] = malloc(sizeof(pthread_mutex_t));
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
