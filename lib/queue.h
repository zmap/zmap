#ifndef ZMAP_QUEUE_H
#define ZMAP_QUEUE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

typedef struct zqueue_node {
	char *data;
	struct zqueue_node *prev;
	struct zqueue_node *next;
} znode_t;

typedef struct zqueue {
	struct zqueue_node *front;
	struct zqueue_node *back;
	size_t size;
	// Threading utilities
	pthread_mutex_t lock;
	pthread_cond_t empty;
} zqueue_t;

zqueue_t *queue_init();
int is_empty(zqueue_t *queue);
void push_back(char *data, zqueue_t *queue);
znode_t *pop_front(zqueue_t *queue);
znode_t *pop_front_unsafe(zqueue_t *queue);
znode_t *get_front(zqueue_t *queue);
znode_t *get_back(zqueue_t *queue);
size_t get_size(zqueue_t *queue);

#endif /* ZMAP_QUEUE_H */
