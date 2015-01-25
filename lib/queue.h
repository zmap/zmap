#ifndef ZMAP_QUEUE_H
#define ZMAP_QUEUE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

typedef struct zqueue_node {
    char* data;
    struct zqueue_node *prev;
    struct zqueue_node *next;
} znode_t;

typedef struct zqueue {
    struct zqueue_node *front;
    struct zqueue_node *back;
    int size;
} zqueue_t;

zqueue_t* queue_init ();
int is_empty (zqueue_t *queue);
void push_back (char* data, zqueue_t *queue);
znode_t* pop_front (zqueue_t *queue);
znode_t* get_front (zqueue_t *queue);
znode_t* get_back (zqueue_t *queue);
void delete_queue (zqueue_t *queue);
int get_size (zqueue_t *queue);

#endif /* ZMAP_QUEUE_H */
