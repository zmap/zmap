#include "queue.h"

#include "xalloc.h"

#include <pthread.h>

zqueue_t *queue_init()
{
	zqueue_t *p = xmalloc(sizeof(zqueue_t));
	p->front = NULL;
	p->back = NULL;
	p->size = 0;

	pthread_mutex_init(&p->lock, NULL);
	pthread_cond_init(&p->empty, NULL);
	return p;
}

int is_empty(zqueue_t *queue) { return queue->size == 0; }

void push_back(char *data, zqueue_t *queue)
{
	znode_t *new_node = xmalloc(sizeof(znode_t));
	new_node->prev = NULL;
	new_node->next = NULL;
	new_node->data = strdup(data);

	pthread_mutex_lock(&queue->lock);
	if (is_empty(queue)) {
		queue->front = new_node;
		queue->back = new_node;
	} else {
		queue->back->next = new_node;
		new_node->prev = queue->back;
		queue->back = new_node;
	}
	queue->size++;
	pthread_cond_signal(&queue->empty);
	pthread_mutex_unlock(&queue->lock);
}

znode_t *pop_front(zqueue_t *queue)
{
	pthread_mutex_lock(&queue->lock);

	while (is_empty(queue)) {
		pthread_cond_wait(&queue->empty, &queue->lock);
	}
	znode_t *temp = pop_front_unsafe(queue);
	pthread_mutex_unlock(&queue->lock);
	return temp;
}

znode_t *pop_front_unsafe(zqueue_t *queue)
{
	znode_t *temp = queue->front;
	queue->front = temp->next;
	if (queue->front != NULL) {
		queue->front->prev = NULL;
	}
	queue->size--;
	return temp;
}

znode_t *get_front(zqueue_t *queue)
{
	pthread_mutex_lock(&queue->lock);

	while (is_empty(queue)) {
		pthread_cond_wait(&queue->empty, &queue->lock);
	}

	znode_t *temp = xmalloc(sizeof(znode_t));
	temp = queue->front;
	pthread_mutex_unlock(&queue->lock);
	return temp;
}

znode_t *get_back(zqueue_t *queue)
{
	pthread_mutex_lock(&queue->lock);

	while (is_empty(queue)) {
		pthread_cond_wait(&queue->empty, &queue->lock);
	}

	znode_t *temp = xmalloc(sizeof(znode_t));
	temp = queue->back;
	pthread_mutex_unlock(&queue->lock);
	return temp;
}

size_t get_size(zqueue_t *queue) { return queue->size; }
