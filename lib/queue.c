#include "queue.h"

#include "xalloc.h"

#include <pthread.h>

//queue_lock used for push and pop
pthread_mutex_t queue_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t queue_empty = PTHREAD_COND_INITIALIZER;

zqueue_t* queue_init()
{
        //call with queue_init(&zqueue_t);
        zqueue_t *p = malloc(sizeof(zqueue_t));
        p->front = NULL;
        p->back = NULL;
        p->size = 0;
        return p;
}

int is_empty(zqueue_t *queue)
{
        if (queue->front == NULL) {
		return 1;
	}
        return 0;
}

void push_back(char* data, zqueue_t *queue)
{
        znode_t *new_node = xmalloc(sizeof(znode_t));
        new_node->prev = NULL;
        new_node->next = NULL;
        new_node->data = strdup(data);

        pthread_mutex_lock(&queue_lock);
        if (is_empty(queue)) {
                queue->front = new_node;
                queue->back = new_node;
        } else {
                queue->back->next = new_node;
                new_node->prev = queue->back;
                queue->back = new_node;
        }
        queue->size++;
        pthread_cond_signal(&queue_empty);
        pthread_mutex_unlock(&queue_lock);
}

znode_t* pop_front(zqueue_t *queue)
{
        pthread_mutex_lock(&queue_lock);

        while (is_empty(queue)) {
                pthread_cond_wait(&queue_empty, &queue_lock);
        }
        znode_t *temp = queue->front;
        queue->front = temp->next;
        if (queue->front != NULL) {
                queue->front->prev = NULL;
        }
        queue->size--;
        pthread_mutex_unlock(&queue_lock);
        return temp;
}

znode_t* get_front(zqueue_t *queue)
{
        pthread_mutex_lock(&queue_lock);

        while (is_empty(queue)) {
                pthread_cond_wait(&queue_empty, &queue_lock);
        }

        znode_t *temp = malloc(sizeof(znode_t));
        temp = queue->front;
        pthread_mutex_unlock(&queue_lock);
        return temp;
}

znode_t* get_back(zqueue_t *queue)
{
        pthread_mutex_lock(&queue_lock);

        while (is_empty(queue)) {
                pthread_cond_wait(&queue_empty, &queue_lock);
        }

        znode_t *temp = malloc(sizeof(znode_t));
        temp = queue->back;
        pthread_mutex_unlock(&queue_lock);
        return temp;
}

void delete_queue(zqueue_t *queue)
{
        while (!is_empty(queue)) {
                pop_front(queue);
        }
}

void check_queue(zqueue_t *queue)
{
        znode_t *temp = queue->front;
        while(temp){
                temp = temp->next;
        }
}

int get_size(zqueue_t *queue)
{
        int buffer_size;
        pthread_mutex_lock(&queue_lock);
        buffer_size = queue->size;
        pthread_mutex_unlock(&queue_lock);
        return buffer_size;
}
