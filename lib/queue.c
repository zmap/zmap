#include "queue.h"

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

int is_empty (zqueue_t *my_queue)
{
        if (my_queue->front == NULL && my_queue->front == NULL) return 1;
        return 0;
}

void push_back(char* data, zqueue_t *my_queue)
{
        znode_t *new_node = malloc(sizeof(znode_t));
        new_node->prev = NULL;
        new_node->next = NULL;
        new_node->data = strdup(data);

        pthread_mutex_lock(&queue_lock);
        if (is_empty(my_queue)) {
                my_queue->front = new_node;
                my_queue->back = new_node;
        } else {
                my_queue->back->next = (struct znode_t*)new_node;
                new_node->prev = (struct znode_t*)my_queue->back;
                my_queue->back = new_node;
        }
        my_queue->size++;
        pthread_cond_signal(&queue_empty);
        pthread_mutex_unlock(&queue_lock);
}

znode_t* pop_front(zqueue_t *my_queue)
{
        pthread_mutex_lock(&queue_lock);

        while (is_empty(my_queue)) {
                pthread_cond_wait(&queue_empty, &queue_lock);
        }
        znode_t *temp = my_queue->front;
        my_queue->front = (znode_t*)temp->next;
        if (my_queue->front != NULL) {
                my_queue->front->prev = NULL;
        }
        my_queue->size--;
        pthread_mutex_unlock(&queue_lock);
        return temp;
}

znode_t* get_front(zqueue_t *my_queue)
{
        pthread_mutex_lock(&queue_lock);

        while (is_empty(my_queue)) {
                pthread_cond_wait(&queue_empty, &queue_lock);
        }

        znode_t *temp = malloc(sizeof(znode_t));
        temp = my_queue->front;
        pthread_mutex_unlock(&queue_lock);
        return temp;
}

znode_t* get_back(zqueue_t *my_queue)
{
        pthread_mutex_lock(&queue_lock);

        while (is_empty(my_queue)) {
                pthread_cond_wait(&queue_empty, &queue_lock);
        }

        znode_t *temp = malloc(sizeof(znode_t));
        temp = my_queue->back;
        pthread_mutex_unlock(&queue_lock);
        return temp;
}

void delete_queue(zqueue_t *my_queue)
{
        while (!is_empty(my_queue)) {
                pop_front(my_queue);
        }
}

void check_queue(zqueue_t *my_queue)
{
        znode_t *temp = my_queue->front;
        while(temp){
                temp = (znode_t*)temp->next;
        }
}

int get_size(zqueue_t *my_queue)
{
        int buffer_size;
        pthread_mutex_lock(&queue_lock);
        buffer_size = my_queue->size;
        pthread_mutex_unlock(&queue_lock);
        return buffer_size;
}
