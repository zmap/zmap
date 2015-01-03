#include "queue.h"
#include <pthread.h>
//queue_lock used for push and pop

pthread_mutex_t queue_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t queue_empty = PTHREAD_COND_INITIALIZER;

queue* queue_init()
{
        //call with queue_init(&queue);
        queue *p = malloc(sizeof(queue));
        p->front = NULL;
        p->back = NULL;
        p->size = 0;
        return p;
}

int is_empty (queue *my_queue)
{
        if (my_queue->front == NULL && my_queue->front == NULL) return 1;
        return 0;
}

void push_back(char* data, queue *my_queue)
{
        node *new_node = malloc(sizeof(node));
        new_node->prev = NULL;
        new_node->next = NULL;
        new_node->data = strdup(data);

        pthread_mutex_lock(&queue_lock);
        if (is_empty(my_queue)) {
                my_queue->front = new_node;
                my_queue->back = new_node;
        } else {
                my_queue->back->next = (struct node*)new_node;
                new_node->prev = (struct node*)my_queue->back;
                my_queue->back = new_node;
        }
        my_queue->size++;
        pthread_cond_signal(&queue_empty);
        pthread_mutex_unlock(&queue_lock);
}

node* pop_front(queue *my_queue)
{
        pthread_mutex_lock(&queue_lock);

        while (is_empty(my_queue)) {
                pthread_cond_wait(&queue_empty, &queue_lock);
        }
        node *temp = my_queue->front;
        my_queue->front = (node*)temp->next;
        if (my_queue->front != NULL) {
                my_queue->front->prev = NULL;
        }
        my_queue->size--;
        pthread_mutex_unlock(&queue_lock);
        return temp;
}

node* get_front(queue *my_queue)
{
        pthread_mutex_lock(&queue_lock);

        while (is_empty(my_queue)) {
                pthread_cond_wait(&queue_empty, &queue_lock);
        }

        node *temp = malloc(sizeof(node));
        temp = my_queue->front;
        pthread_mutex_unlock(&queue_lock);
        return temp;
}

node* get_back(queue *my_queue)
{
        pthread_mutex_lock(&queue_lock);

        while (is_empty(my_queue)) {
                pthread_cond_wait(&queue_empty, &queue_lock);
        }

        node *temp = malloc(sizeof(node));
        temp = my_queue->back;
        pthread_mutex_unlock(&queue_lock);
        return temp;
}

void delete_queue(queue *my_queue)
{
        while (!is_empty(my_queue)) {
                pop_front(my_queue);
        }
}

void check_queue(queue *my_queue)
{
        node *temp = my_queue->front;
        while(temp){
                temp = (node*)temp->next;
        }
}

int get_size(queue *my_queue)
{
        int buffer_size;
        pthread_mutex_lock(&queue_lock);
        buffer_size = my_queue->size;
        pthread_mutex_unlock(&queue_lock);
        return buffer_size;
}
