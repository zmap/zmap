#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

typedef struct queue_node {
    char* data;
    struct node *prev;
    struct node *next;
} node;

typedef struct ztee_queue {
    node *front;
    node *back;
    int size;
} queue;

queue* queue_init ();
int is_empty (queue *my_queue);
void push_back (char* data, queue *my_queue);
node* pop_front (queue *my_queue);
node* get_front (queue *my_queue);
node* get_back (queue *my_queue);
void delete_queue (queue *my_queue);
void check_queue (queue *my_queue);
int get_size (queue *my_queue);
