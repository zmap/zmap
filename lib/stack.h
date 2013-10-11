#ifndef ZMAP_STACK_H
#define ZMAP_STACK_H

#include <stddef.h>

struct stack;
typedef struct stack stack_t;

stack_t* alloc_stack(size_t size);
void free_stack(stack_t* stack);

void push(stack_t* stack, void* elt);
void* pop(stack_t* stack);

#endif /* ZMAP_STACK_H */