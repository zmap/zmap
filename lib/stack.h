#ifndef ZMAP_STACK_H
#define ZMAP_STACK_H

#include <stddef.h>

struct stack;
typedef struct stack stack_t;

stack_t* alloc_stack(size_t size);
void free_stack(stack_t* stack);

void stack_push(stack_t* stack, void* elt);
void stack_pop(stack_t* stack);
void* stack_peek(stack_t* stack);

int stack_is_empty(stack_t* stack);

#endif /* ZMAP_STACK_H */