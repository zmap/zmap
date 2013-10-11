#include "stack.h"
#include "../lib/xalloc.h"

#include <stdlib.h>

struct stack {
	size_t max_size;
	size_t cur_size;
	void** arr;
};

stack_t* alloc_stack(size_t size)
{
	stack_t* stack = xmalloc(sizeof(stack_t));
	stack->arr = xcalloc(size, sizeof(void*));
	stack->max_size = size;
	stack->cur_size = 0;
	return stack;
}

void free_stack(stack_t* stack)
{
	xfree(stack->arr);
	xfree(stack);
}

void stack_push(stack_t* stack, void* elt)
{
	if (stack->cur_size == stack->max_size) {
		stack->max_size *= 2;
		xrealloc(stack->arr, stack->max_size);
	}
	stack->arr[stack->cur_size++] = elt;
}

void stack_pop(stack_t* stack)
{
	--stack->cur_size;
}

void* stack_peek(stack_t* stack)
{
	return stack->arr[stack->cur_size - 1];
}

int stack_is_empty(stack_t* stack)
{
	return (stack->cur_size == 0);
}
