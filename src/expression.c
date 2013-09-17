#include "tree.h"

node_t* alloc_node() 
{
	node_t *node = (node_t*) malloc(sizeof(node_t));
	memset(node, 0, sizeof(node_t));
	return node;
}

node_t* make_op_node(enum operation op) 
{
	node_t* node = alloc_node();
	node->type = OP;
	node->value.op = op;
	return node;
}

node_t* make_field_node(char *fieldname) 
{
	node_t *node = alloc_node();
	node->type = FIELD;
	node->value.fieldname = fieldname;
	return node;
}

node_t* make_string_node(char *literal)
{
	node_t *node = alloc_node();
	node->type = STRING;
	node->value.string_literal = literal;
	return node;
}

node_t* make_int_node(int literal)
{
	node_t *node = alloc_node();
	node->type = INT;
	node->value.int_literal = literal;
	return node;
}

int evaluate_expression(node_t *root) {
	int result = 1;
	return result;
}

void print_expression(node_t *root) {
	if (!root) return;
	printf("%s", "( ");
	print_expression(root->left_child);
	switch (root->type) {
		case OP:
			printf(" %i ", root->value.op);
			break;
		case FIELD:
			printf(" (%s", root->value.fieldname);
			break;
		case STRING:
			printf("%s) ", root->value.string_literal);
			break;
		case INT:
			printf(" %d) ", root->value.int_literal);
			break;
		default:
			break;
	}
	print_expression(root->right_child);
	printf("%s", " )");
}
