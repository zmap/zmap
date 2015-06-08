/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include "expression.h"
#include "fieldset.h"

#include "../lib/xalloc.h"

/* Static helper functions */

static node_t* alloc_node();
static int eval_gt_node(node_t *node, fieldset_t *fields);
static int eval_lt_node(node_t *node, fieldset_t *fields);
static int eval_eq_node(node_t *node, fieldset_t *fields);
static int eval_lt_eq_node(node_t *node, fieldset_t *fields);
static int eval_gt_eq_node(node_t *node, fieldset_t *fields);


static node_t* alloc_node()
{
	node_t *node = xmalloc(sizeof(node_t));
	return node;
}

static int eval_gt_node(node_t *node, fieldset_t *fields)
{
	int index = node->left_child->value.field.index;
	uint64_t expected = node->right_child->value.int_literal;
	uint64_t actual = fs_get_uint64_by_index(fields, index);
	return (actual > expected);
}

static int eval_lt_node(node_t *node, fieldset_t *fields)
{
	int index = node->left_child->value.field.index;
	uint64_t expected = node->right_child->value.int_literal;
	uint64_t actual = fs_get_uint64_by_index(fields, index);
	return (actual < expected);
}

static int eval_eq_node(node_t *node, fieldset_t *fields)
{
	node_t *literal = node->right_child;
	int index = node->left_child->value.field.index;
	char *expected, *actual;
	switch (literal->type) {
		case STRING:
			expected = literal->value.string_literal;
			actual = fs_get_string_by_index(fields, index);
			return (strcmp(expected, actual) == 0);
			break;
		case INT:
			return (fs_get_uint64_by_index(fields, index) == literal->value.int_literal);
			break;
		default:
			printf("wat\n");
			break;
	}
	return 0;
}

static int eval_lt_eq_node(node_t *node, fieldset_t *fields)
{
	return !(eval_gt_node(node, fields));
}

static int eval_gt_eq_node(node_t *node, fieldset_t *fields)
{
	return !(eval_lt_node(node, fields));
}


/* Exposed functions */

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
	node->value.field.fieldname = fieldname;
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

int evaluate_expression(node_t *root, fieldset_t *fields)
{
	if (!root) return 1;
	switch (root->type) { /* XXX Not sure if runs */
	case FIELD:
	case STRING:
	case INT:
		return 1;
	case OP:
		break;
	}
	switch (root->value.op) {
	case GT:
		return eval_gt_node(root, fields);
	case LT:
		return eval_lt_node(root, fields);
	case EQ:
		return eval_eq_node(root, fields);
	case NEQ:
		return (!eval_eq_node(root, fields));
	case LT_EQ:
		return eval_lt_eq_node(root, fields);
	case GT_EQ:
		return eval_gt_eq_node(root, fields);
	case AND:
		return (evaluate_expression(root->left_child, fields)
			&& evaluate_expression(root->right_child, fields));
	case OR:
		return (evaluate_expression(root->left_child, fields)
			|| evaluate_expression(root->right_child, fields));
	}
	return 0;
}

void print_expression(node_t *root)
{
	if (!root) return;
	printf("%s", "( ");
	print_expression(root->left_child);
	switch (root->type) {
		case OP:
			printf(" %i ", root->value.op);
			break;
		case FIELD:
			printf(" (%s", root->value.field.fieldname);
			break;
		case STRING:
			printf("%s) ", root->value.string_literal);
			break;
		case INT:
			printf(" %llu) ", (long long unsigned) root->value.int_literal);
			break;
		default:
			break;
	}
	print_expression(root->right_child);
	printf("%s", " )");
}
