/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef ZMAP_TREE_H
#define ZMAP_TREE_H

#include "fieldset.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

enum operation {
	GT, LT, EQ, NEQ, AND, OR, LT_EQ, GT_EQ
};

enum node_type {
	OP, FIELD, STRING, INT
};

struct field_id {
	int index;
	char *fieldname;
};

union node_value {
	struct field_id field;
	char *string_literal;
	uint64_t int_literal;
	enum operation op;
};

typedef struct node_st {
	struct node_st *left_child;
	struct node_st *right_child;
	enum node_type type;
	union node_value value;
} node_t;

node_t* make_op_node(enum operation op);

node_t* make_field_node(char *fieldname);

node_t* make_string_node(char *literal);

node_t* make_int_node(int literal);

int evaluate_expression(node_t *root, fieldset_t *fields);

void print_expression(node_t *root);

#endif /* ZMAP_TREE_H */
