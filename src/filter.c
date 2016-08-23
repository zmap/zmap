/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include "filter.h"
#include "state.h"
#include "lexer.h"
#include "parser.h"
#include "expression.h"
#include "../lib/logger.h"

#include <string.h>

extern int yyparse();

node_t *zfilter;

static int validate_node(node_t *node, fielddefset_t *fields)
{
	int index, found = 0;
	if (node->type == OP) {
		// These end up getting validated later
		if (node->value.op == AND || node->value.op == OR) {
			return 1;
		}
		// Comparison node (=, >, <, etc.)
		// Validate that the field (left child) exists in the fieldset
		for (index = 0; index < fields->len; index++) {
			if (fields->fielddefs[index].name) {
				if (strcmp(fields->fielddefs[index].name,
						node->left_child->value.field.fieldname) == 0) {
					node->left_child->value.field.index = index;
					found = 1;
					break;
				}
			}
		}
		if (!found) {
			fprintf(stderr, "Field '%s' does not exist\n",
					node->left_child->value.field.fieldname);
			return 0;
		}
		// Fieldname is fine, match the type.
		switch (node->right_child->type) {
		case STRING:
			if (strcmp(fields->fielddefs[index].type, "string") == 0) {
				return 1;
			} else {
				fprintf(stderr, "Field '%s' is not of type 'string'\n",
						fields->fielddefs[index].name);
				return 0;
			}
		case INT:
			if (strcmp(fields->fielddefs[index].type, "int") == 0 ||
					strcmp(fields->fielddefs[index].type, "bool") == 0) {
				return 1;
			} else {
				fprintf(stderr, "Field '%s' is not of type 'int'\n",
						fields->fielddefs[index].name);
				return 0;
			}
		default:
			return 0;
		}
	} else {
		// All non-op nodes are valid
		return 1;
	}
	// Didn't validate
	return 0;

}

int parse_filter_string(char *filter)
{
	YY_BUFFER_STATE buffer_state = yy_scan_string(filter);
	int status = yyparse();
	yy_delete_buffer(buffer_state);
	if (status) {
		// Error
		log_error("zmap", "Unable to parse filter string: '%s'", filter);
		return 0;
	}
	zconf.filter.expression = zfilter;
	return 1;
}

/*
 * 0     Valid
 * -1    Invalid Field Name
 * -2    Type Mismatch
 */
int validate_filter(node_t *root, fielddefset_t *fields)
{
	int valid;
	if (!root) {
		return 1;
	}
	valid = validate_node(root, fields);
	if (!valid) {
		return 0;
	}
	return (validate_filter(root->left_child, fields) && validate_filter(root->right_child, fields));
}
