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
	int i;
	if (node->type != FIELD) {
		return 1;
	}

	for (i = 0; i < fields->len; i++) {
		if (fields->fielddefs[i].name) {
			printf("Fields: %s, Looking for: %s\n", fields->fielddefs[i].name, node->value.field.fieldname);
			if (strcmp(fields->fielddefs[i].name, node->value.field.fieldname) == 0) {
				node->value.field.index = i;
				return 1;
			}
		}
	}
	// Didn't find it
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
	print_expression(zfilter);
	printf("%s\n", "");
	fflush(stdout);
	return 1;
}

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
