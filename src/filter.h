#ifndef ZMAP_FILTER_H
#define ZMAP_FILTER_H

#include "expression.h"
#include "fieldset.h"

struct output_filter {
	node_t *expression;
};

int parse_filter_string(char *filter);

int validate_filter(node_t *root, fielddefset_t *fields);

#endif /* ZMAP_FILTER_H */
