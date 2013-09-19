#ifndef ZMAP_FILTER_H
#define ZMAP_FILTER_H

#include "expression.h"

struct output_filter {
	node_t *expression;
};

void parse_filter_string(char *filter);

#endif /* ZMAP_FILTER_H */