/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

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
