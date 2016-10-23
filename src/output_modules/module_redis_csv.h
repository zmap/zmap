/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include "output_modules.h"

int redisstrmodule_init(struct state_conf *conf, char **fields, int fieldlens);
int redisstrmodule_process(fieldset_t *fs);
int redisstrmodule_close(struct state_conf *c, struct state_send *s,
			 struct state_recv *r);
