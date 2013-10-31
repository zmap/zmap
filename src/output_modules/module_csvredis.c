/*
 * ZMap Copyright 2013 Regents of the University of Michigan 
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "../fieldset.h"

#include "module_redis.h"
#include "module_csv.h"
#include "output_modules.h"
#include "../../lib/logger.h"

static int success_index = -1, repeat_index = -1;

int csvredis_init(struct state_conf *conf, char **fields, int fieldlens)
{
	csv_init(conf, fields, fieldlens);
	redismodule_init(conf, fields, fieldlens);

	for (int i=0; i < fieldlens; i++) {
		if (!strcmp("success", fields[i])) {
			success_index = i;
		} else if (!strcmp("repeat", fields[i])) {
			repeat_index = i;
		}
	}

	if (success_index < 0 || repeat_index < 0) {
		log_fatal("csvredis", "success or repeat not included in fieldset");
	}

	return EXIT_SUCCESS;
}

int csvredis_close(struct state_conf* c, struct state_send* s, struct state_recv* r)
{
	csv_close(c,s,r);
	redismodule_close(c,s,r);
	return EXIT_SUCCESS;
}

int csvredis_process(fieldset_t *fs)
{
	csv_process(fs);
	int is_success = fs_get_uint64_by_index(fs, success_index);
	int is_repeat = fs_get_uint64_by_index(fs, repeat_index);
	if (is_success && !is_repeat) {
		redismodule_process(fs);
	}
	return EXIT_SUCCESS;
}

output_module_t module_csv_redis = {
	.name = "csvredis",
	.init = &csvredis_init,
	.start = NULL,
	.update = NULL,
	.update_interval = 0,
	.close = &csvredis_close,
	.process_ip = &csvredis_process,
	.helptext = NULL
};

