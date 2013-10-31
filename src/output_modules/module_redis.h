#include "output_modules.h"

int redismodule_init(struct state_conf *conf, char **fields, int fieldlens);
int redismodule_process(fieldset_t *fs);
int redismodule_close(struct state_conf* c, 
		struct state_send* s,
		struct state_recv* r);

