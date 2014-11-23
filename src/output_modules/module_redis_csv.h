#include "output_modules.h"

int redisstrmodule_init(struct state_conf *conf, char **fields, int fieldlens);
int redisstrmodule_process(fieldset_t *fs);
int redisstrmodule_close(struct state_conf* c,
		struct state_send* s,
		struct state_recv* r);

