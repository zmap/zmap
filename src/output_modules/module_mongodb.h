#include <bson-types.h>
#include "output_modules.h"

int mongodb_module_init(struct state_conf *conf, char **fields, int fieldlens);
int mongodb_module_process(fieldset_t *fs);
int mongodb_module_close(struct state_conf *c, struct state_send *s,
                      struct state_recv *r);
