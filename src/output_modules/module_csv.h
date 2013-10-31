#include "../fieldset.h"
#include "output_modules.h"

int csv_init(struct state_conf *conf, char **fields, int fieldlens);
int csv_process(fieldset_t *fs);
int csv_close(struct state_conf* c, struct state_send *s, struct state_recv *r);
