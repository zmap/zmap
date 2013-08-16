#ifndef _CONSTRAINT_H
#define _CONSTRAINT_H

typedef struct _constraint constraint_t;
typedef int value_t;

constraint_t* constraint_init(value_t value);
void constraint_free(constraint_t *con);
void constraint_set(constraint_t *con, uint32_t prefix, int len, value_t value);
void constraint_optimize(constraint_t *con);
int constraint_lookup_ip(constraint_t *con, uint32_t address);
uint64_t constraint_count_ips(constraint_t *con, value_t value);

#endif //_CONSTRAINT_H
