/*
 * ZMap Copyright 2013 Regents of the University of Michigan 
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include <output_modules.h>

int redismodule_init(struct state_conf *conf);

int redismodule_newip(ipaddr_n_t saddr, ipaddr_n_t daddr,
        port_n_t sport, port_n_t dport, struct timeval* t,
        const char *response_type, int is_repeat,
        int in_cooldown, const u_char *packet);

int redismodule_close(struct state_conf* c,
		struct state_send* s, struct state_recv* r);
