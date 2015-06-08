/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include "socket.h"

#include "../lib/includes.h"
#include "state.h"

#include <pfring_zc.h>

sock_t get_socket(uint32_t id)
{
	sock_t sock;
	sock.pf.queue = zconf.pf.queues[id];
	sock.pf.buffers = zconf.pf.buffers + 256*id;
	return sock;
}

