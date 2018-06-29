/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include "socket.h"

#include <string.h>
#include <errno.h>

#include "../lib/includes.h"
#include "../lib/logger.h"

#include "state.h"

sock_t get_socket(UNUSED uint32_t id)
{
	int sock;
	if (zconf.send_ip_pkts) {
		sock = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL));
	} else {
		sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	}
	if (sock <= 0) {
		log_fatal("send",
			  "couldn't create socket. "
			  "Are you root? Error: %s\n",
			  strerror(errno));
	}
	sock_t s;
	s.sock = sock;
	return s;
}
