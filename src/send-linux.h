/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */
#ifndef ZMAP_SEND_LINUX_H
#define ZMAP_SEND_LINUX_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <netinet/ip.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "../lib/includes.h"
#include "./send.h"


#ifdef ZMAP_SEND_BSD_H
#error "Don't include both send-bsd.h and send-linux.h"
#endif

// Dummy sockaddr for sendto
static struct sockaddr_ll sockaddr;

int send_run_init(sock_t s);
int send_batch(sock_t sock, batch_t* batch, int retries);

#endif /* ZMAP_SEND_LINUX_H */
