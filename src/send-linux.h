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
#include <netinet/ip.h>
#include <string.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "../lib/includes.h"
#include "./send.h"

#include <netpacket/packet.h>

#ifdef ZMAP_SEND_BSD_H
#error "Don't include both send-bsd.h and send-linux.h"
#endif

// Dummy sockaddr for sendto
static struct sockaddr_ll sockaddr;

// Moving this to `send-linux.c` was necessary for some reason, maybe sockaddr is static to the file? so it was only being modified in the `.h` file? idk
int send_run_init(sock_t s);

int send_packet(sock_t sock, void *buf, int len, UNUSED uint32_t idx);
//{
//	return sendto(sock.sock, buf, len, 0, (struct sockaddr *)&sockaddr,
//		      sizeof(struct sockaddr_ll));
//}

int send_batch(sock_t sock, batch_t* batch);

#endif /* ZMAP_SEND_LINUX_H */
