/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef ZMAP_SEND_BSD_H
#define ZMAP_SEND_BSD_H

#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include "./send.h"

#include "../lib/includes.h"

#include <netinet/in.h>
#include <net/bpf.h>

#ifdef ZMAP_SEND_LINUX_H
#error "Don't include both send-bsd.h and send-linux.h"
#endif

int send_run_init(UNUSED sock_t sock)
{
	// Don't need to do anything on BSD-like variants
	return EXIT_SUCCESS;
}

int send_packet(sock_t sock, void *buf, int len, UNUSED uint32_t idx)
{
	return write(sock.sock, buf, len);
}

int send_batch(sock_t sock, batch_t* batch) {
	int errors = 0;
	for (int i=0;i<batch->len;i++) {
		int rc = send_packet(sock, ((void *)batch->packets) + (i * MAX_PACKET_SIZE), batch->lens[i], 0);
		if (rc < 0) {
			perror("error in send_batch");
			errors += 1;
		}
	}
	return errors;
}

#endif /* ZMAP_SEND_BSD_H */
