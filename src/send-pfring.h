/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef ZMAP_SEND_PFRING_H
#define ZMAP_SEND_PFRING_H

#include "../lib/includes.h"
#include <sys/ioctl.h>

#if defined(ZMAP_SEND_BSD_H) || defined(ZMAP_SEND_LINUX_H)
#error "Don't include send-bsd.h or send-linux.h with send-pfring.h"
#endif

int send_run_init(sock_t socket)
{
	(void)socket;

	// All init for pfring happens in get_socket
	return 0;
}

int send_batch(sock_t sock, batch_t *batch, UNUSED int attempts)
{
	for (int i = 0; i < batch->len; i++) {
		uint32_t len = batch->packets[i].len;
		sock.pf.buffers[i]->len = len;
		memcpy(pfring_zc_pkt_buff_data(sock.pf.buffers[i], sock.pf.queue), batch->packets[i].buf, len);
	}

	return pfring_zc_send_pkt_burst(sock.pf.queue, sock.pf.buffers, batch->len, 1 /* flush */);
}

#endif /* ZMAP_SEND_PFRING_H */
