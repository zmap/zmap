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

// Since BSD doesn't have the sendmmsg syscall leveraged in send-linux.c, this just wraps the single send_packet call.
// However, the behavior in sendmmsg is to send as many packets as possible until one fails, and then return the number of sent packets.
// Following the same pattern for consistency
// Returns - number of packets sent
// Returns last error code if no packets could be sent successfully
int send_batch(sock_t sock, batch_t* batch, int retries) {
	int packets_sent = 0;
	int retry_ct = 0;
	int rc = 0;
	for (int i=0;i<batch->len;i++) {
		for (retry_ct = 0; retry_ct < retries; retry_ct++) {
			rc = send_packet(sock, ((void *)batch->packets) + (i * MAX_PACKET_SIZE), batch->lens[i], 0);
			if (rc >= 0) {
				packets_sent++;
				break;
			}
		}
		if (rc < 0) {
			// packet couldn't be sent in retries number of attempts
			struct in_addr addr;
			addr.s_addr = batch->ips[i];
			char addr_str_buf
			    [INET_ADDRSTRLEN];
			const char *addr_str =
			    inet_ntop(
				AF_INET, &addr,
				addr_str_buf,
				INET_ADDRSTRLEN);
			if (addr_str != NULL) {
				log_debug(
				    "send",
				    "send_packet failed for %s. %s",
				    addr_str,
				    strerror(
					errno));
			}
		}
	}
	if (packets_sent == 0) {
		return rc;
	}
	return packets_sent;
}

#endif /* ZMAP_SEND_BSD_H */
