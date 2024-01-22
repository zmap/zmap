/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef ZMAP_SEND_BSD_H
#define ZMAP_SEND_BSD_H

#include <stdbool.h>

#include <netinet/in.h>
#include <net/bpf.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#include "send.h"
#include "../lib/includes.h"


#ifdef ZMAP_SEND_LINUX_H
#error "Don't include both send-bsd.h and send-linux.h"
#endif

int send_run_init(UNUSED sock_t sock, UNUSED uint32_t kernel_cpu, UNUSED bool is_liburing_enabled)
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
// Returns -1 and sets errno if no packets could be sent successfully
int send_batch(sock_t sock, batch_t* batch, int retries) {
	int packets_sent = 0;
	int rc = 0;
	for (int packet_num = 0; packet_num < batch->len; packet_num++) {
		for (int retry_ct = 0; retry_ct < retries; retry_ct++) {
			rc = send_packet(sock, ((void *)batch->packets) + (packet_num * MAX_PACKET_SIZE), batch->lens[packet_num], 0);
			if (rc >= 0) {
				packets_sent++;
				break;
			}
		}
		if (rc < 0) {
			// packet couldn't be sent in retries number of attempts
			struct in_addr addr;
			addr.s_addr = batch->ips[packet_num];
			char addr_str_buf
			    [INET_ADDRSTRLEN];
			const char *addr_str =
			    inet_ntop(
				AF_INET, &addr,
				addr_str_buf,
				INET_ADDRSTRLEN);
			if (addr_str != NULL) {
				log_debug( "send", "send_packet failed for %s. %s", addr_str,
				    strerror( errno));
			}
		}
	}
	if (packets_sent == 0) {
		// simulating the return behaviour of the Linux send_mmsg sys call on error. Returns -1 and leaves
		// errno as set by send_packet
		log_error("send", "send_batch failed and no packets were able to be sent: "
				  "%s", strerror(errno));
		return -1;
	}
	return packets_sent;
}

int send_run_cleanup(void)
{
	// Don't need to do anything on BSD-like variants
	return EXIT_SUCCESS;
}

#endif /* ZMAP_SEND_BSD_H */
