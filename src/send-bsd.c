/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include "send.h"

#include <netinet/in.h>
#include <net/bpf.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "state.h"
#include "probe_modules/packet.h"

#include "../lib/includes.h"
#include "../lib/logger.h"

int send_run_init(UNUSED sock_t sock)
{
	// Don't need to do anything on BSD-like variants
	return EXIT_SUCCESS;
}

static int
send_packet(sock_t sock, uint8_t *buf, int len, UNUSED uint32_t retry_ct)
{
	if (zconf.send_ip_pkts) {
		buf += sizeof(struct ether_header);
		struct ip *iph = (struct ip *)buf;

#if defined(__APPLE__) || (defined(__FreeBSD__) && __FreeBSD_version < 1100030)
		// Early BSD's raw IP sockets required IP headers to have len
		// and off fields in host byte order, as they were being byte
		// swapped on the way out.  Getting byte order wrong would
		// result in EINVAL from sendto(2) below.
		// Most modern BSD systems have fixed this and removed the byte
		// swapping on raw IP sockets, while some, notably macOS, still
		// require header fields in host byte order.
		// See ip(4) for details on byte order requirements of raw IP
		// sockets.
		// Swap byte order on the first send attempt for a given packet
		// (retry_ct == 0), and rely on the caller to pass us the same
		// buffer again for retries (retry_ct > 0), with the buffer
		// still containing the header fields in corrected byte order.
		if (retry_ct == 0) {
			iph->ip_len = ntohs(iph->ip_len);
			iph->ip_off = ntohs(iph->ip_off);
			iph->ip_sum = 0;
		}
#endif

		struct sockaddr_in sai;
		bzero(&sai, sizeof(sai));
		sai.sin_family = AF_INET;
		sai.sin_addr.s_addr = iph->ip_dst.s_addr;
		return sendto(sock.sock, buf, len, 0, (struct sockaddr *)&sai, sizeof(sai));
	} else {
		return write(sock.sock, buf, len);
	}
}

// macOS doesn't have sendmmsg as of Sonoma. Since we want a uniform interface, we'll emulate the send_batch used in Linux.
// FreeBSD does have sendmmsg, but it is a libc wrapper around the sendmsg syscall, without the perf benefits of sendmmsg.
// The behavior in sendmmsg is to send as many packets as possible until one fails, and then return the number of sent packets.
// Following the same pattern for consistency
// Returns - number of packets sent
// Returns -1 and sets errno if no packets could be sent successfully
int send_batch(sock_t sock, batch_t *batch, int retries)
{
	if (batch->len == 0) {
		// nothing to send
		return EXIT_SUCCESS;
	}
	int packets_sent = 0;
	int rc = 0;
	for (int packet_num = 0; packet_num < batch->len; packet_num++) {
		for (int retry_ct = 0; retry_ct < retries; retry_ct++) {
			rc = send_packet(sock, batch->packets[packet_num].buf, batch->packets[packet_num].len, retry_ct);
			if (rc >= 0) {
				packets_sent++;
				break;
			}
		}
		if (rc < 0) {
			// packet couldn't be sent in retries number of attempts
			struct ip *iph = (struct ip *)(batch->packets[packet_num].buf + sizeof(struct ether_header));
			char addr_str_buf[INET_ADDRSTRLEN];
			const char *addr_str =
			    inet_ntop(
				AF_INET, &iph->ip_dst,
				addr_str_buf,
				INET_ADDRSTRLEN);
			if (addr_str != NULL) {
				log_debug("send-bsd", "send_packet failed for %s. %s", addr_str,
					  strerror(errno));
			}
		}
	}
	if (packets_sent == 0) {
		// simulating the return behaviour of the Linux send_mmsg sys call on error. Returns -1 and leaves
		// errno as set by send_packet
		return -1;
	}
	return packets_sent;
}
