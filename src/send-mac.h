/*
* ZMap Copyright 2024 Regents of the University of Michigan
*
* Licensed under the Apache License, Version 2.0 (the "License"); you may not
* use this file except in compliance with the License. You may obtain a copy
* of the License at http://www.apache.org/licenses/LICENSE-2.0
*/

#ifndef ZMAP_SEND_MAC_H
#define ZMAP_SEND_MAC_H

#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#include "send.h"
#include "../lib/includes.h"

#include <netinet/in.h>
#include <net/bpf.h>

#ifdef ZMAP_SEND_LINUX_H
#error "Don't include both send-mac.h and send-linux.h"
#endif
#ifdef ZMAP_SEND_BSD_H
#error "Don't include both send-mac.h and send-bsd.h"
#endif

int send_run_init(UNUSED sock_t sock)
{
	// Don't need to do anything on MacOS
	return EXIT_SUCCESS;
}

int send_packet(sock_t sock, void *buf, int len, UNUSED uint32_t retry_ct)
{
	if (zconf.send_ip_pkts) {
		struct ip *iph = (struct ip *)buf;
#ifdef __APPLE__
		// The len and off fields need to be in host byte order on macOS.
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

// MacOS doesn't have the sendmmsg as of Sonoma 14.2. Since we want a uniform interface, we'll emulate the send_batch used in Linux.
// The behavior in sendmmsg is to send as many packets as possible until one fails, and then return the number of sent packets.
// Following the same pattern for consistency
// Returns - number of packets sent
// Returns -1 and sets errno if no packets could be sent successfully
int send_batch(sock_t sock, batch_t* batch, int retries) {
	if (batch->len == 0) {
		// nothing to send
		return EXIT_SUCCESS;
	}
	int packets_sent = 0;
	int rc = 0;
	for (int packet_num = 0; packet_num < batch->len; packet_num++) {
		for (int retry_ct = 0; retry_ct < retries; retry_ct++) {
			rc = send_packet(sock, ((uint8_t *)batch->packets) + (packet_num * MAX_PACKET_SIZE), batch->lens[packet_num], retry_ct);
			if (rc >= 0) {
				packets_sent++;
				break;
			}
		}
		if (rc < 0) {
			// packet couldn't be sent in retries number of attempts
			struct in_addr addr;
			addr.s_addr = batch->ips[packet_num];
			char addr_str_buf[INET_ADDRSTRLEN];
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
		return -1;
	}
	return packets_sent;
}

#endif //ZMAP_SEND_MAC_H
