/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include "socket.h"

#include <errno.h>

#include "../lib/includes.h"
#include "../lib/logger.h"

#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <net/bpf.h>

#include "state.h"

sock_t get_socket(UNUSED uint32_t id)
{
	sock_t sock;
	sock.sock = -1;

#ifndef __APPLE__
	if (zconf.send_ip_pkts && !zconf.dryrun) {
		log_fatal("socket", "iplayer not supported on BSD other than macOS");
	}
#endif

	if (zconf.send_ip_pkts) {
		int fd = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
		if (fd == -1) {
			log_debug("socket-bsd", "socket(PF_INET, SOCK_RAW, IPPROTO_IP) failed: %d %s", errno, strerror(errno));
			return sock;
		}

		int yes = 1;
		if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &yes, sizeof(yes)) == -1) {
			log_debug("socket-bsd", "setsockopt(IP_HDRINCL) failed: %d %s", errno, strerror(errno));
			return sock;
		}

		sock.sock = fd;
	} else {
		int bpf;
		char file[32];

		// Try to find a valid bpf
		for (int i = 0; i < 128; i++) {
			snprintf(file, sizeof(file), "/dev/bpf%d", i);
			bpf = open(file, O_WRONLY);
			if (bpf != -1 || errno != EBUSY)
				break;
		}

		// Make sure it worked
		if (bpf < 0) {
			return sock;
		}

		// Set up an ifreq to bind to
		struct ifreq ifr;
		memset(&ifr, 0, sizeof(ifr));
		strlcpy(ifr.ifr_name, zconf.iface, sizeof(ifr.ifr_name));

		// Bind the bpf to the interface
		if (ioctl(bpf, BIOCSETIF, (char *)&ifr) < 0) {
			close(bpf);
			return sock;
		}

		// Enable writing the address in
		int write_addr_enable = 1;
		if (ioctl(bpf, BIOCSHDRCMPLT, &write_addr_enable) < 0) {
			close(bpf);
			return sock;
		}

		sock.sock = bpf;
	}
	return sock;
}
