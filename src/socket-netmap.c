/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#if !(defined(__FreeBSD__) || defined(__linux__))
#error "NETMAP requires FreeBSD or Linux"
#endif

#include "socket.h"

#include "../lib/includes.h"
#include "../lib/logger.h"
#include "state.h"
#include "utility.h"

#include <net/netmap_user.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <inttypes.h>

// Open another file descriptor on the NIC, scoped to just one pair of rings,
// allowing the send threads to sync and poll just their tx ring w/o wreaking
// havoc on tx rings in use by other send threads, changing head/cur/tail
// underneath them unexpectedly.
sock_t get_socket(uint32_t id)
{
	sock_t sock;

	sock.nm.tx_ring_idx = id;
	sock.nm.tx_ring_fd = open(NETMAP_DEVICE_NAME, O_RDWR);
	if (sock.nm.tx_ring_fd == -1) {
		log_fatal("socket-netmap", "open(\"" NETMAP_DEVICE_NAME "\") failed: %d: %s", errno, strerror(errno));
	}

	struct nmreq_register nmrreg;
	memset(&nmrreg, 0, sizeof(nmrreg));
	nmrreg.nr_ringid = sock.nm.tx_ring_idx;
	nmrreg.nr_mode = NR_REG_ONE_NIC;
	nmrreg.nr_flags = NR_TX_RINGS_ONLY | NR_NO_TX_POLL;
	struct nmreq_header nmrhdr;
	memset(&nmrhdr, 0, sizeof(nmrhdr));
	nmrhdr.nr_version = NETMAP_API;
	nmrhdr.nr_reqtype = NETMAP_REQ_REGISTER;
	cross_platform_strlcpy(nmrhdr.nr_name, zconf.iface, sizeof(nmrhdr.nr_name));
	nmrhdr.nr_body = (uint64_t)&nmrreg;
	if (ioctl(sock.nm.tx_ring_fd, NIOCCTRL, &nmrhdr) == -1) {
		log_fatal("socket-netmap", "ioctl(NIOCCTRL) failed: %d: %s", errno, strerror(errno));
	}

	return sock;
}
