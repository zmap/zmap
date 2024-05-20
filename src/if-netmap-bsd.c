/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef __FreeBSD__
#error "NETMAP requires FreeBSD or Linux"
#endif

#include "if-netmap.h"

#include "../lib/includes.h"
#include "../lib/logger.h"

#include <sys/ioctl.h>
#include <net/if_types.h>
#include <unistd.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <errno.h>

static void
fetch_if_data(struct if_data *ifd, char const *ifname, int fd)
{
	struct ifreq ifr;
	bzero(&ifr, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	ifr.ifr_data = (caddr_t)ifd;
	if (ioctl(fd, SIOCGIFDATA, &ifr) == -1) {
		log_fatal("if-netmap-bsd", "unable to retrieve if_data: %d: %s",
			  errno, strerror(errno));
	}
}

void if_wait_for_phy_reset(char const *ifname, int fd)
{
	struct if_data ifd;
	bzero(&ifd, sizeof(ifd));
	for (size_t i = 0; i < 40 /* 10s */; i++) {
		fetch_if_data(&ifd, ifname, fd);
		if (ifd.ifi_link_state == LINK_STATE_UP) {
			return;
		}
		usleep(250000);
	}
	log_fatal("if-netmap-bsd", "timeout waiting for PHY reset to complete");
}

size_t
if_get_data_link_size(char const *ifname, int fd)
{
	struct if_data ifd;
	bzero(&ifd, sizeof(ifd));
	fetch_if_data(&ifd, ifname, fd);

	switch (ifd.ifi_type) {
	case IFT_ETHER:
		log_debug("if-netmap-bsd", "IFT_ETHER");
		return sizeof(struct ether_header);
	default:
		log_fatal("if-netmap-bsd", "Unsupported if type %u", ifd.ifi_type);
	}
}

// Notes on if counters:
// On interfaces without hardware counters (HWSTATS), ipackets misses
// packets that we do not forward to the host ring pair.
// oqdrops counts packets the host OS could not send due to netmap mode.

struct if_stats_ctx {
	char *ifname; // owned
	int fd;	      // borrowed
	bool hwstats;
	uint64_t ifi_ipackets;
	uint64_t ifi_iqdrops;
	uint64_t ifi_ierrors;
	uint64_t ifi_oerrors;
};

if_stats_ctx_t *
if_stats_init(char const *ifname, int fd)
{
	if_stats_ctx_t *ctx = malloc(sizeof(struct if_stats_ctx));
	bzero(ctx, sizeof(struct if_stats_ctx));

	ctx->ifname = strdup(ifname);
	ctx->fd = fd;

	struct if_data ifd;
	bzero(&ifd, sizeof(ifd));
	fetch_if_data(&ifd, ctx->ifname, ctx->fd);

	ctx->hwstats = (ifd.ifi_hwassist & IFCAP_HWSTATS) != 0;
	if (ctx->hwstats) {
		ctx->ifi_ipackets = ifd.ifi_ipackets;
	} else {
		ctx->ifi_ipackets = 0;
	}
	ctx->ifi_iqdrops = ifd.ifi_iqdrops;
	ctx->ifi_ierrors = ifd.ifi_ierrors;
	ctx->ifi_oerrors = ifd.ifi_oerrors;
	return ctx;
}

void if_stats_fini(if_stats_ctx_t *ctx)
{
	free(ctx->ifname);
	free(ctx);
}

bool if_stats_have_recv_ctr(if_stats_ctx_t *ctx)
{
	return ctx->hwstats;
}

int if_stats_get(if_stats_ctx_t *ctx, uint32_t *ps_recv, uint32_t *ps_drop, uint32_t *ps_ifdrop)
{
	struct if_data ifd;
	bzero(&ifd, sizeof(ifd));
	fetch_if_data(&ifd, ctx->ifname, ctx->fd);

	if (ctx->hwstats) {
		*ps_recv = (uint32_t)(ifd.ifi_ipackets - ctx->ifi_ipackets);
	}
	*ps_drop = (uint32_t)(ifd.ifi_iqdrops - ctx->ifi_iqdrops);
	*ps_ifdrop = (uint32_t)(ifd.ifi_ierrors - ctx->ifi_ierrors +
				ifd.ifi_oerrors - ctx->ifi_oerrors);
	return 0;
}
