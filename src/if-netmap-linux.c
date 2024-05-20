/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include "if-netmap.h"

#include "../lib/includes.h"
#include "../lib/logger.h"
#include "utility.h"

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <assert.h>
#include <errno.h>

static int
nlrt_socket(void)
{
	int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (fd == -1) {
		log_fatal("if-netmap-linux", "socket(NETLINK_ROUTE): %d: %s", errno, strerror(errno));
	}

	int one = 1;
	(void)setsockopt(fd, SOL_NETLINK, NETLINK_CAP_ACK, &one, sizeof(one));

	struct sockaddr_nl sanl;
	memset(&sanl, 0, sizeof(sanl));
	sanl.nl_family = AF_NETLINK;

	if (bind(fd, (struct sockaddr *)&sanl, sizeof(sanl)) == -1) {
		log_fatal("if-netmap-linux", "bind(AF_NETLINK): %d: %s", errno, strerror(errno));
	}

	return fd;
}

static void
fetch_stats64(struct rtnl_link_stats64 *rtlstats64, char const *ifname, int nlrtfd)
{
	struct {
		struct nlmsghdr nlh;
		struct if_stats_msg ifsm;
	} nlreq;
	memset(&nlreq, 0, sizeof(nlreq));
	nlreq.nlh.nlmsg_len = sizeof(nlreq);
	nlreq.nlh.nlmsg_type = RTM_GETSTATS;
	nlreq.nlh.nlmsg_flags = NLM_F_REQUEST;
	nlreq.ifsm.ifindex = if_nametoindex(ifname);
	nlreq.ifsm.filter_mask = IFLA_STATS_LINK_64;

	struct iovec iov[2];
	memset(&iov[0], 0, sizeof(iov[0]));
	iov[0].iov_base = (void *)&nlreq;
	iov[0].iov_len = sizeof(nlreq);

	struct msghdr msg;
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov[0];
	msg.msg_iovlen = 1;

	if (sendmsg(nlrtfd, &msg, 0) == -1) {
		log_fatal("if-netmap-linux", "sendmsg(RTM_GETSTATS): %d: %s", errno, strerror(errno));
	}

	struct nlresp {
		struct nlmsghdr nlh;
		union {
			struct {
				struct rtmsg rth;
				struct rtnl_link_stats64 rtlstats64;
			} ans;
			struct {
				struct nlmsgerr nlerr;
			} err;
		} u;
	} nlresp;
	static_assert(sizeof(nlresp.u.ans) >= sizeof(nlresp.u.err), "ans is at least as large as err");
	static const size_t ans_size = offsetof(struct nlresp, u.ans) + sizeof(nlresp.u.ans);
	static const size_t err_size = offsetof(struct nlresp, u.err) + sizeof(nlresp.u.err);

	memset(iov, 0, sizeof(iov));
	iov[0].iov_base = (void *)&nlresp;
	iov[0].iov_len = offsetof(struct nlresp, u.ans.rtlstats64);
	iov[1].iov_base = (void *)rtlstats64; // caller-provided
	iov[1].iov_len = sizeof(struct rtnl_link_stats64);
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = iov;
	msg.msg_iovlen = 2;

	ssize_t n = recvmsg(nlrtfd, &msg, 0);
	if (n == -1) {
		log_fatal("if-netmap-linux", "recvmsg(RTM_GETSTATS): %d: %s", errno, strerror(errno));
	}
	if ((size_t)n < err_size) {
		log_fatal("if-netmap-linux", "received %zu expected %zu or larger", (size_t)n, err_size);
	}

	if (nlresp.nlh.nlmsg_type == NLMSG_ERROR) {
		// copy second iov into ans in first iov to get contiguous struct nlmsgerr
		nlresp.u.ans.rtlstats64 = *rtlstats64;
		assert(nlresp.u.err.nlerr.error < 0);
		errno = -nlresp.u.err.nlerr.error;
		log_fatal("if-netmap-linux", "received NLMSG_ERROR: %d: %s", errno, strerror(errno));
	}
	if (nlresp.nlh.nlmsg_type != RTM_NEWSTATS) {
		log_fatal("if-netmap-linux", "received unexpected nlmsg_type %u", nlresp.nlh.nlmsg_type);
	}
	if ((size_t)n != ans_size) {
		log_fatal("if-netmap-linux", "received %zu expected %zu", (size_t)n, ans_size);
	}
}

void if_wait_for_phy_reset(char const *ifname, int fd)
{
	// clobber deliberately
	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (fd == -1) {
		log_fatal("if-netmap-linux", "socket(AF_INET): %d: %s", errno, strerror(errno));
	}

	for (size_t i = 0; i < 40 /* 10s */; i++) {
		struct ifreq ifr;
		cross_platform_strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name) - 1);
		struct ethtool_value etv;
		etv.cmd = ETHTOOL_GLINK;
		ifr.ifr_data = (void *)&etv;
		if (ioctl(fd, SIOCETHTOOL, &ifr) == -1) {
			log_fatal("if-netmap-linux", "ioctl(SIOCETHTOOL): %d: %s", errno, strerror(errno));
		}
		if (etv.data != 0 /* carrier */) {
			close(fd);
			return;
		}
		usleep(250000);
	}
	log_fatal("if-netmap-linux", "timeout waiting for PHY reset to complete");
}

size_t
if_get_data_link_size(UNUSED char const *ifname, UNUSED int fd)
{
	// Assuming Ethernet is not entirely unreasonable, as that's
	// the only thing we support on the send path anyway.
	// TODO figure out actual link type or link header size
	return sizeof(struct ether_header);
}

struct if_stats_ctx {
	char *ifname; // owned
	int nlrtfd;   // owned
	// uint64_t rx_packets;
	uint64_t rx_dropped;
	uint64_t rx_errors;
	uint64_t tx_errors;
};

if_stats_ctx_t *
if_stats_init(char const *ifname, UNUSED int fd)
{
	if_stats_ctx_t *ctx = malloc(sizeof(struct if_stats_ctx));
	memset(ctx, 0, sizeof(struct if_stats_ctx));

	ctx->ifname = strdup(ifname);
	ctx->nlrtfd = nlrt_socket();

	struct rtnl_link_stats64 rtlstats64;
	memset(&rtlstats64, 0, sizeof(rtlstats64));
	fetch_stats64(&rtlstats64, ctx->ifname, ctx->nlrtfd);

	//ctx->rx_packets = rtlstats64.rx_packets;
	ctx->rx_dropped = rtlstats64.rx_dropped;
	ctx->rx_errors = rtlstats64.rx_errors;
	ctx->tx_errors = rtlstats64.tx_errors;
	return ctx;
}

void if_stats_fini(if_stats_ctx_t *ctx)
{
	free(ctx->ifname);
	close(ctx->nlrtfd);
	free(ctx);
}

bool if_stats_have_recv_ctr(UNUSED if_stats_ctx_t *ctx)
{
	return false;
}

int if_stats_get(if_stats_ctx_t *ctx, UNUSED uint32_t *ps_recv, uint32_t *ps_drop, uint32_t *ps_ifdrop)
{
	struct rtnl_link_stats64 rtlstats64;
	memset(&rtlstats64, 0, sizeof(rtlstats64));
	fetch_stats64(&rtlstats64, ctx->ifname, ctx->nlrtfd);

	//*ps_recv = (uint32_t)(rtlstats64.rx_packets - ctx->rx_packets);
	*ps_drop = (uint32_t)(rtlstats64.rx_dropped - ctx->rx_dropped);
	*ps_ifdrop = (uint32_t)(rtlstats64.rx_errors - ctx->rx_errors +
				rtlstats64.tx_errors - ctx->tx_errors);
	return 0;
}
