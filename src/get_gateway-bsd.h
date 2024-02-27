/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef ZMAP_GET_GATEWAY_BSD_H
#define ZMAP_GET_GATEWAY_BSD_H

#ifdef ZMAP_GET_GATEWAY_LINUX_H
#error "Don't include both get_gateway-bsd.h and get_gateway-linux.h"
#endif

#include <net/route.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_arp.h>
#include <net/if_types.h>
#include <netinet/if_ether.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <assert.h>

#define ROUNDUP(a) ((a) > 0 ? (1 + (((a)-1) | (sizeof(int) - 1))) : sizeof(int))
#define UNUSED __attribute__((unused))

int get_hw_addr(struct in_addr *gw_ip, UNUSED char *iface,
		unsigned char *hw_mac)
{
	int mib[6];
	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE;
	mib[2] = 0;
	mib[3] = AF_INET;
	mib[4] = NET_RT_FLAGS;
	mib[5] = RTF_LLINFO;
	size_t bufsz = 0;
	if (sysctl(mib, 6, NULL, &bufsz, NULL, 0) == -1) {
		log_debug("get_hw_addr", "sysctl getting buffer size: %d %s", errno, strerror(errno));
		return EXIT_FAILURE;
	}
	uint8_t *buf = (uint8_t *)malloc(bufsz);
	assert(buf);
	if (sysctl(mib, 6, buf, &bufsz, NULL, 0) == -1) {
		log_debug("get_hw_addr", "sysctl getting buffer data: %d %s", errno, strerror(errno));
		free(buf);
		return EXIT_FAILURE;
	}

	int result = EXIT_FAILURE;
	uint8_t *bufend = buf + bufsz;
	size_t min_msglen = sizeof(struct rt_msghdr) + sizeof(struct sockaddr_inarp) + sizeof(struct sockaddr_dl);
	struct rt_msghdr *rtm = (struct rt_msghdr *)buf;
	for (uint8_t *p = buf; p < bufend; p += rtm->rtm_msglen) {
		rtm = (struct rt_msghdr *)p;
		if ((p + sizeof(struct rt_msghdr) > bufend) ||
		    (p + rtm->rtm_msglen > bufend) ||
		    (rtm->rtm_msglen < min_msglen)) {
			break;
		}
		struct sockaddr_inarp *sin = (struct sockaddr_inarp *)(rtm + 1);
		struct sockaddr_dl *sdl = (struct sockaddr_dl *)(sin + 1);
		assert(sin->sin_family == AF_INET);
		if (sin->sin_addr.s_addr != gw_ip->s_addr) {
			continue;
		}
		assert(sdl->sdl_family == AF_LINK);
		memcpy(hw_mac, LLADDR(sdl), ETHER_ADDR_LEN);
		result = EXIT_SUCCESS;
	}

	free(buf);
	return result;
}

int get_iface_ip(char *iface, struct in_addr *ip)
{
	assert(iface);
	struct ifaddrs *ifaddr, *ifa;
	if (getifaddrs(&ifaddr)) {
		log_fatal(
		    "get-iface-ip",
		    "ZMap is unable able to retrieve a list of available network "
		    "interfaces: %s. You can manually specify the network interface "
		    "to use with the \"-i\" flag.",
		    strerror(errno));
	}
	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL ||
		    ifa->ifa_addr->sa_family != AF_INET) {
			continue;
		}
		if (!strcmp(iface, ifa->ifa_name)) {
			struct sockaddr_in *sin =
			    (struct sockaddr_in *)ifa->ifa_addr;
			ip->s_addr = sin->sin_addr.s_addr;
			log_debug("get-iface-ip", "IP address found for %s: %s",
				  iface, inet_ntoa(*ip));
			freeifaddrs(ifaddr);
			return EXIT_SUCCESS;
		}
	}
	log_fatal("get-iface-ip",
		  "The specified network interface (\"%s\") does not"
		  " exist or does not have an assigned IPv4 address.",
		  iface);
	return EXIT_FAILURE;
}

int get_iface_hw_addr(char *iface, unsigned char *hw_mac)
{
	struct ifaddrs *ifa;
	if (getifaddrs(&ifa) == -1) {
		log_debug("get_iface_hw_addr", "getifaddrs(): %d %s", errno, strerror(errno));
		return EXIT_FAILURE;
	}
	int result = EXIT_FAILURE;
	for (struct ifaddrs *p = ifa; p; p = p->ifa_next) {
		if (strcmp(p->ifa_name, iface) == 0 &&
		    p->ifa_addr != NULL && p->ifa_addr->sa_family == AF_LINK) {
			struct sockaddr_dl *sdl = (struct sockaddr_dl *)p->ifa_addr;
			memcpy(hw_mac, LLADDR(sdl), ETHER_ADDR_LEN);
			result = EXIT_SUCCESS;
			break;
		}
	}
	freeifaddrs(ifa);
	return result;
}

int _get_default_gw(struct in_addr *gw, char **iface)
{
	char buf[4096];
	struct rt_msghdr *rtm = (struct rt_msghdr *)&buf;
	memset(rtm, 0, sizeof(buf));
	int seq = 0x00FF;
	rtm->rtm_msglen = sizeof(buf);
	rtm->rtm_type = RTM_GET;
	rtm->rtm_flags = RTF_GATEWAY;
	rtm->rtm_version = RTM_VERSION;
	rtm->rtm_seq = seq;
	rtm->rtm_addrs = RTA_DST | RTA_IFP;
	rtm->rtm_pid = getpid();

	int fd = socket(PF_ROUTE, SOCK_RAW, 0);
	assert(fd > 0);
	if (!write(fd, (char *)rtm, sizeof(buf))) {
		log_fatal(
		    "get-gateway",
		    "Unable to send request to retrieve default"
		    "gateway MAC address. You will need to manually specify your "
		    "gateway MAC with the \"-G\" or \"--gateway-mac\" flag.");
	}
	size_t len;
	while (rtm->rtm_type == RTM_GET &&
	       (len = read(fd, rtm, sizeof(buf))) > 0) {
		if (len < (int)sizeof(*rtm)) {
			close(fd);
			return (-1);
		}
		if (rtm->rtm_type == RTM_GET && rtm->rtm_pid == getpid() &&
		    rtm->rtm_seq == seq) {
			if (rtm->rtm_errno) {
				close(fd);
				errno = rtm->rtm_errno;
				return (-1);
			}
			break;
		}
	}

	struct sockaddr *sa = (struct sockaddr *)(rtm + 1);
	for (int i = 0; i < RTAX_MAX; i++) {
		if (rtm->rtm_addrs & (1 << i)) {
			if ((1 << i) == RTA_IFP) {
				struct sockaddr_dl *sdl =
				    (struct sockaddr_dl *)sa;
				if (!sdl) {
					log_fatal(
					    "get-gateway",
					    "Unable to parse kernel response to request "
					    "for gateway MAC address. You will need to manually specify "
					    "your gateway MAC with the \"-G\" or \"--gateway-mac\" flag.");
				}
				char *_iface = xmalloc(sdl->sdl_nlen + 1);
				memcpy(_iface, sdl->sdl_data, sdl->sdl_nlen);
				_iface[sdl->sdl_nlen + 1] = 0;
				*iface = _iface;
			}
			if ((1 << i) == RTA_GATEWAY) {
				struct sockaddr_in *sin =
				    (struct sockaddr_in *)sa;
				gw->s_addr = sin->sin_addr.s_addr;
			}
			// next element
			sa = (struct sockaddr *)(ROUNDUP(sa->sa_len) +
						 (char *)sa);
		}
	}
	close(fd);
	return EXIT_SUCCESS;
}

char *get_default_iface(void)
{
	struct in_addr t;
	char *retv = NULL;
	_get_default_gw(&t, &retv);
	return retv;
}

int get_default_gw(struct in_addr *gw, UNUSED char *iface)
{
	char *_iface = NULL;
	_get_default_gw(gw, &_iface);
	return EXIT_SUCCESS;
}

#endif /* ZMAP_GET_GATEWAY_BSD_H */
