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

#if !defined(__APPLE__)

#if __GNUC__ < 4
#error "gcc version >= 4 is required"
#elif __GNUC_MINOR_ >= 6
#pragma GCC diagnostic ignored "-Wflexible-array-extensions"
#endif

#include <dnet/os.h>
#include <dnet/eth.h>
#include <dnet/ip.h>
#include <dnet/ip6.h>
#include <dnet/addr.h>
#include <dnet/arp.h>
#endif

#define ROUNDUP(a) ((a) > 0 ? (1 + (((a) - 1) | (sizeof(int) - 1))) : sizeof(int))
#define UNUSED __attribute__((unused))

int get_hw_addr(struct in_addr *gw_ip, UNUSED char *iface, unsigned char *hw_mac)
{
	arp_t *arp;
	struct arp_entry entry;

	if (!gw_ip || !hw_mac) {
		return EXIT_FAILURE;
	}

	if ((arp = arp_open()) == NULL) {
		log_error("get_hw_addr", "failed to open arp table");
		return EXIT_FAILURE;
	}

	// Convert gateway ip to dnet struct format
	memset(&entry, 0, sizeof(struct arp_entry));
	entry.arp_pa.addr_type = ADDR_TYPE_IP;
	entry.arp_pa.addr_bits = IP_ADDR_BITS;
	entry.arp_pa.addr_ip = gw_ip->s_addr;

	if (arp_get(arp, &entry) < 0) {
		log_debug("get_hw_addr", "failed to fetch arp entry");
		return EXIT_FAILURE;
	} else {
		log_debug("get_hw_addr", "found ip %s at hw_addr %s",
			   addr_ntoa(&entry.arp_pa),
			   addr_ntoa(&entry.arp_ha));
		memcpy(hw_mac, &entry.arp_ha.addr_eth, ETHER_ADDR_LEN);
	}
	arp_close(arp);
	return EXIT_SUCCESS;
}

int get_iface_ip(char *iface, struct in_addr *ip)
{
    assert(iface);
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr)) {
        log_fatal("get-iface-ip", "unable able to retrieve list of network interfaces: %s",
                        strerror(errno));
    }
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_INET) {
            continue;
        }
        if (!strcmp(iface, ifa->ifa_name)) {
            struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
            ip->s_addr = sin->sin_addr.s_addr;
            log_debug("get-iface-ip", "ip address found for %s: %s",
                            iface, inet_ntoa(*ip));
            return EXIT_SUCCESS;
        }
    }
    log_fatal("get-iface-ip", "specified interface does not"
                    " exist or have an IPv4 address");
    return EXIT_FAILURE;
}

int get_iface_hw_addr(char *iface, unsigned char *hw_mac)
{
        eth_t *e = eth_open(iface);
        if (e) {
                eth_addr_t eth_addr;
                int res = eth_get(e, &eth_addr);
                log_debug("gateway", "res: %d", res);
                if (res == 0) {
                        memcpy(hw_mac, eth_addr.data, ETHER_ADDR_LEN);
                        return EXIT_SUCCESS;
                }
        }
        return EXIT_FAILURE;
}

int _get_default_gw(struct in_addr *gw, char **iface)
{
	char buf[4096];
	struct rt_msghdr *rtm = (struct rt_msghdr*) &buf;
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
	assert (fd > 0);
	if (!write(fd, (char*) rtm, sizeof(buf))) {
		log_fatal("get-gateway", "unable to send request");
	}

	size_t len;
	while (rtm->rtm_type == RTM_GET && (len = read(fd, rtm, sizeof(buf))) > 0) {
		if (len < (int)sizeof(*rtm)) {
			return (-1);
		}
		if (rtm->rtm_type == RTM_GET && rtm->rtm_pid == getpid() && rtm->rtm_seq == seq) {
			if (rtm->rtm_errno) {
				errno = rtm->rtm_errno;
				return (-1);
			}
			break;
		}
	}

	struct sockaddr *sa = (struct sockaddr *)(rtm + 1);
	for (int i = 0; i < RTAX_MAX; i++) {
		if (rtm->rtm_addrs & (1 << i)) {
			if ((1<<i) == RTA_IFP) {
				struct sockaddr_dl *sdl = (struct sockaddr_dl *) sa;
				if (!sdl) {
					log_fatal("get-gateway", "unable to retrieve gateway");
				}
				char *_iface = xmalloc(sdl->sdl_nlen+1);
				memcpy(_iface, sdl->sdl_data, sdl->sdl_nlen);
				_iface[sdl->sdl_nlen+1] = 0;
				*iface = _iface;
			}
			if ((1<<i) == RTA_GATEWAY) {
				struct sockaddr_in *sin = (struct sockaddr_in *) sa;
				gw->s_addr = sin->sin_addr.s_addr;
			}
			// next element
			sa = (struct sockaddr *)(ROUNDUP(sa->sa_len) + (char *)sa);
		}
	}
	close(fd);
	return EXIT_SUCCESS;
}

char* get_default_iface(void)
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
