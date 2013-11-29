/*
 * ZMap Copyright 2013 Regents of the University of Michigan 
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <string.h>

#include "../lib/includes.h"
#include "../lib/logger.h"

#include <sys/ioctl.h>

#define ROUNDUP(a) ((a) > 0 ? (1 + (((a) - 1) | (sizeof(int) - 1))) : sizeof(int))

#define UNUSED __attribute__((unused))

int get_hw_addr(struct in_addr *gw_ip, unsigned char *hw_mac)
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
		memcpy(hw_mac, &entry.arp_ha.addr_eth, 6);
	}
	arp_close(arp);
	return EXIT_SUCCESS;
}

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__)

#include <net/route.h>
#include <net/if.h>
#include <net/if_dl.h>

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
        } else {
                fprintf(stderr, "%s\n", "#wat");
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
					log_fatal("get-gateway", "fuck");
				}
				char *_iface = malloc(sdl->sdl_nlen+1);
				assert(_iface);
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

int get_default_gw(struct in_addr *gw, char *iface)
{
	char** iface_ = &iface;
	_get_default_gw(gw, iface_);
	if (strcmp(*iface_, iface) != 0) {
		log_fatal("get-gateway", "interface specified (%s) does not match "
				"the interface of the default gateway (%s). You will need "
				"to manually specify the MAC address of your dateway.",
				*iface_);	
	}
	return EXIT_SUCCESS;
}

#else // (linux)

#include <sys/ioctl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>

char *get_default_iface(void)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	char *iface = pcap_lookupdev(errbuf);
	if (iface == NULL) {
		log_fatal("zmap", "could not detect default network interface "
				"(e.g. eth0). Try running as root or setting"
				" interface using -i flag.");
	}
	return iface;
}

int read_nl_sock(int sock, char *buf, int buf_len)
{
	int msg_len = 0;
	char *pbuf = buf;
	do {
		int len = recv(sock, pbuf, buf_len - msg_len, 0);
		if (len <= 0) {
			log_debug("get-gw", "recv failed: %s", strerror(errno));
			return -1;
		}
		struct nlmsghdr *nlhdr = (struct nlmsghdr *)pbuf;
		if (NLMSG_OK(nlhdr, ((unsigned int)len)) == 0 || 
						nlhdr->nlmsg_type == NLMSG_ERROR) {
			log_debug("get-gw", "recv failed: %s", strerror(errno));
			return -1;
		}
		if (nlhdr->nlmsg_type == NLMSG_DONE) {
			break;
		} else {
			msg_len += len;
			pbuf += len;
		} 
		if ((nlhdr->nlmsg_flags & NLM_F_MULTI) == 0) {
			break;
		}
	} while (1);
	return msg_len;
}

int send_nl_req(uint16_t msg_type, uint32_t seq,
				void *payload, uint32_t payload_len)
{
	int sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	if (sock < 0) {
		log_error("get-gw", "unable to get socket: %s", strerror(errno));
		return -1;
	}
	if (NLMSG_SPACE(payload_len) < payload_len) {
		// Integer overflow
		return -1;
	}
	struct nlmsghdr *nlmsg;
	nlmsg = malloc(NLMSG_SPACE(payload_len));
	if (!nlmsg) {
		return -1;
	}

	memset(nlmsg, 0, NLMSG_SPACE(payload_len));
	memcpy(NLMSG_DATA(nlmsg), payload, payload_len);
	nlmsg->nlmsg_type = msg_type;
	nlmsg->nlmsg_len = NLMSG_LENGTH(payload_len);
	nlmsg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
	nlmsg->nlmsg_seq = seq;
	nlmsg->nlmsg_pid = getpid();

	if (send(sock, nlmsg, nlmsg->nlmsg_len, 0) < 0) {
		log_error("get-gw", "failure sending: %s", strerror(errno));
		return -1;
	}
	free(nlmsg);
	return sock;
}

// gw and iface[IF_NAMESIZE] MUST be allocated
int get_default_gw(struct in_addr *gw, char *iface)
{
	struct rtmsg req;
	unsigned int nl_len;
	char buf[8192];
	struct nlmsghdr *nlhdr;

	if (!gw || !iface) {
		return -1;
	}

	// Send RTM_GETROUTE request
	memset(&req, 0, sizeof(req));
	int sock = send_nl_req(RTM_GETROUTE, 0, &req, sizeof(req));

	// Read responses
	nl_len = read_nl_sock(sock, buf, sizeof(buf));
	if (nl_len <= 0) {
		return -1;
	}

	// Parse responses
	nlhdr = (struct nlmsghdr *)buf;
	while (NLMSG_OK(nlhdr, nl_len)) {
		struct rtattr *rt_attr;
		struct rtmsg *rt_msg;
		int rt_len;
		int has_gw = 0;

		rt_msg = (struct rtmsg *) NLMSG_DATA(nlhdr);

		if ((rt_msg->rtm_family != AF_INET) || (rt_msg->rtm_table != RT_TABLE_MAIN)) {
			return -1;
		}

		rt_attr = (struct rtattr *) RTM_RTA(rt_msg);
		rt_len = RTM_PAYLOAD(nlhdr);
		while (RTA_OK(rt_attr, rt_len)) {
			switch (rt_attr->rta_type) {
			case RTA_OIF:
				if_indextoname(*(int *) RTA_DATA(rt_attr), iface); 
				break;
			case RTA_GATEWAY:
				gw->s_addr = *(unsigned int *) RTA_DATA(rt_attr); 
				has_gw = 1;
				break;
			}
			rt_attr = RTA_NEXT(rt_attr, rt_len);
		}
	
		if (has_gw) {
			return 0;
		}
		nlhdr = NLMSG_NEXT(nlhdr, nl_len);	
	}
	return -1;
}

int get_iface_ip(char *iface, struct in_addr *ip)
{
	int sock;
	struct ifreq ifr;
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		log_fatal("get-iface-ip", "failure opening socket: %s", strerror(errno));
	}
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);

	if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
		log_fatal("get-iface-ip", "ioctl failure: %s", strerror(errno));
		close(sock);
	}
	ip->s_addr =  ((struct sockaddr_in*) &ifr.ifr_addr)->sin_addr.s_addr;
	close(sock);
	return EXIT_SUCCESS;
}

int get_iface_hw_addr(char *iface, unsigned char *hw_mac)
{
	int s;
	struct ifreq buffer;

	// Load the hwaddr from a dummy socket
	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		log_error("get_iface_hw_addr", "Unable to open socket: %s",
			  strerror(errno));
		return EXIT_FAILURE;
	}
	memset(&buffer, 0, sizeof(buffer));
	strcpy(buffer.ifr_name, iface);
	ioctl(s, SIOCGIFHWADDR, &buffer);
	close(s);
	memcpy(hw_mac, buffer.ifr_hwaddr.sa_data, 6);
	return EXIT_SUCCESS;
}

#endif // end linux
