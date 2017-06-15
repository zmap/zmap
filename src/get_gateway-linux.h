/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef ZMAP_GET_GATEWAY_LINUX_H
#define ZMAP_GET_GATEWAY_LINUX_H

#ifdef ZMAP_GET_GATEWAY_BSD_H
#error "Don't include both get_gateway-bsd.h and get_gateway-linux.h"
#endif

#include <sys/ioctl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>

#define GW_BUFFER_SIZE 64000

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
		close(sock);
		// Integer overflow
		return -1;
	}
	struct nlmsghdr *nlmsg;
	nlmsg = xmalloc(NLMSG_SPACE(payload_len));

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

int get_hw_addr(struct in_addr *gw_ip, char *iface, unsigned char *hw_mac)
{
	struct ndmsg req;
	memset(&req, 0, sizeof(struct ndmsg));

	if (!gw_ip || !hw_mac) {
		return -1;
	}
	// Send RTM_GETNEIGH request
	req.ndm_family = AF_INET;
	req.ndm_ifindex = if_nametoindex(iface);
	req.ndm_state = NUD_REACHABLE;
	req.ndm_type = NDA_LLADDR;

	int sock = send_nl_req(RTM_GETNEIGH, 1, &req, sizeof(req));
	// Read responses
	char *buf = xmalloc(GW_BUFFER_SIZE);
	int nl_len = read_nl_sock(sock, buf, GW_BUFFER_SIZE);
	if (nl_len <= 0) {
		free(buf);
		return -1;
	}
	// Parse responses
	struct nlmsghdr *nlhdr = (struct nlmsghdr *) buf;
	while (NLMSG_OK(nlhdr, nl_len)) {
		struct rtattr *rt_attr;
		struct rtmsg *rt_msg;
		int rt_len;
		unsigned char mac[6];
		struct in_addr dst_ip;
		int correct_ip = 0;

		rt_msg = (struct rtmsg *) NLMSG_DATA(nlhdr);
		if ((rt_msg->rtm_family != AF_INET)) {
			free(buf);
			return -1;
		}
		rt_attr = (struct rtattr *) RTM_RTA(rt_msg);
		rt_len = RTM_PAYLOAD(nlhdr);
		while (RTA_OK(rt_attr, rt_len)) {
			switch (rt_attr->rta_type) {
			case NDA_LLADDR:
				if (RTA_PAYLOAD(rt_attr) != IFHWADDRLEN) {
					// could be using a VPN
					log_fatal("get_gateway", "Unexpected hardware address length (%d)."
						" If you are using a VPN, supply the --vpn flag (and provide an"
                        " interface via -i)",
						RTA_PAYLOAD(rt_attr));
				}
				memcpy(mac, RTA_DATA(rt_attr), IFHWADDRLEN);
				break;
			case NDA_DST:
				if (RTA_PAYLOAD(rt_attr) != sizeof(dst_ip)) {
					// could be using a VPN
					log_fatal("get_gateway", "Unexpected IP address length (%d)."
						" If you are using a VPN, supply the --vpn flag"
                        " (and provide an interface via -i)",
						RTA_PAYLOAD(rt_attr));
				}
				memcpy(&dst_ip, RTA_DATA(rt_attr), sizeof(dst_ip));
				if (memcmp(&dst_ip, gw_ip, sizeof(dst_ip)) == 0) {
					correct_ip = 1;
				}
				break;
			}
			rt_attr = RTA_NEXT(rt_attr, rt_len);
		}
		if (correct_ip) {
			memcpy(hw_mac, mac, IFHWADDRLEN);
			free(buf);
			return 0;
		}
		nlhdr = NLMSG_NEXT(nlhdr, nl_len);
	}
	free(buf);
	return -1;
}

// gw and iface[IF_NAMESIZE] MUST be allocated
int _get_default_gw(struct in_addr *gw, char *iface)
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

int get_default_gw(struct in_addr *gw, char *iface)
{
	char _iface[IF_NAMESIZE];
	memset(_iface, 0, IF_NAMESIZE);

	_get_default_gw(gw, _iface);
	if (strcmp(iface, _iface) != 0) {
		log_fatal("get-gateway", "interface specified (%s) does not match "
				"the interface of the default gateway (%s). You will need "
				"to manually specify the MAC address of your gateway.",
				iface, _iface);
	}
	return EXIT_SUCCESS;
}

int get_iface_ip(char *iface, struct in_addr *ip)
{
	int sock;
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(struct ifreq));
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		log_fatal("get-iface-ip", "failure opening socket: %s", strerror(errno));
	}
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);

	if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
		close(sock);
		log_fatal("get-iface-ip", "ioctl failure: %s", strerror(errno));
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
	strncpy(buffer.ifr_name, iface, IFNAMSIZ);
	ioctl(s, SIOCGIFHWADDR, &buffer);
	close(s);
	memcpy(hw_mac, buffer.ifr_hwaddr.sa_data, 6);
	return EXIT_SUCCESS;
}

#endif /* ZMAP_GET_GATEWAY_LINUX_H */
