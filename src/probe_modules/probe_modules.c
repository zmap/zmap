/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <sys/time.h>

#include "../../lib/includes.h"
#include "../../lib/logger.h"
#include "../../lib/xalloc.h"
#include "../fieldset.h"
#include "probe_modules.h"
#include "packet.h"

extern probe_module_t module_tcp_cisco_backdoor;
extern probe_module_t module_tcp_synscan;
extern probe_module_t module_icmp_echo;
extern probe_module_t module_icmp_echo_time;
extern probe_module_t module_udp;
extern probe_module_t module_ntp;
extern probe_module_t module_upnp;
extern probe_module_t module_dns;
extern probe_module_t module_arp;
// ADD YOUR MODULE HERE

probe_module_t* probe_modules[] = {
	&module_tcp_synscan,
	&module_icmp_echo,
	&module_icmp_echo_time,
	&module_udp,
	&module_ntp,
	&module_upnp,
	&module_dns,
	&module_arp,
	&module_tcp_cisco_backdoor
	// ADD YOUR MODULE HERE
};

probe_module_t* get_probe_module_by_name(const char* name)
{
	int len = (int) (sizeof(probe_modules)/sizeof(probe_modules[0]));
	for (int i=0; i < len; i++) {
		if (!strcmp(probe_modules[i]->name, name)) {
			return probe_modules[i];
		}
	}
	return NULL;
}

void print_probe_modules(void)
{
	int len = (int) (sizeof(probe_modules)/sizeof(probe_modules[0]));
	for (int i=0; i < len; i++) {
		printf("%s\n", probe_modules[i]->name);
	}
}

int ip_validate_packet(const void *packet, uint32_t len, uint32_t *src_ip,
		         __attribute__((__unused__)) uint32_t *validation)
{
	if ((sizeof(struct ip) + sizeof(struct ether_header)) > len) {
		// buffer not large enough to contain ethernet
		// and ip headers. further action would overrun buf
		return 0;
	}

	struct ip *ip_hdr = (struct ip *) &((struct ether_header *)packet)[1];

	*src_ip = ip_hdr->ip_src.s_addr;

	return 1;
}

void ip_process_packet(const void *packet, __attribute__((unused)) uint32_t len, fieldset_t *fs)
{
	struct ip *ip_hdr = (struct ip *) &((struct ether_header *)packet)[1];
	fs_add_ip_fields(fs, ip_hdr);
}

void fs_add_eth_fields(fieldset_t *fs, struct ether_header *eth)
{
	// WARNING: you must update eth_fields_len  as well
	// as the definitions set (eth_fields) if you
	// change the fields added below:
	fs_add_string(fs, "smac", make_mac_str(eth->ether_shost), 1);
	fs_add_string(fs, "dmac", make_mac_str(eth->ether_dhost), 1);
	fs_add_uint64(fs, "eth-type", eth->ether_type);
}

void fs_add_ip_fields(fieldset_t *fs, struct ip *ip)
{
	// WARNING: you must update ip_fields_len as well
	// as the definitions set (ip_fields) if you
	// change the fields added below:
	fs_add_string(fs, "saddr", make_ip_str(ip->ip_src.s_addr), 1);
	fs_add_uint64(fs, "saddr_raw", (uint64_t) ip->ip_src.s_addr);
	fs_add_string(fs, "daddr", make_ip_str(ip->ip_dst.s_addr), 1);
	fs_add_uint64(fs, "daddr_raw", (uint64_t) ip->ip_dst.s_addr);
	fs_add_uint64(fs, "ipid", ntohs(ip->ip_id));
	fs_add_uint64(fs, "ttl", ip->ip_ttl);
}

#define TIMESTR_LEN 55

void fs_add_system_fields(fieldset_t *fs, int is_repeat, int in_cooldown)
{
	fs_add_uint64(fs, "repeat", is_repeat);
	fs_add_uint64(fs, "cooldown", in_cooldown);

	char *timestr = xmalloc(TIMESTR_LEN+1);
	char *timestr_ms = xmalloc(TIMESTR_LEN+1);
	struct timeval t;
	gettimeofday(&t, NULL);
	struct tm *ptm = localtime(&t.tv_sec);
	strftime(timestr, TIMESTR_LEN, "%Y-%m-%dT%H:%M:%S.%%03d%z", ptm);
	snprintf(timestr_ms, TIMESTR_LEN, timestr, t.tv_usec/1000);
	free(timestr);
	fs_add_string(fs, "timestamp_str", timestr_ms, 1);
	fs_add_uint64(fs, "timestamp_ts", (uint64_t) t.tv_sec);
	fs_add_uint64(fs, "timestamp_us", (uint64_t) t.tv_usec);
}

fielddefset_t ip_fields = {
	.fielddefs = {
		{.name="saddr", .type="string", .desc="source IP address of response"},
		{.name="saddr-raw", .type="int", .desc="network order integer form of source IP address"},
		{.name="daddr", .type="string", .desc="destination IP address of response"},
		{.name="daddr-raw", .type="int", .desc="network order integer form of destination IP address"},
		{.name="ipid", .type="int", .desc="IP identification number of response"},
		{.name="ttl", .type="int", .desc="time-to-live of response packet"}
	},
	.len = 6
};

fielddefset_t eth_fields = {
	.fielddefs = {
		{.name="smac", .type="string", .desc="source MAC address of response"},
		{.name="dmac", .type="string", .desc="destination MAC address of response"},
		{.name="eth-type", .type="int", .desc="ethernet packet type of response"}
	},
	.len = 3
};

fielddefset_t sys_fields = {
	.fielddefs = {
		{.name="repeat", .type="int", .desc="Is response a repeat response from host"},
		{.name="cooldown", .type="int", .desc="Was response received during the cooldown period"},
		{.name="timestamp-str", .type="string", .desc="timestamp of when response arrived in ISO8601 format."},
		{.name="timestamp-ts", .type="int", .desc="timestamp of when response arrived in seconds since Epoch"},
		{.name="timestamp-us", .type="int", .desc="microsecond part of timestamp (e.g. microseconds since 'timestamp-ts')"}
	},
	.len = 5
};

