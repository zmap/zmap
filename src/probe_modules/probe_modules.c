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

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>

#include "../../lib/logger.h"
#include "../fieldset.h"
#include "probe_modules.h"
#include "packet.h"

extern probe_module_t module_tcp_synscan;
extern probe_module_t module_icmp_echo;
extern probe_module_t module_udp;
// ADD YOUR MODULE HERE

probe_module_t* probe_modules[] = {
	&module_tcp_synscan,
	&module_icmp_echo,
	&module_udp
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


void fs_add_ip_fields(fieldset_t *fs, struct iphdr *ip)
{
	// WARNING: you must update fs_ip_fields_len  as well
	// as the definitions set (ip_fiels) if you
	// change the fields added below:
	fs_add_string(fs, "saddr", make_ip_str(ip->saddr), 1);
	fs_add_uint64(fs, "saddr-raw", (uint64_t) ip->saddr);
	fs_add_string(fs, "daddr", make_ip_str(ip->daddr), 1);
	fs_add_uint64(fs, "daddr-raw", (uint64_t) ip->daddr);
	fs_add_uint64(fs, "ipid", ntohs(ip->id));
	fs_add_uint64(fs, "ttl", ip->ttl);
}

#define TIMESTR_LEN 55

void fs_add_system_fields(fieldset_t *fs, int is_repeat, int in_cooldown)
{
	fs_add_uint64(fs, "repeat", is_repeat);
	fs_add_uint64(fs, "cooldown", in_cooldown);

	char *timestr = malloc(TIMESTR_LEN+1);
	char *timestr_ms = malloc(TIMESTR_LEN+1);
	if (!timestr || !timestr_ms) {
		log_fatal("recv", "unable to allocate memory for "
				  "timestamp string in fieldset.");
	}
	struct timeval t;
	gettimeofday(&t, NULL);
	struct tm *ptm = localtime(&t.tv_sec);
	strftime(timestr, TIMESTR_LEN, "%Y-%m-%dT%H:%M:%S.%%03d%z", ptm);
	snprintf(timestr_ms, TIMESTR_LEN, timestr, t.tv_usec/1000);
	free(timestr);
	fs_add_string(fs, "timestamp-str", timestr_ms, 1);
	fs_add_uint64(fs, "timestamp-ts", (uint64_t) t.tv_sec);
	fs_add_uint64(fs, "timestamp-us", (uint64_t) t.tv_usec);
}

int ip_fields_len = 6; 
fielddef_t ip_fields[] = {
	{.name="saddr", .type="string", .desc="source IP address of response"},
	{.name="saddr-raw", .type="int", .desc="network order integer form of source IP address"},
	{.name="daddr", .type="string", .desc="destination IP address of response"},
	{.name="daddr-raw", .type="int", .desc="network order integer form of destination IP address"},
	{.name="ipid", .type="int", .desc="IP identification number of response"},
	{.name="ttl", .type="int", .desc="time-to-live of response packet"}
};

int sys_fields_len = 5;
fielddef_t sys_fields[] = {
	{.name="repeat", .type="int", .desc="Is response a repeat response from host"},
	{.name="cooldown", .type="int", .desc="Was response received during the cooldown period"},
	{.name="timestamp-str", .type="string", .desc="timestamp of when response arrived in ISO8601 format."},
	{.name="timestamp-ts", .type="int", .desc="timestamp of when response arrived in seconds since Epoch"},
	{.name="timestamp-us", .type="int", .desc="microsecond part of timestamp (e.g. microseconds since 'timestamp-ts')"}
};

