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

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>

#include "../fieldset.h"
#include "probe_modules.h"

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
	for (int i=0; i < (int) (sizeof(probe_modules)/sizeof(probe_modules[0])); i++) {
		if (!strcmp(probe_modules[i]->name, name)) {
			return probe_modules[i];
		}
	}
	return NULL;
}

void print_probe_modules(void)
{
	for (int i=0; i < (int) (sizeof(probe_modules)/sizeof(probe_modules[0])); i++) {
		printf("%s\n", probe_modules[i]->name);
	}
}

void print_probe_module_fields(probe_module_t *p)
{
	for (int i=0; i < (int) (sizeof(p->fields)/sizeof(p->fields[0])); i++) {

	}
}

char *make_ip_str(uint32_t ip)
{
	struct in_addr t;
	t.s_addr = ip;
	const char *temp = inet_ntoa(t);
	char *retv = malloc(strlen(temp)+1);
	assert (retv);
	strcpy(retv, temp);
	return retv;
}

void fs_add_ip_fields(fieldset_t *fs, struct iphdr *ip)
{
	fs_add_string(fs, "saddr", make_ip_str(ip->saddr), 1);
	fs_add_string(fs, "daddr", make_ip_str(ip->daddr), 1);
	fs_add_uint64(fs, "ipid", ntohl(ip->id));
	fs_add_uint64(fs, "ttl", ntohl(ip->ttl));
}

