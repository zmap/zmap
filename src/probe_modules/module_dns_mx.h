/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

struct dnshdr {
    
    char* dns_msg_header;
    char* dns_msg_name;
    char* dns_msg_tail;
    char* dns_msg_additional;

};

int dnshdr_default(struct dnshdr *passed_in, unsigned long src_ip);
void dns_print_packet(FILE *fp, void* packet);

int dns_make_packet(void *buf, ipaddr_n_t src_ip, ipaddr_n_t dst_ip,
		uint32_t *validation, int probe_num, void *arg);

int dns_validate_packet(const struct ip *ip_hdr, uint32_t len,
		__attribute__((unused))uint32_t *src_ip, uint32_t *validation);

