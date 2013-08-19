/*
 * ZMap Copyright 2013 Regents of the University of Michigan 
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>

#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../../lib/logger.h"

#include "output_modules.h"

static FILE *file = NULL;
#define UNUSED __attribute__((unused))


int extendedfile_init(struct state_conf *conf)
{
	assert(conf);
	if (conf->output_filename) {
		if (!strcmp(conf->output_filename, "-")) {
			file = stdout;
		} else {
			if (!(file = fopen(conf->output_filename, "w"))) {
				perror("Couldn't open output file");
				exit(EXIT_FAILURE);
			}
		}
		fprintf(file, "response, saddr, daddr, sport, "
						"dport, seq, ack, in_cooldown, is_repeat, timestamp\n");
	}
	return EXIT_SUCCESS;
}

static void fprint_tv(FILE *f, struct timeval *tv) 
{
	char time_string[40]; 
	struct tm *ptm = localtime(&tv->tv_sec); 
	strftime(time_string, sizeof (time_string),
					"%Y-%m-%d %H:%M:%S", ptm);
	long milliseconds = tv->tv_usec / 1000; 
	fprintf(f, "%s.%03ld\n", time_string, milliseconds); 
} 


int extendedfile_ip(ipaddr_n_t saddr, ipaddr_n_t daddr,
		const char *response_type, int is_repeat,
		int in_cooldown, const u_char *packet, size_t buflen)
{
	struct iphdr *ip_hdr = (struct iphdr *)&packet[sizeof(struct ethhdr)];
	if (buflen < (sizeof(struct ethhdr) + ip_hdr->ihl*4 + sizeof(struct tcphdr)))
		return EXIT_FAILURE;
	struct tcphdr *tcp = (struct tcphdr *)((char *)ip_hdr + ip_hdr->ihl * 4);

	if (file) {
		struct in_addr addr;
		addr.s_addr = saddr;
		// inet_ntoa returns a <<const>> char * 
		fprintf(file, "%s, %s, ", 
				response_type, 
				inet_ntoa(addr));
		addr.s_addr = daddr;
		fprintf(file, "%s, %u, %u, %u, %u, %i, %i,", 
				inet_ntoa(addr),
				ntohs(tcp->source),
				ntohs(tcp->dest),
				ntohl(tcp->seq),
				ntohl(tcp->ack_seq),
				in_cooldown,
				is_repeat);
		struct timeval t;
		gettimeofday(&t, NULL);
		fprint_tv(file, &t);
		fflush(file);
	}
	return EXIT_SUCCESS;
}

int extendedfile_close(UNUSED struct state_conf* c, 
		UNUSED struct state_send* s, UNUSED struct state_recv* r)
{
	if (file) {
		fflush(file);
		fclose(file);
	}
	return EXIT_SUCCESS;
}

output_module_t module_extended_file = {
	.name = "extended_file",
	.init = &extendedfile_init,
	.start = NULL,
	.update = NULL,
	.update_interval = 0,
	.close = &extendedfile_close,
	.success_ip = &extendedfile_ip,
	.other_ip = &extendedfile_ip
};

