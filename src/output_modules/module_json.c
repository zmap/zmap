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
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#include <json.h>

#include "../../lib/logger.h"

#include "output_modules.h"
#include "../probe_modules/probe_modules.h"

static FILE *file = NULL;
#define UNUSED __attribute__((unused))


//#define json_object_object_add(a,b,c) { fprintf(stderr, "adding %s\n", b); json_object_object_add(a,b,c); }

int json_output_file_init(struct state_conf *conf)
{
	int i;
	char mac_buf[ (IFHWADDRLEN * 2) + (IFHWADDRLEN - 1) + 1 ];
	char *p;
	json_object *obj = json_object_new_object();
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
	
		// Create a header json object to describe this output file
		json_object_object_add(obj, "type", json_object_new_string("header"));
		json_object_object_add(obj, "log_level", json_object_new_int(conf->log_level));
		json_object_object_add(obj, "target_port", json_object_new_int(conf->target_port));
		json_object_object_add(obj, "source_port_first", json_object_new_int(conf->source_port_first));
		json_object_object_add(obj, "source_port_last", json_object_new_int(conf->source_port_last));
		json_object_object_add(obj, "max_targets", json_object_new_int(conf->max_targets));
		json_object_object_add(obj, "max_runtime", json_object_new_int(conf->max_runtime));
		json_object_object_add(obj, "max_results", json_object_new_int(conf->max_results));
		if (conf->iface) json_object_object_add(obj, "iface", json_object_new_string(conf->iface));
		json_object_object_add(obj, "rate", json_object_new_int(conf->rate));

		json_object_object_add(obj, "bandwidth", json_object_new_int64(conf->bandwidth));
		json_object_object_add(obj, "cooldown_secs", json_object_new_int(conf->cooldown_secs));
		json_object_object_add(obj, "senders", json_object_new_int(conf->senders));
		json_object_object_add(obj, "use_seed", json_object_new_int(conf->use_seed));
		json_object_object_add(obj, "seed", json_object_new_int(conf->seed));
		json_object_object_add(obj, "generator", json_object_new_int(conf->generator));
		json_object_object_add(obj, "packet_streams", json_object_new_int(conf->packet_streams));
		json_object_object_add(obj, "probe_module", json_object_new_string(((probe_module_t *)conf->probe_module)->name));
		json_object_object_add(obj, "output_module", json_object_new_string(((output_module_t *)conf->output_module)->name));
		
		if (conf->probe_args) json_object_object_add(obj, "probe_args", json_object_new_string(conf->probe_args));
		if (conf->output_args) json_object_object_add(obj, "output_args", json_object_new_string(conf->output_args));

		if (conf->gw_mac) {
			memset(mac_buf, 0, sizeof(mac_buf));
			p = mac_buf;
			for(i=0; i < IFHWADDRLEN; i++) {
				if (i == IFHWADDRLEN-1) {
					snprintf(p, 3, "%.2x", conf->gw_mac[i]);
					p += 2;
				} else {
					snprintf(p, 4, "%.2x:", conf->gw_mac[i]);
					p += 3;
				}
			}
			json_object_object_add(obj, "gw_mac", json_object_new_string(mac_buf));
		}

		json_object_object_add(obj, "source_ip_first", json_object_new_string(conf->source_ip_first));
		json_object_object_add(obj, "source_ip_last", json_object_new_string(conf->source_ip_last));
		json_object_object_add(obj, "output_filename", json_object_new_string(conf->output_filename));
		if (conf->blacklist_filename) json_object_object_add(obj, "blacklist_filename", json_object_new_string(conf->blacklist_filename));
		if (conf->whitelist_filename) json_object_object_add(obj, "whitelist_filename", json_object_new_string(conf->whitelist_filename));
		json_object_object_add(obj, "dryrun", json_object_new_int(conf->dryrun));
		json_object_object_add(obj, "summary", json_object_new_int(conf->summary));
		json_object_object_add(obj, "quiet", json_object_new_int(conf->quiet));
		json_object_object_add(obj, "recv_ready", json_object_new_int(conf->recv_ready));


		fprintf(file, "%s\n", json_object_to_json_string(obj));
	}
	return EXIT_SUCCESS;
}

static void json_output_file_store_tv(json_object *obj, struct timeval *tv) 
{
	char time_string[40]; 
	struct tm *ptm = localtime(&tv->tv_sec); 
	long milliseconds = tv->tv_usec / 1000; 
	
	strftime(time_string, sizeof (time_string), "%Y-%m-%d %H:%M:%S", ptm);

	json_object_object_add(obj, "t", json_object_new_string(time_string));
	json_object_object_add(obj, "ts", json_object_new_int(tv->tv_sec));
	json_object_object_add(obj, "tm", json_object_new_int(milliseconds));
}

static void json_output_file_store_data(json_object *obj, const u_char *packet, size_t buflen) 
{
	unsigned int i;
	char *buf;

	buf = malloc((buflen*2)+1);
	buf[buflen*2] = 0;

	for (i=0; i<buflen; i++)
		snprintf(buf + (i*2), 3, "%.2x", packet[i]);
	json_object_object_add(obj, "data", json_object_new_string(buf));
	json_object_object_add(obj, "length", json_object_new_int(buflen));
	free(buf);
} 


int json_output_file_ip(ipaddr_n_t saddr, ipaddr_n_t daddr,
		const char *response_type, int is_repeat,
		int in_cooldown, const u_char *packet, size_t buflen)
{
	struct iphdr *ip_hdr = (struct iphdr *)&packet[sizeof(struct ethhdr)];
	int data_offset = 0;
	struct timeval t;
	char tbuff[10];
	struct tcphdr *tcp;
	struct udphdr *udp; 
	struct icmphdr *icmp;
	struct in_addr addr;

	json_object *obj = json_object_new_object();

	if (buflen < (sizeof(struct ethhdr) + ip_hdr->ihl*4))
		return EXIT_FAILURE;

	if (buflen < (sizeof(struct ethhdr) + ip_hdr->ihl*4 + sizeof(struct tcphdr)) && ip_hdr->protocol == IPPROTO_TCP)
		return EXIT_FAILURE;

	if (buflen < (sizeof(struct ethhdr) + ip_hdr->ihl*4 + sizeof(struct udphdr)) && ip_hdr->protocol == IPPROTO_UDP)
		return EXIT_FAILURE;

	if (buflen < (sizeof(struct ethhdr) + ip_hdr->ihl*4 + sizeof(struct icmphdr)) && ip_hdr->protocol == IPPROTO_ICMP)
		return EXIT_FAILURE;

	if (!file)
		return EXIT_SUCCESS;

	json_object_object_add(obj, "type", json_object_new_string("result"));
	json_object_object_add(obj, "response-type", json_object_new_string(response_type));

	addr.s_addr = saddr;
	json_object_object_add(obj, "saddr", json_object_new_string(inet_ntoa(addr)));

	addr.s_addr = daddr;
	json_object_object_add(obj, "daddr", json_object_new_string(inet_ntoa(addr)));

	switch(ip_hdr->protocol){
		case IPPROTO_ICMP:
			icmp = (struct icmphdr *)((char *)ip_hdr + ip_hdr->ihl * 4);
			json_object_object_add(obj, "proto", json_object_new_string("icmp"));
			json_object_object_add(obj, "icmp_type", json_object_new_int(icmp->type));
			json_object_object_add(obj, "icmp_code", json_object_new_int(icmp->code));
			data_offset = sizeof(struct ethhdr) + ip_hdr->ihl*4 + sizeof(struct icmphdr);
			break;

		case IPPROTO_IGMP:
			json_object_object_add(obj, "protocol", json_object_new_string("igmp"));
			break;

		case IPPROTO_TCP:
			tcp = (struct tcphdr *)((char *)ip_hdr + ip_hdr->ihl * 4);
			json_object_object_add(obj, "proto", json_object_new_string("tcp"));
			json_object_object_add(obj, "sport", json_object_new_int(ntohs(tcp->source)));
			json_object_object_add(obj, "dport", json_object_new_int(ntohs(tcp->dest)));
			// Print these as 64-bit values to keep the text output unsigned
			json_object_object_add(obj, "seq", json_object_new_int64(ntohl(tcp->seq)));
			json_object_object_add(obj, "ack", json_object_new_int64(ntohl(tcp->ack_seq)));
			data_offset = sizeof(struct ethhdr) + ip_hdr->ihl*4 + tcp->doff*4;
			break;

		case IPPROTO_UDP:
			udp = (struct udphdr *)((char *)ip_hdr + ip_hdr->ihl * 4);
			json_object_object_add(obj, "proto", json_object_new_string("udp"));
			json_object_object_add(obj, "sport", json_object_new_int(ntohs(udp->source)));
			json_object_object_add(obj, "dport", json_object_new_int(ntohs(udp->dest)));
			data_offset = sizeof(struct ethhdr) + ip_hdr->ihl*4 + sizeof(struct udphdr);
			break;

		default:
			snprintf(tbuff, sizeof(tbuff), "proto-%d", ip_hdr->protocol);
			json_object_object_add(obj, "proto", json_object_new_string(tbuff));
	}

	json_object_object_add(obj, "in_cooldown", json_object_new_int(in_cooldown));
	json_object_object_add(obj, "is_repeat", json_object_new_int(is_repeat));

	gettimeofday(&t, NULL);
	json_output_file_store_tv(obj, &t);

	if ((ip_hdr->protocol == IPPROTO_UDP || ip_hdr->protocol == IPPROTO_ICMP) && (buflen - data_offset) > 0)
		json_output_file_store_data(obj, packet + data_offset, buflen - data_offset);

	fprintf(file, "%s\n", json_object_to_json_string(obj));
	fflush(file);
	
	return EXIT_SUCCESS;
}

int json_output_file_close(UNUSED struct state_conf* c, 
		UNUSED struct state_send* s, UNUSED struct state_recv* r)
{
	if (file) {
		fflush(file);
		fclose(file);
	}
	return EXIT_SUCCESS;
}

output_module_t module_json_file = {
	.name = "json_file",
	.init = &json_output_file_init,
	.start = NULL,
	.update = NULL,
	.update_interval = 0,
	.close = &json_output_file_close,
	.success_ip = &json_output_file_ip,
	.other_ip = &json_output_file_ip
};

