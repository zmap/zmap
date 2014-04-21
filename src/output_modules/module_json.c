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

#include "../../lib/includes.h"
#include "../../lib/xalloc.h"

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
#define MAC_ADDR_LEN 6

int json_output_file_init(struct state_conf *conf, UNUSED char **fields, UNUSED int fieldlens)
{
	int i;
	char mac_buf[ (MAC_ADDR_LEN * 2) + (MAC_ADDR_LEN - 1) + 1 ];
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
		json_object_object_add(obj, "target_port",
				json_object_new_int(conf->target_port));
		json_object_object_add(obj, "source_port_first",
				json_object_new_int(conf->source_port_first));
		json_object_object_add(obj, "source_port_last",
				json_object_new_int(conf->source_port_last));
		json_object_object_add(obj, "max_targets", json_object_new_int(conf->max_targets));
		json_object_object_add(obj, "max_runtime", json_object_new_int(conf->max_runtime));
		json_object_object_add(obj, "max_results", json_object_new_int(conf->max_results));
		if (conf->iface) {
			json_object_object_add(obj, "iface", json_object_new_string(conf->iface));
		}
		json_object_object_add(obj, "rate", json_object_new_int(conf->rate));

		json_object_object_add(obj, "bandwidth", json_object_new_int(conf->bandwidth));
		json_object_object_add(obj, "cooldown_secs", json_object_new_int(conf->cooldown_secs));
		json_object_object_add(obj, "senders", json_object_new_int(conf->senders));
		json_object_object_add(obj, "use_seed", json_object_new_int(conf->use_seed));
		json_object_object_add(obj, "seed", json_object_new_int(conf->seed));
		json_object_object_add(obj, "generator", json_object_new_int(conf->generator));
		json_object_object_add(obj, "packet_streams",
				json_object_new_int(conf->packet_streams));
		json_object_object_add(obj, "probe_module",
				json_object_new_string(((probe_module_t *)conf->probe_module)->name));
		json_object_object_add(obj, "output_module",
				json_object_new_string(((output_module_t *)conf->output_module)->name));
		
		if (conf->probe_args) {
			json_object_object_add(obj, "probe_args",
				json_object_new_string(conf->probe_args));
		}
		if (conf->output_args) {
			json_object_object_add(obj, "output_args",
				json_object_new_string(conf->output_args));
		}

		if (conf->gw_mac) {
			memset(mac_buf, 0, sizeof(mac_buf));
			p = mac_buf;
			for(i=0; i < MAC_ADDR_LEN; i++) {
				if (i == MAC_ADDR_LEN-1) {
					snprintf(p, 3, "%.2x", conf->gw_mac[i]);
					p += 2;
				} else {
					snprintf(p, 4, "%.2x:", conf->gw_mac[i]);
					p += 3;
				}
			}
			json_object_object_add(obj, "gw_mac", json_object_new_string(mac_buf));
		}

		json_object_object_add(obj, "source_ip_first",
				json_object_new_string(conf->source_ip_first));
		json_object_object_add(obj, "source_ip_last",
				json_object_new_string(conf->source_ip_last));
		json_object_object_add(obj, "output_filename",
				json_object_new_string(conf->output_filename));
		if (conf->blacklist_filename) json_object_object_add(obj,
				"blacklist_filename", 
				json_object_new_string(conf->blacklist_filename));
		if (conf->whitelist_filename) json_object_object_add(obj, "whitelist_filename", json_object_new_string(conf->whitelist_filename));
		json_object_object_add(obj, "dryrun", json_object_new_int(conf->dryrun));
		json_object_object_add(obj, "summary", json_object_new_int(conf->summary));
		json_object_object_add(obj, "quiet", json_object_new_int(conf->quiet));
		json_object_object_add(obj, "recv_ready", json_object_new_int(conf->recv_ready));

		fprintf(file, "%s\n", json_object_to_json_string(obj));
	}
	return EXIT_SUCCESS;
}

static void json_output_file_store_data(json_object *obj, const u_char *packet, size_t buflen) 
{
	unsigned int i;
	char *buf;

	buf = xmalloc((buflen*2)+1);
	buf[buflen*2] = 0;

	for (i=0; i<buflen; i++)
		snprintf(buf + (i*2), 3, "%.2x", packet[i]);
	json_object_object_add(obj, "data", json_object_new_string(buf));
	json_object_object_add(obj, "length", json_object_new_int(buflen));
	free(buf);
} 

int json_output_file_ip(fieldset_t *fs)
{
	if (!file) {
		return EXIT_SUCCESS;
	}
	json_object *obj = json_object_new_object();
	json_object_object_add(obj, "type", json_object_new_string("result"));
	for (int i=0; i < fs->len; i++) {
		field_t *f = &(fs->fields[i]);
		if (f->type == FS_STRING) {
			json_object_object_add(obj, f->name,
					json_object_new_string((char *) f->value.ptr));
		} else if (f->type == FS_UINT64) {
			json_object_object_add(obj, f->name,
					json_object_new_int((int) f->value.num));
		} else if (f->type == FS_BINARY) {
			json_output_file_store_data(obj,
					(const u_char*) f->value.ptr, f->len); 
		} else if (f->type == FS_NULL) {
			// do nothing
		} else {
			log_fatal("json", "received unknown output type");
		}
	}

	fprintf(file, "%s\n", json_object_to_json_string(obj));
	fflush(file);
	// free memory
	json_object_put(obj);
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
	.name = "json",
	.init = &json_output_file_init,
	.start = NULL,
	.update = NULL,
	.update_interval = 0,
	.close = &json_output_file_close,
	.process_ip = &json_output_file_ip,
	.helptext = NULL
};

