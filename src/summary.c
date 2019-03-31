/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include "summary.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <unistd.h>

#include "../lib/includes.h"
#include "../lib/logger.h"
#include "../lib/blacklist.h"

#include "state.h"
#include "probe_modules/probe_modules.h"
#include "output_modules/output_modules.h"

#define STRTIME_LEN 1024

#include <json.h>

void json_metadata(FILE *file)
{
	char send_start_time[STRTIME_LEN + 1];
	assert(dstrftime(send_start_time, STRTIME_LEN, "%Y-%m-%dT%H:%M:%S%z",
			 zsend.start));
	char send_end_time[STRTIME_LEN + 1];
	assert(dstrftime(send_end_time, STRTIME_LEN, "%Y-%m-%dT%H:%M:%S%z",
			 zsend.finish));
	char recv_start_time[STRTIME_LEN + 1];
	assert(dstrftime(recv_start_time, STRTIME_LEN, "%Y-%m-%dT%H:%M:%S%z",
			 zrecv.start));
	char recv_end_time[STRTIME_LEN + 1];
	assert(dstrftime(recv_end_time, STRTIME_LEN, "%Y-%m-%dT%H:%M:%S%z",
			 zrecv.finish));
	double hitrate =
	    ((double)100 * zrecv.success_unique) / ((double)zsend.sent);

	json_object *obj = json_object_new_object();

	// scanner host name
	char hostname[1024];
	if (gethostname(hostname, 1023) < 0) {
		log_error("json_metadata", "unable to retrieve local hostname");
	} else {
		hostname[1023] = '\0';
		json_object_object_add(obj, "local_hostname",
				       json_object_new_string(hostname));
		struct hostent *h = gethostbyname(hostname);
		if (h) {
			json_object_object_add(
			    obj, "full_hostname",
			    json_object_new_string(h->h_name));
		} else {
			log_error("json_metadata",
				  "unable to retrieve complete hostname");
		}
	}

	json_object_object_add(obj, "target_port",
			       json_object_new_int(zconf.target_port));
	json_object_object_add(obj, "source_port_first",
			       json_object_new_int(zconf.source_port_first));
	json_object_object_add(obj, "source_port_last",
			       json_object_new_int(zconf.source_port_last));
	json_object_object_add(obj, "max_targets",
			       json_object_new_int(zconf.max_targets));
	json_object_object_add(obj, "max_runtime",
			       json_object_new_int(zconf.max_runtime));
	json_object_object_add(obj, "max_results",
			       json_object_new_int(zconf.max_results));
	json_object_object_add(obj, "output_results",
			       json_object_new_int(zrecv.filter_success));
	if (zconf.iface) {
		json_object_object_add(obj, "iface",
				       json_object_new_string(zconf.iface));
	}
	json_object_object_add(obj, "rate", json_object_new_int(zconf.rate));
	json_object_object_add(obj, "bandwidth",
			       json_object_new_int(zconf.bandwidth));
	json_object_object_add(obj, "cooldown_secs",
			       json_object_new_int(zconf.cooldown_secs));
	json_object_object_add(obj, "senders",
			       json_object_new_int(zconf.senders));
	json_object_object_add(obj, "seed", json_object_new_int64(zconf.seed));
	json_object_object_add(obj, "seed_provided",
			       json_object_new_int64(zconf.seed_provided));
	json_object_object_add(obj, "generator",
			       json_object_new_int64(zconf.generator));
	json_object_object_add(obj, "hitrate", json_object_new_double(hitrate));
	json_object_object_add(obj, "shard_num",
			       json_object_new_int(zconf.shard_num));
	json_object_object_add(obj, "total_shards",
			       json_object_new_int(zconf.total_shards));

	json_object_object_add(obj, "min_hitrate",
			       json_object_new_double(zconf.min_hitrate));
	json_object_object_add(obj, "max_sendto_failures",
			       json_object_new_int(zconf.max_sendto_failures));

	json_object_object_add(obj, "syslog",
			       json_object_new_int(zconf.syslog));
	json_object_object_add(obj, "filter_duplicates",
			       json_object_new_int(zconf.filter_duplicates));
	json_object_object_add(obj, "filter_unsuccessful",
			       json_object_new_int(zconf.filter_unsuccessful));

	json_object_object_add(obj, "pcap_recv",
			       json_object_new_int(zrecv.pcap_recv));
	json_object_object_add(obj, "pcap_drop",
			       json_object_new_int(zrecv.pcap_drop));
	json_object_object_add(obj, "pcap_ifdrop",
			       json_object_new_int(zrecv.pcap_ifdrop));

	json_object_object_add(obj, "ip_fragments",
			       json_object_new_int(zrecv.ip_fragments));
	json_object_object_add(obj, "blacklist_total_allowed",
			       json_object_new_int64(zconf.total_allowed));
	json_object_object_add(obj, "blacklist_total_not_allowed",
			       json_object_new_int64(zconf.total_disallowed));
	json_object_object_add(obj, "validation_passed",
			       json_object_new_int(zrecv.validation_passed));
	json_object_object_add(obj, "validation_failed",
			       json_object_new_int(zrecv.validation_failed));

	//	json_object_object_add(obj, "blacklisted",
	//            json_object_new_int64(zsend.blacklisted));
	//	json_object_object_add(obj, "whitelisted",
	//            json_object_new_int64(zsend.whitelisted));
	json_object_object_add(obj, "first_scanned",
			       json_object_new_int64(zsend.first_scanned));
	json_object_object_add(obj, "send_to_failures",
			       json_object_new_int64(zsend.sendto_failures));
	json_object_object_add(obj, "total_sent",
			       json_object_new_int64(zsend.sent));
	json_object_object_add(obj, "success_total",
			       json_object_new_int64(zrecv.success_total));
	json_object_object_add(obj, "success_unique",
			       json_object_new_int64(zrecv.success_unique));
	if (zconf.fsconf.app_success_index >= 0) {
		json_object_object_add(
		    obj, "app_success_total",
		    json_object_new_int64(zrecv.app_success_total));
		json_object_object_add(
		    obj, "app_success_unique",
		    json_object_new_int64(zrecv.app_success_unique));
	}
	json_object_object_add(obj, "success_cooldown_total",
			       json_object_new_int64(zrecv.cooldown_total));
	json_object_object_add(obj, "success_cooldown_unique",
			       json_object_new_int64(zrecv.cooldown_unique));
	json_object_object_add(obj, "failure_total",
			       json_object_new_int64(zrecv.failure_total));

	json_object_object_add(obj, "packet_streams",
			       json_object_new_int(zconf.packet_streams));
	json_object_object_add(
	    obj, "probe_module",
	    json_object_new_string(
		((probe_module_t *)zconf.probe_module)->name));
	json_object_object_add(
	    obj, "output_module",
	    json_object_new_string(
		((output_module_t *)zconf.output_module)->name));

	json_object_object_add(obj, "send_start_time",
			       json_object_new_string(send_start_time));
	json_object_object_add(obj, "send_end_time",
			       json_object_new_string(send_end_time));
	json_object_object_add(obj, "recv_start_time",
			       json_object_new_string(recv_start_time));
	json_object_object_add(obj, "recv_end_time",
			       json_object_new_string(recv_end_time));

	if (zconf.output_filter_str) {
		json_object_object_add(
		    obj, "output_filter",
		    json_object_new_string(zconf.output_filter_str));
	}
	if (zconf.log_file) {
		json_object_object_add(obj, "log_file",
				       json_object_new_string(zconf.log_file));
	}
	if (zconf.log_directory) {
		json_object_object_add(
		    obj, "log_directory",
		    json_object_new_string(zconf.log_directory));
	}

	if (zconf.destination_cidrs_len) {
		json_object *cli_dest_cidrs = json_object_new_array();
		for (int i = 0; i < zconf.destination_cidrs_len; i++) {
			json_object_array_add(
			    cli_dest_cidrs,
			    json_object_new_string(zconf.destination_cidrs[i]));
		}
		json_object_object_add(obj, "cli_cidr_destinations",
				       cli_dest_cidrs);
	}
	if (zconf.probe_args) {
		json_object_object_add(
		    obj, "probe_args",
		    json_object_new_string(zconf.probe_args));
	}
	if (zconf.probe_ttl) {
		json_object_object_add(
		    obj, "probe_ttl",
		    json_object_new_int(zconf.probe_ttl));
	}
	if (zconf.output_args) {
		json_object_object_add(
		    obj, "output_args",
		    json_object_new_string(zconf.output_args));
	}
	{
		char mac_buf[(MAC_ADDR_LEN * 2) + (MAC_ADDR_LEN - 1) + 1];
		memset(mac_buf, 0, sizeof(mac_buf));
		char *p = mac_buf;
		for (int i = 0; i < MAC_ADDR_LEN; i++) {
			if (i == MAC_ADDR_LEN - 1) {
				snprintf(p, 3, "%.2x", zconf.gw_mac[i]);
				p += 2;
			} else {
				snprintf(p, 4, "%.2x:", zconf.gw_mac[i]);
				p += 3;
			}
		}
		json_object_object_add(obj, "gateway_mac",
				       json_object_new_string(mac_buf));
	}
	if (zconf.gw_ip) {
		struct in_addr addr;
		addr.s_addr = zconf.gw_ip;
		json_object_object_add(obj, "gateway_ip",
				       json_object_new_string(inet_ntoa(addr)));
	}
	{
		char mac_buf[(ETHER_ADDR_LEN * 2) + (ETHER_ADDR_LEN - 1) + 1];
		char *p = mac_buf;
		for (int i = 0; i < ETHER_ADDR_LEN; i++) {
			if (i == ETHER_ADDR_LEN - 1) {
				snprintf(p, 3, "%.2x", zconf.hw_mac[i]);
				p += 2;
			} else {
				snprintf(p, 4, "%.2x:", zconf.hw_mac[i]);
				p += 3;
			}
		}
		json_object_object_add(obj, "source_mac",
				       json_object_new_string(mac_buf));
	}
	json_object *source_ips = json_object_new_array();
	for (uint i = 0; i < zconf.number_source_ips; i++) {
		struct in_addr temp;
		temp.s_addr = zconf.source_ip_addresses[i];
		json_object_array_add(source_ips, json_object_new_string(
						      strdup(inet_ntoa(temp))));
	}
	json_object_object_add(obj, "source_ips", source_ips);
	if (zconf.output_filename) {
		json_object_object_add(
		    obj, "output_filename",
		    json_object_new_string(zconf.output_filename));
	}
	if (zconf.blacklist_filename) {
		json_object_object_add(
		    obj, "blacklist_filename",
		    json_object_new_string(zconf.blacklist_filename));
	}
	if (zconf.whitelist_filename) {
		json_object_object_add(
		    obj, "whitelist_filename",
		    json_object_new_string(zconf.whitelist_filename));
	}
	if (zconf.list_of_ips_filename) {
		json_object_object_add(
		    obj, "list_of_ips_filename",
		    json_object_new_string(zconf.list_of_ips_filename));
		json_object_object_add(
		    obj, "list_of_ips_count",
		    json_object_new_int(zconf.list_of_ips_count));
		json_object_object_add(obj, "list_of_ips_tried_sent",
				       json_object_new_int(zsend.tried_sent));
	}
	json_object_object_add(obj, "dryrun",
			       json_object_new_int(zconf.dryrun));
	json_object_object_add(obj, "quiet", json_object_new_int(zconf.quiet));
	json_object_object_add(obj, "log_level",
			       json_object_new_int(zconf.log_level));

	// parse out JSON metadata that was supplied on the command-line
	if (zconf.custom_metadata_str) {
		json_object *user =
		    json_tokener_parse(zconf.custom_metadata_str);
		if (!user) {
			log_error("json-metadata",
				  "unable to parse user metadata");
		} else {
			json_object_object_add(obj, "user-metadata", user);
		}
	}

	if (zconf.notes) {
		json_object_object_add(obj, "notes",
				       json_object_new_string(zconf.notes));
	}

	// add blacklisted and whitelisted CIDR blocks
	bl_cidr_node_t *b = get_blacklisted_cidrs();
	if (b) {
		json_object *blacklisted_cidrs = json_object_new_array();
		do {
			char cidr[50];
			struct in_addr addr;
			addr.s_addr = b->ip_address;
			sprintf(cidr, "%s/%i", inet_ntoa(addr), b->prefix_len);
			json_object_array_add(blacklisted_cidrs,
					      json_object_new_string(cidr));
		} while (b && (b = b->next));
		json_object_object_add(obj, "blacklisted_networks",
				       blacklisted_cidrs);
	}

	b = get_whitelisted_cidrs();
	if (b) {
		json_object *whitelisted_cidrs = json_object_new_array();
		do {
			char cidr[50];
			struct in_addr addr;
			addr.s_addr = b->ip_address;
			sprintf(cidr, "%s/%i", inet_ntoa(addr), b->prefix_len);
			json_object_array_add(whitelisted_cidrs,
					      json_object_new_string(cidr));
		} while (b && (b = b->next));
		json_object_object_add(obj, "whitelisted_networks",
				       whitelisted_cidrs);
	}

	fprintf(file, "%s\n", json_object_to_json_string(obj));
	json_object_put(obj);
}
