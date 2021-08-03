/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include "state.h"
#include "../lib/logger.h"

// global configuration and defaults
struct state_conf zconf = {.log_level = LOG_INFO,
			   .source_port_first = 32768, // (these are the default
			   .source_port_last = 61000, //   ephemeral range on Linux)
			   .output_filename = NULL,
			   .blocklist_filename = NULL,
			   .allowlist_filename = NULL,
			   .list_of_ips_filename = NULL,
			   .list_of_ips_count = 0,
			   .target_port = 0,
			   .max_targets = 0xFFFFFFFF,
			   .max_runtime = 0,
			   .max_results = 0,
			   .iface = NULL,
			   .rate = -1,
			   .bandwidth = 0,
			   .cooldown_secs = 0,
			   .senders = 1,
			   .batch = 1,
			   .packet_streams = 1,
			   .seed_provided = 0,
			   .seed = 0,
			   .output_module = NULL,
			   .output_args = NULL,
			   .probe_module = NULL,
			   .probe_args = NULL,
			   .probe_ttl = MAXTTL,
			   .gw_mac = {0},
			   .gw_ip = 0,
			   .hw_mac = {0},
			   .gw_mac_set = 0,
			   .hw_mac_set = 0,
			   .number_source_ips = 0,
			   .send_ip_pkts = 0,
			   .raw_output_fields = NULL,
			   .output_fields = NULL,
			   .output_filter_str = NULL,
			   .output_fields_len = 0,
			   .log_file = NULL,
			   .log_directory = NULL,
			   .status_updates_file = NULL,
			   .dryrun = 0,
			   .quiet = 0,
			   .syslog = 1,
			   .max_sendto_failures = -1,
			   .min_hitrate = 0.0,
			   .metadata_file = NULL,
			   .metadata_filename = NULL,
			   .notes = NULL,
			   .custom_metadata_str = NULL,
			   .recv_ready = 0,
			   .data_link_size = 0,
			   .default_mode = 0,
			   .no_header_row = 0,
};

void init_empty_global_configuration(struct state_conf *c) {
	memset(c->source_ip_addresses, 0, sizeof(c->source_ip_addresses));
}

// global sender stats and defaults
struct state_send zsend = {
    .start = 0.0,
    .finish = 0.0,
    .packets_sent = 0,
    .hosts_scanned = 0,
    .blocklisted = 0,
    .allowlisted = 0,
    .warmup = 1,
    .complete = 0,
    .sendto_failures = 0,
    .max_targets = 0,
    .list_of_ips_pbm = NULL,
};

// global receiver stats and defaults
struct state_recv zrecv = {
    .success_unique = 0,
    .success_total = 0,
    .app_success_unique = 0,
    .app_success_total = 0,
    .validation_passed = 0,
    .validation_failed = 0,
    .cooldown_unique = 0,
    .cooldown_total = 0,
    .failure_total = 0,
    .filter_success = 0,
    .ip_fragments = 0,
    .complete = 0,
    .pcap_recv = 0,
    .pcap_drop = 0,
    .pcap_ifdrop = 0,
};
