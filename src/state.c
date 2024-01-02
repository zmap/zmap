/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include "state.h"
#include "../lib/logger.h"

const char *const DEDUP_METHOD_NAMES[] = {"default", "none", "full", "window"};

// global configuration and defaults
struct state_conf zconf = {
    .allowlist_filename = NULL,
    .bandwidth = 0,
    .batch = 64,
    .blocklist_filename = NULL,
    .cooldown_secs = 0,
    .custom_metadata_str = NULL,
    .data_link_size = 0,
    .default_mode = 0,
    .dedup_method = 0,
    .dedup_window_size = 0,
    .dryrun = 0,
    .hw_mac = {0},
    .hw_mac_set = 0,
    .gw_ip = 0,
    .gw_mac = {0},
    .gw_mac_set = 0,
    .iface = NULL,
    .list_of_ips_count = 0,
    .list_of_ips_filename = NULL,
    .log_directory = NULL,
    .log_file = NULL,
    .log_level = LOG_INFO,
    .max_results = 0,
    .max_runtime = 0,
    .max_sendto_failures = -1,
    .max_targets = UINT64_MAX,
    .metadata_file = NULL,
    .metadata_filename = NULL,
    .min_hitrate = 0.0,
    .no_header_row = 0,
    .notes = NULL,
    .number_source_ips = 0,
    .output_args = NULL,
    .output_fields = NULL,
    .output_fields_len = 0,
    .output_filename = NULL,
    .output_filter_str = NULL,
    .output_module = NULL,
    .packet_streams = 1,
    .ports = NULL,
    .probe_args = NULL,
    .probe_module = NULL,
    .probe_ttl = MAXTTL,
    .quiet = 0,
    .rate = -1,
    .raw_output_fields = NULL,
    .recv_ready = 0,
    .retries = 10,
    .seed = 0,
    .seed_provided = 0,
    .senders = 1,
    .send_ip_pkts = 0,
    .source_port_first = 32768, // (these are the default
    .source_port_last = 61000, //   ephemeral range on Linux),
    .status_updates_file = NULL,
    .syslog = 1};

void init_empty_global_configuration(struct state_conf *c)
{
	memset(c->source_ip_addresses, 0, sizeof(c->source_ip_addresses));
}

// global sender stats and defaults
struct state_send zsend = {
    .start = 0.0,
    .finish = 0.0,
    .packets_sent = 0,
    .targets_scanned = 0,
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
