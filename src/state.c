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
struct state_conf zconf = {
	.log_level = LOG_INFO,
	.source_port_first = 32768, // (these are the default
	.source_port_last = 61000,	//	 ephemeral range on Linux)
	.output_filename = NULL,
	.blacklist_filename = NULL,
	.whitelist_filename = NULL,
	.target_port = 0,
	.max_targets = 0xFFFFFFFF,
	.max_runtime = 0,
	.max_results = 0,
	.iface = NULL,
	.rate = 0,
	.bandwidth = 0,
	.cooldown_secs = 0,
	.senders = 1,
	.packet_streams = 1,
	.use_seed = 0,
	.seed = 0,
	.output_module = NULL,
	.output_args = NULL,
	.probe_module = NULL,
	.probe_args = NULL,
	.gw_mac = {0},
	.gw_ip = 0,
	.hw_mac = {0},
	.gw_mac_set = 0,
	.send_ip_pkts = 0,
	.source_ip_first = NULL,
	.source_ip_last = NULL,
	.raw_output_fields = NULL,
	.output_fields = NULL,
	.output_filter_str = NULL,
	.output_fields_len = 0,
	.log_file = NULL,
	.log_directory = NULL,
	.dryrun = 0,
	.quiet = 0,
	.summary = 0,
	.syslog = 1,
	.filter_duplicates = 0,
	.filter_unsuccessful = 0,
	.recv_ready = 0,
	.metadata_file = NULL,
	.metadata_filename = NULL
};

// global sender stats and defaults
struct state_send zsend = {
	.start = 0.0,
	.finish = 0.0,
	.sent = 0,
	.blacklisted = 0,
	.complete = 0,
	.sendto_failures = 0,
	.targets = 0,
};

// global receiver stats and defaults
struct state_recv zrecv = {
	.success_unique = 0,
	.success_total = 0,
	.app_success_unique = 0,
	.app_success_total = 0,
	.cooldown_unique = 0,
	.cooldown_total = 0,
	.failure_total = 0,
	.complete = 0,
	.pcap_recv = 0,
	.pcap_drop = 0,
	.pcap_ifdrop = 0,
};

