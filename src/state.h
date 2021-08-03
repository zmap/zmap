/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef STATE_H
#define STATE_H

#include <stdio.h>
#include <stdint.h>

#include "../lib/includes.h"

#ifdef PFRING
#include <pfring_zc.h>
#endif

#include "aesrand.h"
#include "fieldset.h"
#include "filter.h"
#include "types.h"

#define MAX_PACKET_SIZE 4096
#define MAC_ADDR_LEN_BYTES 6

struct probe_module;
struct output_module;

struct fieldset_conf {
	fielddefset_t defs;
	fielddefset_t outdefs;
	translation_t translation;
	int success_index;
	int app_success_index;
	int classification_index;
};

// global configuration
struct state_conf {
	int log_level;
	port_h_t target_port;
	port_h_t source_port_first;
	port_h_t source_port_last;
	// maximum number of packets that the scanner will send before
	// terminating
	uint32_t max_targets;
	// maximum number of seconds that scanner will run before terminating
	uint32_t max_runtime;
	// maximum number of results before terminating
	uint32_t max_results;
	// name of network interface that
	// will be utilized for sending/receiving
	char *iface;
	// rate in packets per second
	// that the sender will maintain
	int rate;
	// rate in bits per second
	uint64_t bandwidth;
	// how many seconds after the termination of the sender will the
	// receiver continue to process responses
	int cooldown_secs;
	// number of sending threads
	uint8_t senders;
	uint8_t batch;
	uint32_t pin_cores_len;
	uint32_t *pin_cores;
	// should use CLI provided randomization seed instead of generating
	// a random seed.
	int seed_provided;
	uint64_t seed;
	aesrand_t *aes;
	// generator of the cyclic multiplicative group that is utilized for
	// address generation
	uint32_t generator;
	// sharding options
	uint16_t shard_num;
	uint16_t total_shards;
	int packet_streams;
	struct probe_module *probe_module;
	char *output_module_name;
	struct output_module *output_module;
	char *probe_args;
	uint8_t probe_ttl;
	char *output_args;
	macaddr_t gw_mac[MAC_ADDR_LEN_BYTES];
	macaddr_t hw_mac[MAC_ADDR_LEN_BYTES];
	uint32_t gw_ip;
	int gw_mac_set;
	int hw_mac_set;
	in_addr_t source_ip_addresses[256];
	uint32_t number_source_ips;
	int send_ip_pkts;
	char *output_filename;
	char *blocklist_filename;
	char *allowlist_filename;
	char *list_of_ips_filename;
	uint32_t list_of_ips_count;
	char *metadata_filename;
	FILE *metadata_file;
	char *notes;
	char *custom_metadata_str;
	char **destination_cidrs;
	int destination_cidrs_len;
	const char *raw_output_fields;
	const char **output_fields;
	struct output_filter filter;
	char *output_filter_str;
	struct fieldset_conf fsconf;
	int output_fields_len;
	char *log_file;
	char *log_directory;
	char *status_updates_file;
	int dryrun;
	int quiet;
	int ignore_invalid_hosts;
	int syslog;
	int recv_ready;
	int num_retries;
	uint64_t total_allowed;
	uint64_t total_disallowed;
	int max_sendto_failures;
	float min_hitrate;
	int data_link_size;
	int default_mode;
	int no_header_row;
#ifdef PFRING
	struct {
		pfring_zc_cluster *cluster;
		pfring_zc_queue *send;
		pfring_zc_queue *recv;
		pfring_zc_queue **queues;
		pfring_zc_pkt_buff **buffers;
		pfring_zc_buffer_pool *prefetches;
	} pf;
#endif
};
extern struct state_conf zconf;

void init_empty_global_configuration(struct state_conf *c);

// global sender stats
struct state_send {
	double start;
	double finish;
	uint64_t packets_sent;
	uint64_t hosts_scanned;
	uint64_t blocklisted;
	uint64_t allowlisted;
	int warmup;
	int complete;
	uint32_t first_scanned;
	uint32_t max_targets;
	uint32_t sendto_failures;
	uint32_t max_index;
	uint8_t **list_of_ips_pbm;
};
extern struct state_send zsend;

// global receiver stats
struct state_recv {
	// valid responses classified as "success"
	uint32_t success_total;
	// unique IPs that sent valid responses classified as "success"
	uint32_t success_unique;
	// valid responses classified as "success"
	uint32_t app_success_total;
	// unique IPs that sent valid responses classified as "success"
	uint32_t app_success_unique;
	// valid responses classified as "success" received during cooldown
	uint32_t cooldown_total;
	// unique IPs that first sent valid "success"es during cooldown
	uint32_t cooldown_unique;
	// valid responses NOT classified as "success"
	uint32_t failure_total;
	// valid responses that passed the filter
	uint64_t filter_success;
	// how many packets did we receive that were marked as being the first
	// fragment in a stream
	uint32_t ip_fragments;
	// metrics about _only_ validate_packet
	uint32_t validation_passed;
	uint32_t validation_failed;

	int complete;  // has the scanner finished sending?
	double start;  // timestamp of when recv started
	double finish; // timestamp of when recv terminated

	// number of packets captured by pcap filter
	uint32_t pcap_recv;
	// number of packets dropped because there was no room in
	// the operating system's buffer when they arrived, because
	// packets weren't being read fast enough
	uint32_t pcap_drop;
	// number of packets dropped by the network interface or its driver.
	uint32_t pcap_ifdrop;
};
extern struct state_recv zrecv;

#endif // _STATE_H
