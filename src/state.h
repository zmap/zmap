/*
 * ZMap Copyright 2013 Regents of the University of Michigan 
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include <stdio.h>
#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <net/if.h>

#ifndef _STATE_H
#define _STATE_H

#define MAX_PACKET_SIZE 4096

typedef uint32_t ipaddr_n_t; // IPv4 address network order
typedef uint32_t ipaddr_h_t; // IPv4 address host order
typedef uint16_t port_n_t; // port network order
typedef uint16_t port_h_t; // port host order
typedef unsigned char macaddr_t;

struct probe_module;
struct output_module;

// global configuration
struct state_conf {
	int log_level;
	port_h_t target_port;
	port_h_t source_port_first;
	port_h_t source_port_last;
	// maximum number of packets that the scanner will send before terminating
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
	// how many seconds after the termination of the sender will the receiver
	// continue to process responses
	int cooldown_secs;
	// number of sending threads
	int senders;
	// should use CLI provided randomization seed instead of generating
	// a random seed.
	int use_seed;
	uint32_t seed;
	// generator of the cyclic multiplicative group that is utilized for
	// address generation
	uint32_t generator;
	int packet_streams;
	struct probe_module *probe_module;
	struct output_module *output_module;
	char *probe_args;
	char *output_args;
	macaddr_t gw_mac[IFHWADDRLEN];
  	int gw_mac_set;
	char *source_ip_first;
	char *source_ip_last;
	char *output_filename;
	char *blacklist_filename;
	char *whitelist_filename;
	int dryrun;
	int summary;
	int quiet;
	int recv_ready;

	//CIDR to scan
	char *cidr;
};
extern struct state_conf zconf;

// global sender stats
struct state_send {
	double start;
	double finish;
	uint32_t sent;
	uint32_t blacklisted;
	int complete;
	uint32_t first_scanned;
	uint32_t last_to_scan;
	uint32_t targets;
	uint32_t sendto_failures;
};
extern struct state_send zsend;

// global receiver stats
struct state_recv {
	// valid responses classified as "success"
	uint32_t success_total;   
	// unique IPs that sent valid responses classified as "success"
	uint32_t success_unique;  
	// valid responses classified as "success" received during cooldown
	uint32_t cooldown_total;  
	// unique IPs that first sent valid "success"es during cooldown
	uint32_t cooldown_unique;
	// valid responses NOT classified as "success"
	uint32_t failure_total;   

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

