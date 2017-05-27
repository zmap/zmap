/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <sched.h>
#include <errno.h>
#include <pwd.h>
#include <time.h>

#include <pcap/pcap.h>
#include <json.h>

#include <pthread.h>

#include "../lib/includes.h"
#include "../lib/blacklist.h"
#include "../lib/logger.h"
#include "../lib/random.h"
#include "../lib/util.h"
#include "../lib/xalloc.h"
#include "../lib/pbm.h"

#include "aesrand.h"
#include "zopt.h"
#include "send.h"
#include "recv.h"
#include "state.h"
#include "monitor.h"
#include "get_gateway.h"
#include "filter.h"
#include "summary.h"

#include "output_modules/output_modules.h"
#include "probe_modules/probe_modules.h"

#ifdef PFRING
#include <pfring_zc.h>
static int32_t distrib_func(pfring_zc_pkt_buff *pkt, pfring_zc_queue *in_queue, void *arg) {
	(void) pkt;
	(void) in_queue;
	(void) arg;
	return 0;
}
#endif

pthread_mutex_t recv_ready_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct send_arg {
	uint32_t cpu;
	sock_t sock;
	shard_t *shard;
} send_arg_t;

typedef struct recv_arg {
	uint32_t cpu;
} recv_arg_t;

typedef struct mon_start_arg {
	uint32_t cpu;
	iterator_t *it;
	pthread_mutex_t *recv_ready_mutex;
} mon_start_arg_t;

const char *default_help_text = "By default, ZMap prints out unique, successful"
	"IP addresses (e.g., SYN-ACK from a TCP SYN scan) "
	"in ASCII form (e.g., 192.168.1.5) to stdout or the specified output "
	"file. Internally this is handled by the \"csv\" output module and is "
	"equivalent to running zmap --output-module=csv --output-fields=saddr "
	"--output-filter=\"success = 1 && repeat = 0\".";

static void* start_send(void *arg)
{
	send_arg_t *s = (send_arg_t *) arg;
	log_debug("zmap", "Pinning a send thread to core %u", s->cpu);
	set_cpu(s->cpu);
	send_run(s->sock, s->shard);
	free(s);
	return NULL;
}

static void* start_recv(void *arg)
{
	recv_arg_t *r = (recv_arg_t *) arg;
	log_debug("zmap", "Pinning receive thread to core %u", r->cpu);
	set_cpu(r->cpu);
	recv_run(&recv_ready_mutex);
	return NULL;
}

static void *start_mon(void *arg)
{
	mon_start_arg_t *mon_arg = (mon_start_arg_t *) arg;
	log_debug("zmap", "Pinning monitor thread to core %u", mon_arg->cpu);
	set_cpu(mon_arg->cpu);
	monitor_run(mon_arg->it, mon_arg->recv_ready_mutex);
	free(mon_arg);
	return NULL;
}

static void start_zmap(void)
{
	if (zconf.iface == NULL) {
		zconf.iface = get_default_iface();
		assert(zconf.iface);
		log_debug("zmap", "no interface provided. will use default"
				" interface (%s).", zconf.iface);
	}
	if (zconf.source_ip_first == NULL) {
		struct in_addr default_ip;
		zconf.source_ip_first = xmalloc(INET_ADDRSTRLEN);
		zconf.source_ip_last = zconf.source_ip_first;
		if (get_iface_ip(zconf.iface, &default_ip) < 0) {
			log_fatal("zmap", "could not detect default IP address for %s."
					" Try specifying a source address (-S).", zconf.iface);
		}
		inet_ntop(AF_INET, &default_ip, zconf.source_ip_first, INET_ADDRSTRLEN);
		log_debug("zmap", "no source IP address given. will use default address: %s.",
				zconf.source_ip_first);
	}
	if (!zconf.gw_mac_set) {
		struct in_addr gw_ip;
		memset(&gw_ip, 0, sizeof(struct in_addr));
		if (get_default_gw(&gw_ip, zconf.iface) < 0) {
			log_fatal("zmap", "could not detect default gateway address for %s."
					" Try setting default gateway mac address (-G).",
					zconf.iface);
		}
		log_debug("zmap", "found gateway IP %s on %s", inet_ntoa(gw_ip), zconf.iface);
		zconf.gw_ip = gw_ip.s_addr;
		memset(&zconf.gw_mac, 0, MAC_ADDR_LEN);
		if (get_hw_addr(&gw_ip, zconf.iface, zconf.gw_mac)) {
			log_fatal("zmap", "could not detect GW MAC address for %s on %s."
					" Try setting default gateway mac address (-G), or run"
					" \"arp <gateway_ip>\" in terminal.",
					inet_ntoa(gw_ip), zconf.iface);
		}
		zconf.gw_mac_set = 1;
	}
	log_debug("send", "gateway MAC address %02x:%02x:%02x:%02x:%02x:%02x",
		  zconf.gw_mac[0], zconf.gw_mac[1], zconf.gw_mac[2],
		  zconf.gw_mac[3], zconf.gw_mac[4], zconf.gw_mac[5]);
	// Initialization
	log_info("zmap", "output module: %s", zconf.output_module->name);
	if (zconf.output_module && zconf.output_module->init) {
		if (zconf.output_module->init(&zconf, zconf.output_fields,
				zconf.output_fields_len)) {
			log_fatal("zmap", "output module did not initialize successfully.");
		}
	}

	iterator_t *it = send_init();
	if (!it) {
		log_fatal("zmap", "unable to initialize sending component");
	}
	if (zconf.output_module && zconf.output_module->start) {
		zconf.output_module->start(&zconf, &zsend, &zrecv);
	}

	// start threads
	uint32_t cpu = 0;
	pthread_t *tsend, trecv, tmon;
	int r;
	if (!zconf.dryrun) {
		recv_arg_t *recv_arg = xmalloc(sizeof(recv_arg_t));
		recv_arg->cpu = zconf.pin_cores[cpu % zconf.pin_cores_len];
		cpu += 1;
		r = pthread_create(&trecv, NULL, start_recv, recv_arg);
		if (r != 0) {
			log_fatal("zmap", "unable to create recv thread");
		}
		for (;;) {
			pthread_mutex_lock(&recv_ready_mutex);
			if (zconf.recv_ready) {
				pthread_mutex_unlock(&recv_ready_mutex);
				break;
			}
			pthread_mutex_unlock(&recv_ready_mutex);
		}
	}
#ifdef PFRING
	pfring_zc_worker *zw = pfring_zc_run_balancer(zconf.pf.queues,
		&zconf.pf.send,
		zconf.senders,
		1,
		zconf.pf.prefetches,
		round_robin_bursts_policy,
		NULL,
		distrib_func,
		NULL,
		0,
		zconf.pin_cores[cpu & zconf.pin_cores_len]);
	cpu += 1;
#endif
	tsend = xmalloc(zconf.senders * sizeof(pthread_t));
	for (uint8_t i = 0; i < zconf.senders; i++) {
		sock_t sock;
		if (zconf.dryrun) {
			sock = get_dryrun_socket();
		} else {
			sock = get_socket(i);
		}
		send_arg_t *arg = xmalloc(sizeof(send_arg_t));

		arg->sock = sock;
		arg->shard = get_shard(it, i);
		arg->cpu = zconf.pin_cores[cpu % zconf.pin_cores_len];
		cpu += 1;
		int r = pthread_create(&tsend[i], NULL, start_send, arg);
		if (r != 0) {
			log_fatal("zmap", "unable to create send thread");
			exit(EXIT_FAILURE);
		}
	}
	log_debug("zmap", "%d sender threads spawned", zconf.senders);

	if (!zconf.dryrun) {
		monitor_init();
		mon_start_arg_t *mon_arg = xmalloc(sizeof(mon_start_arg_t));
		mon_arg->it = it;
		mon_arg->recv_ready_mutex = &recv_ready_mutex;
		mon_arg->cpu = zconf.pin_cores[cpu % zconf.pin_cores_len];
		int r = pthread_create(&tmon, NULL, start_mon, mon_arg);
		if (r != 0) {
			log_fatal("zmap", "unable to create monitor thread");
			exit(EXIT_FAILURE);
		}
	}

#ifndef PFRING
	drop_privs();
#endif

	// wait for completion
	for (uint8_t i = 0; i < zconf.senders; i++) {
		int r = pthread_join(tsend[i], NULL);
		if (r != 0) {
			log_fatal("zmap", "unable to join send thread");
			exit(EXIT_FAILURE);
		}
	}
	log_debug("zmap", "senders finished");
#ifdef PFRING
	pfring_zc_kill_worker(zw);
	pfring_zc_sync_queue(zconf.pf.send, tx_only);
	log_debug("zmap", "send queue flushed");
#endif
	// no receiving or monitoring thread is started in dry run mode
	if (!zconf.dryrun) {
		r = pthread_join(trecv, NULL);
		if (r != 0) {
			log_fatal("zmap", "unable to join recv thread");
			exit(EXIT_FAILURE);
		}
		if (!zconf.quiet || zconf.status_updates_file) {
			pthread_join(tmon, NULL);
			if (r != 0) {
				log_fatal("zmap", "unable to join monitor thread");
				exit(EXIT_FAILURE);
			}
		}
	}

	// finished
	if (zconf.metadata_filename) {
		json_metadata(zconf.metadata_file);
	}
	if (zconf.output_module && zconf.output_module->close) {
		zconf.output_module->close(&zconf, &zsend, &zrecv);
	}
	if (zconf.probe_module && zconf.probe_module->close) {
		zconf.probe_module->close(&zconf, &zsend, &zrecv);
	}
#ifdef PFRING
	pfring_zc_destroy_cluster(zconf.pf.cluster);
#endif
	log_info("zmap", "completed");
}

#define SET_IF_GIVEN(DST,ARG) \
	{ if (args.ARG##_given) { (DST) = args.ARG##_arg; }; }
#define SET_BOOL(DST,ARG) \
	{ if (args.ARG##_given) { (DST) = 1; }; }

int main(int argc, char *argv[])
{
	struct gengetopt_args_info args;
	struct cmdline_parser_params *params;
	params = cmdline_parser_params_create();
	params->initialize = 1;
	params->override = 0;
	params->check_required = 0;

	int config_loaded = 0;

	if (cmdline_parser_ext(argc, argv, &args, params) != 0) {
		exit(EXIT_SUCCESS);
	}
	if (args.config_given || file_exists(args.config_arg)) {
		params->initialize = 0;
		params->override = 0;
		if (cmdline_parser_config_file(args.config_arg, &args, params)
				!= 0) {
			exit(EXIT_FAILURE);
		}
		config_loaded = 1;
	}

	// initialize logging. if no log file or log directory are specified
	// default to using stderr.
	zconf.log_level = args.verbosity_arg;
	zconf.log_file = args.log_file_arg;
	zconf.log_directory = args.log_directory_arg;
	if (args.disable_syslog_given) {
		zconf.syslog = 0;
	} else {
		zconf.syslog = 1;
	}
	if (zconf.log_file && zconf.log_directory) {
		log_init(stderr, zconf.log_level, zconf.syslog, "zmap");
		log_fatal("zmap", "log-file and log-directory cannot "
				"specified simultaneously.");
	}
	FILE *log_location = NULL;
	if (zconf.log_file) {
		log_location = fopen(zconf.log_file, "w");
	} else if (zconf.log_directory) {
		time_t now;
		time(&now);
		struct tm *local = localtime(&now);
		char path[100];
		strftime(path, 100, "zmap-%Y-%m-%dT%H%M%S%z.log", local);
		char *fullpath = xmalloc(strlen(zconf.log_directory) + strlen(path) + 2);
		sprintf(fullpath, "%s/%s", zconf.log_directory, path);
		log_location = fopen(fullpath, "w");
		free(fullpath);

	} else {
		log_location = stderr;
	}
	if (!log_location) {
		log_init(stderr, zconf.log_level, zconf.syslog, "zmap");
		log_fatal("zmap", "unable to open specified log file: %s",
				strerror(errno));
	}
	log_init(log_location, zconf.log_level, zconf.syslog, "zmap");
	log_debug("zmap", "zmap main thread started");
	if (config_loaded) {
		log_debug("zmap", "Loaded configuration file %s",
				args.config_arg);
	}
	if (zconf.syslog) {
		log_debug("zmap", "syslog support enabled");
	} else {
		log_info("zmap", "syslog support disabled");
	}
	// parse the provided probe and output module s.t. that we can support
	// other command-line helpers (e.g. probe help)
	log_debug("zmap", "requested ouput-module: %s", args.output_module_arg);

	// zmap's default behavior is to provide a simple file of the unique IP
	// addresses that responded successfully.
	if (!strcmp(args.output_module_arg, "default")) {
		log_debug("zmap", "no output module provided. will use csv.");
		zconf.output_module = get_output_module_by_name("csv");
	} else {
		zconf.output_module = get_output_module_by_name(args.output_module_arg);
		if (!zconf.output_module) {
		  log_fatal("zmap", "specified output module (%s) does not exist\n",
				args.output_module_arg);
		}
	}
	zconf.probe_module = get_probe_module_by_name(args.probe_module_arg);
	if (!zconf.probe_module) {
		log_fatal("zmap", "specified probe module (%s) does not exist\n",
				args.probe_module_arg);
	  exit(EXIT_FAILURE);
	}
	// check whether the probe module is going to generate dynamic data
	// and that the output module can support exporting that data out of
	// zmap. If they can't, then quit.
	if (zconf.probe_module->output_type == OUTPUT_TYPE_DYNAMIC
			&& !zconf.output_module->supports_dynamic_output) {
		log_fatal("zmap", "specified probe module (%s) requires dynamic "
				"output support, which output module (%s) does not support. "
				"Most likely you want to use JSON output.",
				args.probe_module_arg,
				args.output_module_arg);
	}
	if (args.help_given) {
		cmdline_parser_print_help();
		printf("\nProbe-module (%s) Help:\n", zconf.probe_module->name);
		if (zconf.probe_module->helptext) {
			fprintw(stdout, (char*) zconf.probe_module->helptext, 80);
		} else {
			printf("no help text available\n");
		}
		printf("\nOutput-module (%s) Help:\n", zconf.output_module->name);

	   	if (!strcmp(args.output_module_arg, "default")) {
			fprintw(stdout, (char*) default_help_text, 80);
		} else if (zconf.output_module->helptext) {
			fprintw(stdout, (char*) zconf.output_module->helptext, 80);
		} else {
			printf("no help text available\n");
		}
		exit(EXIT_SUCCESS);
	}
	if (args.version_given) {
		cmdline_parser_print_version();
		exit(EXIT_SUCCESS);
	}
	if (args.list_output_modules_given) {
		print_output_modules();
		exit(EXIT_SUCCESS);
	}
	if (args.list_probe_modules_given) {
		print_probe_modules();
		exit(EXIT_SUCCESS);
	}
	if (args.vpn_given) {
		zconf.send_ip_pkts = 1;
		zconf.gw_mac_set = 1;
		memset(zconf.gw_mac, 0, MAC_ADDR_LEN);
	}
	if (cmdline_parser_required(&args, CMDLINE_PARSER_PACKAGE) != 0) {
		exit(EXIT_FAILURE);
	}
	// now that we know the probe module, let's find what it supports
	memset(&zconf.fsconf, 0, sizeof(struct fieldset_conf));
	// the set of fields made available to a user is constructed
	// of IP header fields + probe module fields + system fields
	fielddefset_t *fds = &(zconf.fsconf.defs);
	gen_fielddef_set(fds, (fielddef_t*) &(ip_fields), ip_fields_len);
	gen_fielddef_set(fds, zconf.probe_module->fields,
			zconf.probe_module->numfields);
	gen_fielddef_set(fds, (fielddef_t*) &(sys_fields), sys_fields_len);
	if (args.list_output_fields_given) {
		for (int i = 0; i < fds->len; i++) {
			printf("%-15s %6s: %s\n", fds->fielddefs[i].name,
				fds->fielddefs[i].type,
				fds->fielddefs[i].desc);
		}
		exit(EXIT_SUCCESS);
	}
	// find the fields we need for the framework
	zconf.fsconf.success_index =
			fds_get_index_by_name(fds, (char*) "success");
	if (zconf.fsconf.success_index < 0) {
		log_fatal("fieldset", "probe module does not supply "
					  "required success field.");
	}
	zconf.fsconf.app_success_index =
			fds_get_index_by_name(fds, (char*) "app_success");
	if (zconf.fsconf.app_success_index < 0) {
		log_debug("fieldset", "probe module does not supply "
					  "application success field.");
	} else {
		log_debug("fieldset", "probe module supplies app_success"
				" output field. It will be included in monitor output");
	}
	zconf.fsconf.classification_index =
			fds_get_index_by_name(fds, (char*) "classification");
	if (zconf.fsconf.classification_index < 0) {
		log_fatal("fieldset", "probe module does not supply "
					  "required packet classification field.");
	}
	// process the list of requested output fields.
	if (args.output_fields_given) {
		zconf.raw_output_fields = args.output_fields_arg;
	} else if (!zconf.raw_output_fields) {
		zconf.raw_output_fields = (char*) "saddr";
	}
	if (!strcmp(zconf.raw_output_fields, "*")) {
		zconf.output_fields_len = zconf.fsconf.defs.len;
		zconf.output_fields = xcalloc(zconf.fsconf.defs.len, sizeof(char*));
		for (int i=0; i < zconf.fsconf.defs.len; i++) {
			zconf.output_fields[i] = (char*) zconf.fsconf.defs.fielddefs[i].name;
		}
		fs_generate_full_fieldset_translation(&zconf.fsconf.translation,
				&zconf.fsconf.defs);
	} else {
		split_string(zconf.raw_output_fields, &(zconf.output_fields_len),
				&(zconf.output_fields));
		for (int i=0; i < zconf.output_fields_len; i++) {
			log_debug("zmap", "requested output field (%i): %s", i,
					zconf.output_fields[i]);
		}
		// generate a translation that can be used to convert output
		// from a probe module to the input for an output module
		fs_generate_fieldset_translation(&zconf.fsconf.translation,
				&zconf.fsconf.defs, zconf.output_fields,
				zconf.output_fields_len);
	}
	// default filtering behavior is to drop unsuccessful and duplicates
	if (!args.output_filter_arg || !strcmp(args.output_filter_arg, "default")) {
		zconf.filter_duplicates = 1;
		zconf.filter_unsuccessful = 1;
		log_debug("filter", "no output filter specified. will use default: exclude duplicates and unssuccessful");
	} else if (args.output_filter_arg && !strcmp(args.output_filter_arg, "")) {
		zconf.filter_duplicates = 0;
		zconf.filter_unsuccessful = 0;
		log_debug("filter", "empty output filter. will not exclude any values");
	} else {
		// Run it through yyparse to build the expression tree
		if (!parse_filter_string(args.output_filter_arg)) {
			log_fatal("zmap", "Unable to parse filter expression");
		}
		// Check the fields used against the fieldset in use
		if (!validate_filter(zconf.filter.expression, &zconf.fsconf.defs)) {
			log_fatal("zmap", "Invalid filter");
		}
		zconf.output_filter_str = args.output_filter_arg;
		log_debug("filter", "will use output filter %s", args.output_filter_arg);
	}

	SET_BOOL(zconf.dryrun, dryrun);
	SET_BOOL(zconf.quiet, quiet);
	SET_BOOL(zconf.ignore_invalid_hosts, ignore_invalid_hosts);
	zconf.cooldown_secs = args.cooldown_time_arg;
	SET_IF_GIVEN(zconf.output_filename, output_file);
	SET_IF_GIVEN(zconf.blacklist_filename, blacklist_file);
	SET_IF_GIVEN(zconf.list_of_ips_filename, list_of_ips_file);
	SET_IF_GIVEN(zconf.probe_args, probe_args);
	SET_IF_GIVEN(zconf.output_args, output_args);
	SET_IF_GIVEN(zconf.iface, interface);
	SET_IF_GIVEN(zconf.max_runtime, max_runtime);
	SET_IF_GIVEN(zconf.max_results, max_results);
	SET_IF_GIVEN(zconf.rate, rate);
	SET_IF_GIVEN(zconf.packet_streams, probes);
	SET_IF_GIVEN(zconf.status_updates_file, status_updates_file);
	SET_IF_GIVEN(zconf.num_retries, retries);
	SET_IF_GIVEN(zconf.max_sendto_failures, max_sendto_failures);
	SET_IF_GIVEN(zconf.min_hitrate, min_hitrate);

	if (zconf.num_retries < 0) {
		log_fatal("zmap", "Invalid retry count");
	}

	if (zconf.max_sendto_failures >= 0) {
		log_debug("zmap", "scan will abort if more than %i "
				"sendto failures occur", zconf.max_sendto_failures);
	}
	if (zconf.min_hitrate > 0.0) {
		log_debug("zmap", "scan will abort if hitrate falls below %f",
				zconf.min_hitrate);
	}
	if (args.metadata_file_arg) {
		zconf.metadata_filename = args.metadata_file_arg;
		if (!strcmp(zconf.metadata_filename, "-")) {
			zconf.metadata_file = stdout;
		} else {
			zconf.metadata_file = fopen(zconf.metadata_filename, "w");
		}
		if (!zconf.metadata_file) {
			log_fatal("metadata", "unable to open metadata file (%s): %s",
					zconf.metadata_filename, strerror(errno));
		}
		log_debug("metadata", "metdata will be saved to %s",
				zconf.metadata_filename);
	}

	if (args.user_metadata_given) {
		zconf.custom_metadata_str = args.user_metadata_arg;
		if (!json_tokener_parse(zconf.custom_metadata_str)) {
			log_fatal("metadata", "unable to parse custom user metadata");
		} else {
			log_debug("metadata", "user metadata validated successfully");
		}
	}
	if (args.notes_given) {
		zconf.notes = args.notes_arg;
	}

	// find if zmap wants any specific cidrs scanned instead
	// of the entire Internet
	zconf.destination_cidrs = args.inputs;
	zconf.destination_cidrs_len = args.inputs_num;
	if (zconf.destination_cidrs && zconf.blacklist_filename
			&& !strcmp(zconf.blacklist_filename, "/etc/zmap/blacklist.conf")) {
		log_warn("blacklist", "ZMap is currently using the default blacklist located "
				"at /etc/zmap/blacklist.conf. By default, this blacklist excludes locally "
				"scoped networks (e.g. 10.0.0.0/8, 127.0.0.1/8, and 192.168.0.0/16). If you are"
				" trying to scan local networks, you can change the default blacklist by "
				"editing the default ZMap configuration at /etc/zmap/zmap.conf.");
	}
	SET_IF_GIVEN(zconf.whitelist_filename, whitelist_file);

	if (zconf.probe_module->port_args) {
		if (args.source_port_given) {
			char *dash = strchr(args.source_port_arg, '-');
			if (dash) { // range
				*dash = '\0';
				zconf.source_port_first = atoi(args.source_port_arg);
				enforce_range("starting source-port", zconf.source_port_first, 0, 0xFFFF);
				zconf.source_port_last = atoi(dash+1);
				enforce_range("ending source-port", zconf.source_port_last, 0, 0xFFFF);
				if (zconf.source_port_first > zconf.source_port_last) {
					fprintf(stderr, "%s: invalid source port range: "
						"last port is less than first port\n",
						CMDLINE_PARSER_PACKAGE);
					exit(EXIT_FAILURE);
				}
			} else { // single port
				int port = atoi(args.source_port_arg);
				enforce_range("source-port", port, 0, 0xFFFF);
				zconf.source_port_first = port;
				zconf.source_port_last = port;
			}
		}
	  	if (!args.target_port_given) {
			log_fatal("zmap", "target port (-p) is required for this type of probe");
		}
		enforce_range("target-port", args.target_port_arg, 0, 0xFFFF);
		zconf.target_port = args.target_port_arg;
	}
	if (args.source_ip_given) {
		char *dash = strchr(args.source_ip_arg, '-');
		if (dash) { // range
			*dash = '\0';
			zconf.source_ip_first = args.source_ip_arg;
			zconf.source_ip_last = dash+1;
		} else { // single address
			zconf.source_ip_first = args.source_ip_arg;
			zconf.source_ip_last = args.source_ip_arg;
		}
	}
	if (args.gateway_mac_given) {
		if (!parse_mac(zconf.gw_mac, args.gateway_mac_arg)) {
			fprintf(stderr, "%s: invalid MAC address `%s'\n",
				CMDLINE_PARSER_PACKAGE, args.gateway_mac_arg);
			exit(EXIT_FAILURE);
		}
		zconf.gw_mac_set = 1;
	}
	if (args.source_mac_given) {
		if (!parse_mac(zconf.hw_mac, args.source_mac_arg)) {
			fprintf(stderr, "%s: invalid MAC address `%s'\n",
				CMDLINE_PARSER_PACKAGE, args.gateway_mac_arg);
			exit(EXIT_FAILURE);
		}
		log_debug("send", "source MAC address specified on CLI: "
				"%02x:%02x:%02x:%02x:%02x:%02x",
				zconf.hw_mac[0], zconf.hw_mac[1], zconf.hw_mac[2],
				zconf.hw_mac[3], zconf.hw_mac[4], zconf.hw_mac[5]);

		zconf.hw_mac_set = 1;
	}
	// Check for a random seed
	if (args.seed_given) {
		zconf.seed = args.seed_arg;
		zconf.seed_provided = 1;
	} else {
		// generate a seed randomly
		if (!random_bytes(&zconf.seed, sizeof(uint64_t))) {
			log_fatal("zmap", "unable to generate random bytes "
 					"needed for seed");
		}
		zconf.seed_provided = 0;
	}
	zconf.aes = aesrand_init_from_seed(zconf.seed);

	// Set up sharding
	zconf.shard_num = 0;
	zconf.total_shards = 1;
	if ((args.shard_given || args.shards_given) && !args.seed_given) {
		log_fatal("zmap", "Need to specify seed if sharding a scan");
	}
	if (args.shard_given ^ args.shards_given) {
		log_fatal("zmap",
			  "Need to specify both shard number and total number of shards");
	}
	if (args.shard_given) {
		enforce_range("shard", args.shard_arg, 0, 254);
	}
	if (args.shards_given) {
		enforce_range("shards", args.shards_arg, 1, 254);
	}
	SET_IF_GIVEN(zconf.shard_num, shard);
	SET_IF_GIVEN(zconf.total_shards, shards);
	if (zconf.shard_num >= zconf.total_shards) {
		log_fatal("zmap", "With %hhu total shards, shard number (%hhu)"
			  " must be in range [0, %hhu)", zconf.total_shards,
			  zconf.shard_num, zconf.total_shards);
	}

	if (args.bandwidth_given) {
		// Supported: G,g=*1000000000; M,m=*1000000 K,k=*1000 bits per second
		zconf.bandwidth = atoi(args.bandwidth_arg);
		char *suffix = args.bandwidth_arg;
		while (*suffix >= '0' && *suffix <= '9') {
			suffix++;
		}
		if (*suffix) {
			switch (*suffix) {
			case 'G': case 'g':
				zconf.bandwidth *= 1000000000;
				break;
			case 'M': case 'm':
				zconf.bandwidth *= 1000000;
				break;
			case 'K': case 'k':
				zconf.bandwidth *= 1000;
				break;
			default:
			  	fprintf(stderr, "%s: unknown bandwidth suffix '%s' "
					"(supported suffixes are G, M and K)\n",
					CMDLINE_PARSER_PACKAGE, suffix);
				exit(EXIT_FAILURE);
			}
		}
	}
	if (args.max_targets_given) {
		zconf.max_targets = parse_max_hosts(args.max_targets_arg);
	}

	// blacklist
	if (blacklist_init(zconf.whitelist_filename, zconf.blacklist_filename,
			zconf.destination_cidrs, zconf.destination_cidrs_len,
			NULL, 0,
			zconf.ignore_invalid_hosts)) {
		log_fatal("zmap", "unable to initialize blacklist / whitelist");
	}
	// if there's a list of ips to scan, then initialize PBM and populate
	// it based on the provided file
	if (zconf.list_of_ips_filename) {
		zsend.list_of_ips_pbm = pbm_init();
		zconf.list_of_ips_count = pbm_load_from_file(zsend.list_of_ips_pbm,
				zconf.list_of_ips_filename);
	}

	// compute number of targets
	uint64_t allowed = blacklist_count_allowed();
	zconf.total_allowed = allowed;
	zconf.total_disallowed = blacklist_count_not_allowed();
	assert(allowed <= (1LL << 32));
	if (allowed == (1LL << 32)) {
		zsend.targets = 0xFFFFFFFF;
	} else {
		zsend.targets = allowed;
	}
	if (zsend.targets > zconf.max_targets) {
		zsend.targets = zconf.max_targets;
	}
	if (!zsend.targets) {
		log_fatal("zmap", "zero eligible addresses to scan");
	}

#ifndef PFRING
	// Set the correct number of threads, default to num_cores - 1
	if (args.sender_threads_given) {
		zconf.senders = args.sender_threads_arg;
	} else {
		zconf.senders = 1;
	}
	if (2*zconf.senders >= zsend.targets) {
		log_warn("zmap", "too few targets relative to senders, dropping to one sender");
		zconf.senders = 1;
	}
#else
	zconf.senders = args.sender_threads_arg;
#endif
	// Figure out what cores to bind to
	if (args.cores_given) {
		char **core_list = NULL;
		int len = 0;
		split_string(args.cores_arg, &len, &core_list);
		zconf.pin_cores_len = (uint32_t) len;
		zconf.pin_cores = xcalloc(zconf.pin_cores_len,
			sizeof(uint32_t));
		for (uint32_t i = 0; i < zconf.pin_cores_len; ++i) {
			zconf.pin_cores[i] = atoi(core_list[i]);
		}
	} else {
		int num_cores = sysconf(_SC_NPROCESSORS_ONLN);
		zconf.pin_cores_len = (uint32_t) num_cores;
		zconf.pin_cores = xcalloc(zconf.pin_cores_len,
			sizeof(uint32_t));
		for (uint32_t i = 0; i < zconf.pin_cores_len; ++i) {
			zconf.pin_cores[i] = i;
		}
	}

	// PFRING
#ifdef PFRING
#define MAX_CARD_SLOTS 32768
#define QUEUE_LEN 8192
#define ZMAP_PF_BUFFER_SIZE 1536
#define ZMAP_PF_ZC_CLUSTER_ID 9627
	uint32_t user_buffers = zconf.senders*256;
	uint32_t queue_buffers = zconf.senders*QUEUE_LEN;
	uint32_t card_buffers = 2*MAX_CARD_SLOTS;
	uint32_t total_buffers = user_buffers + queue_buffers + card_buffers + 2;
	uint32_t metadata_len = 0;
	uint32_t numa_node = 0; // TODO
	zconf.pf.cluster = pfring_zc_create_cluster(
			ZMAP_PF_ZC_CLUSTER_ID,
			ZMAP_PF_BUFFER_SIZE,
			metadata_len,
			total_buffers,
			numa_node,
			NULL);
	if (zconf.pf.cluster == NULL) {
		log_fatal("zmap", "Could not create zc cluster: %s", strerror(errno));
	}

	zconf.pf.buffers = xcalloc(user_buffers, sizeof(pfring_zc_pkt_buff *));
	for (uint32_t i = 0; i < user_buffers; ++i) {
		zconf.pf.buffers[i] = pfring_zc_get_packet_handle(zconf.pf.cluster);
		if (zconf.pf.buffers[i] == NULL) {
			log_fatal("zmap", "Could not get ZC packet handle");
		}
	}

	zconf.pf.send = pfring_zc_open_device(zconf.pf.cluster, zconf.iface,
			tx_only, 0);
	if (zconf.pf.send == NULL) {
		log_fatal("zmap", "Could not open device %s for TX. [%s]",
				zconf.iface, strerror(errno));
	}

	zconf.pf.recv = pfring_zc_open_device(zconf.pf.cluster, zconf.iface,
			rx_only, 0);
	if (zconf.pf.recv == NULL) {
		log_fatal("zmap", "Could not open device %s for RX. [%s]",
				zconf.iface, strerror(errno));
	}

	zconf.pf.queues = xcalloc(zconf.senders, sizeof(pfring_zc_queue *));
	for (uint32_t i = 0; i < zconf.senders; ++i) {
		zconf.pf.queues[i] = pfring_zc_create_queue(zconf.pf.cluster,
				QUEUE_LEN);
		if (zconf.pf.queues[i] == NULL) {
			log_fatal("zmap", "Could not create queue: %s",
					strerror(errno));
		}
	}

	zconf.pf.prefetches = pfring_zc_create_buffer_pool(zconf.pf.cluster, 8);
	if (zconf.pf.prefetches == NULL) {
		log_fatal("zmap", "Could not open prefetch pool: %s",
				strerror(errno));
	}
#endif

	// resume scan if requested

	start_zmap();

	fclose(log_location);

	cmdline_parser_free(&args);
	free(params);
	return EXIT_SUCCESS;
}
