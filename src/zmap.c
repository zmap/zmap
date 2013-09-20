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
#include <net/if.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>

#include <pcap/pcap.h>

#include <pthread.h>

#include "../lib/logger.h"
#include "../lib/random.h"

#include "zopt.h"
#include "send.h"
#include "recv.h"
#include "state.h"
#include "monitor.h"
#include "get_gateway.h"
#include "filter.h"

#include "output_modules/output_modules.h"
#include "probe_modules/probe_modules.h"

pthread_mutex_t cpu_affinity_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t recv_ready_mutex = PTHREAD_MUTEX_INITIALIZER;

// splits comma delimited string into char*[]. Does not handle
// escaping or complicated setups: designed to process a set
// of fields that the user wants output 
static void split_string(char* in, int *len, char***results)
{
        char** fields = calloc(MAX_FIELDS, sizeof(char*));
        memset(fields, 0, MAX_FIELDS*sizeof(fields));
        int retvlen = 0;
        char *currloc = in; 
        // parse csv into a set of strings
        while (1) {
                size_t len = strcspn(currloc, ", ");    
                if (len == 0) {
                        currloc++;
                } else {
                        char *new = malloc(len+1);
			assert(new);
                        strncpy(new, currloc, len);
                        new[len] = '\0';             
                        fields[retvlen++] = new;
			assert(fields[retvlen-1]);
                }   
		if (len == strlen(currloc)) {
			break;
		}
                currloc += len;
        }
        *results = fields;
        *len = retvlen;
}

static void set_cpu(void)
{
	pthread_mutex_lock(&cpu_affinity_mutex);
	static int core=0;
	int num_cores = sysconf(_SC_NPROCESSORS_ONLN);
	cpu_set_t cpuset;	
	CPU_ZERO(&cpuset);
	CPU_SET(core, &cpuset);
	if (pthread_setaffinity_np(pthread_self(),
				sizeof(cpu_set_t), &cpuset) != 0) {
		log_error("zmap", "can't set thread CPU affinity");
	}
	log_trace("zmap", "set thread %u affinity to core %d",
			pthread_self(), core);
	core = (core + 1) % num_cores;
	pthread_mutex_unlock(&cpu_affinity_mutex);
}	

static void* start_send(void *arg)
{
	uintptr_t v = (uintptr_t) arg;
	int sock = (int) v & 0xFFFF;
	set_cpu();
	send_run(sock);
	return NULL;
}

static void* start_recv(__attribute__((unused)) void *arg)
{
	set_cpu();
	recv_run(&recv_ready_mutex);
	return NULL;
}

static void drop_privs()
{
	struct passwd *pw;
	if ((pw = getpwnam("nobody")) != NULL) {
		if (setuid(pw->pw_uid) == 0) {
			return; // success
		}
	}
	log_fatal("zmap", "Couldn't change UID to 'nobody'");		
}

static void *start_mon(__attribute__((unused)) void *arg)
{
	set_cpu();
	monitor_run();
	return NULL;
}

#define SI(w,x,y) printf("%s\t%s\t%i\n", w, x, y);
#define SD(w,x,y) printf("%s\t%s\t%f\n", w, x, y);
#define SU(w,x,y) printf("%s\t%s\t%u\n", w, x, y);
#define SLU(w,x,y) printf("%s\t%s\t%lu\n", w, x, (long unsigned int) y);
#define SS(w,x,y) printf("%s\t%s\t%s\n", w, x, y);
#define STRTIME_LEN 1024

static void summary(void)
{
	char send_start_time[STRTIME_LEN+1];
	assert(dstrftime(send_start_time, STRTIME_LEN, "%c", zsend.start));
	char send_end_time[STRTIME_LEN+1];
	assert(dstrftime(send_end_time, STRTIME_LEN, "%c", zsend.finish));
	char recv_start_time[STRTIME_LEN+1];
	assert(dstrftime(recv_start_time, STRTIME_LEN, "%c", zrecv.start));
	char recv_end_time[STRTIME_LEN+1];
	assert(dstrftime(recv_end_time, STRTIME_LEN, "%c", zrecv.finish));
	double hitrate = ((double) 100 * zrecv.success_unique)/((double)zsend.sent);

	SU("cnf", "target-port", zconf.target_port);
	SU("cnf", "source-port-range-begin", zconf.source_port_first);
	SU("cnf", "source-port-range-end", zconf.source_port_last);
	SS("cnf", "source-addr-range-begin", zconf.source_ip_first);
	SS("cnf", "source-addr-range-end", zconf.source_ip_last);
	SU("cnf", "maximum-targets", zconf.max_targets);
	SU("cnf", "maximum-runtime", zconf.max_runtime);
	SU("cnf", "maximum-results", zconf.max_results);
	SU("cnf", "permutation-seed", zconf.seed);
	SI("cnf", "cooldown-period", zconf.cooldown_secs);
	SS("cnf", "send-interface", zconf.iface);
	SI("cnf", "rate", zconf.rate);
	SLU("cnf", "bandwidth", zconf.bandwidth);
	SU("env", "nprocessors", (unsigned) sysconf(_SC_NPROCESSORS_ONLN));
	SS("exc", "send-start-time", send_start_time);
	SS("exc", "send-end-time", send_end_time);
	SS("exc", "recv-start-time", recv_start_time);
	SS("exc", "recv-end-time", recv_end_time);
	SU("exc", "sent", zsend.sent);
	SU("exc", "blacklisted", zsend.blacklisted);
	SU("exc", "first-scanned", zsend.first_scanned);
	SD("exc", "hit-rate", hitrate);
	SU("exc", "success-total", zrecv.success_total);
	SU("exc", "success-unique", zrecv.success_unique);
	SU("exc", "success-cooldown-total", zrecv.cooldown_total);
	SU("exc", "success-cooldown-unique", zrecv.cooldown_unique);
	SU("exc", "failure-total", zrecv.failure_total);
	SU("exc", "sendto-failures", zsend.sendto_failures);
	SU("adv", "permutation-gen", zconf.generator);
	SS("exc", "scan-type", zconf.probe_module->name);
}

static void start_zmap(void)
{
	log_info("zmap", "started");

	// finish setting up configuration
	if (zconf.iface == NULL) {
		char errbuf[PCAP_ERRBUF_SIZE];
		char *iface = pcap_lookupdev(errbuf);
		if (iface == NULL) {
			log_fatal("zmap", "could not detect default network interface "
					"(e.g. eth0). Try running as root or setting"
					" interface using -i flag.");
		}
		log_debug("zmap", "no interface provided. will use %s", iface);
		zconf.iface = iface;
	}
	if (zconf.source_ip_first == NULL) {
		struct in_addr default_ip;
		zconf.source_ip_first = malloc(INET_ADDRSTRLEN);
		zconf.source_ip_last = zconf.source_ip_first;
		if (get_iface_ip(zconf.iface, &default_ip) < 0) {
			log_fatal("zmap", "could not detect default IP address for for %s."
					" Try specifying a source address (-S).", zconf.iface);
		}
		inet_ntop(AF_INET, &default_ip, zconf.source_ip_first, INET_ADDRSTRLEN);
		log_debug("zmap", "no source IP address given. will use %s",
				zconf.source_ip_first);
	}
	if (!zconf.gw_mac_set) {
		struct in_addr gw_ip;
		char iface[IF_NAMESIZE];
		if (get_default_gw(&gw_ip, iface) < 0) {
			log_fatal("zmap", "could not detect default gateway address for %i."
					" Try setting default gateway mac address (-G).");
		}
		log_debug("zmap", "found gateway IP %s on %s", inet_ntoa(gw_ip), iface); 
		if (get_hw_addr(&gw_ip, iface, zconf.gw_mac) < 0) {
			log_fatal("zmap", "could not detect GW MAC address for %s on %s."
					" Try setting default gateway mac address (-G).",
					inet_ntoa(gw_ip), zconf.iface);
		}
		zconf.gw_mac_set = 1;
		log_debug("zmap", "using default gateway MAC %02x:%02x:%02x:%02x:%02x:%02x",
				  zconf.gw_mac[0], zconf.gw_mac[1], zconf.gw_mac[2],
				  zconf.gw_mac[3], zconf.gw_mac[4], zconf.gw_mac[5]);
	}

	// initialization
	if (zconf.output_module && zconf.output_module->init) {
		zconf.output_module->init(&zconf, zconf.output_fields,
				zconf.output_fields_len);
	}
	if (send_init()) {
		exit(EXIT_FAILURE);
	}
	if (zconf.output_module && zconf.output_module->start) {
		zconf.output_module->start(&zconf, &zsend, &zrecv);
	}
	// start threads
	pthread_t *tsend, trecv, tmon;
	int r = pthread_create(&trecv, NULL, start_recv, NULL);
	if (r != 0) {
		log_fatal("zmap", "unable to create recv thread");
		exit(EXIT_FAILURE);
	}
	for (;;) {
		pthread_mutex_lock(&recv_ready_mutex);
		if (zconf.recv_ready) {
			break;
		}
		pthread_mutex_unlock(&recv_ready_mutex);
	}
	tsend = malloc(zconf.senders * sizeof(pthread_t));
	assert(tsend);
	log_debug("zmap", "using %d sender threads", zconf.senders);
	for (int i=0; i < zconf.senders; i++) {
	uintptr_t sock;
		if (zconf.dryrun) {
			sock = get_dryrun_socket();
		} else {
			sock = get_socket();
		}
		
		int r = pthread_create(&tsend[i], NULL, start_send, (void*) sock);
		if (r != 0) {
			log_fatal("zmap", "unable to create send thread");
			exit(EXIT_FAILURE);
		}
	}
	if (!zconf.quiet) {
		int r = pthread_create(&tmon, NULL, start_mon, NULL);
		if (r != 0) {
			log_fatal("zmap", "unable to create monitor thread");
			exit(EXIT_FAILURE);
		}
	}

	drop_privs();

	// wait for completion
	for (int i=0; i < zconf.senders; i++) {
		int r = pthread_join(tsend[i], NULL);
		if (r != 0) {
			log_fatal("zmap", "unable to join send thread");
			exit(EXIT_FAILURE);
		}
	}
	log_debug("zmap", "senders finished");
	r = pthread_join(trecv, NULL);
	if (r != 0) {
		log_fatal("zmap", "unable to join recv thread");
		exit(EXIT_FAILURE);
	}
	if (!zconf.quiet) {
		pthread_join(tmon, NULL);
		if (r != 0) {
			log_fatal("zmap", "unable to join monitor thread");
			exit(EXIT_FAILURE);
		}
	}

	// finished
	if (zconf.summary) {
		summary();
	}
	if (zconf.output_module && zconf.output_module->close) {
		zconf.output_module->close(&zconf, &zsend, &zrecv);
	}
	if (zconf.probe_module && zconf.probe_module->close) {
		zconf.probe_module->close(&zconf, &zsend, &zrecv);
	}
	log_info("zmap", "completed");
}

static void enforce_range(const char *name, int v, int min, int max)
{
	if (v < min || v > max) {
	  	fprintf(stderr, "%s: argument `%s' must be between %d and %d\n",
			CMDLINE_PARSER_PACKAGE, name, min, max);
		exit(EXIT_FAILURE);
	}
}

static int file_exists(char *name)
{
	FILE *file = fopen(name, "r");
	if (!file)
		return 0;
	fclose(file);
	return 1;
}

#define MAC_LEN IFHWADDRLEN
int parse_mac(macaddr_t *out, char *in)
{
	if (strlen(in) < MAC_LEN*3-1)
		return 0;
	char octet[3];
	octet[2] = '\0';
	for (int i=0; i < MAC_LEN; i++) {
		if (i < MAC_LEN-1 && in[i*3+2] != ':') {
			return 0;
		}
		strncpy(octet, &in[i*3], 2);
		char *err = NULL;
		long b = strtol(octet, &err, 16);
		if (err && *err != '\0') {
			return 0;
		}
		out[i] = b & 0xFF;
	}
	return 1;
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

	if (cmdline_parser_ext(argc, argv, &args, params) != 0) {
		exit(EXIT_SUCCESS);
	}

	zconf.log_level = args.verbosity_arg;
	log_init(stderr, zconf.log_level);
	log_trace("zmap", "zmap main thread started");

	if (args.help_given) {
		cmdline_parser_print_help();
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
	if (args.config_given || file_exists(args.config_arg)) {
		params->initialize = 0;
		params->override = 0;
		if (cmdline_parser_config_file(args.config_arg, &args, params) 
				!= 0) {
			exit(EXIT_FAILURE);
		}
	}
	if (args.vpn_given) {
		zconf.send_ip_pkts = 1;
		zconf.gw_mac_set = 1;
		memset(zconf.gw_mac, 0, IFHWADDRLEN);
	}
	if (cmdline_parser_required(&args, CMDLINE_PARSER_PACKAGE) != 0) {
		exit(EXIT_FAILURE);
	}
	// parse the provided probe and output module s.t. that we can support
	// other command-line helpers (e.g. probe help)
	if (!args.output_module_given) {
		zconf.output_module = get_output_module_by_name("csv");
		zconf.raw_output_fields = (char*) "saddr";
		zconf.filter_duplicates = 1;
		zconf.filter_unsuccessful = 1;
	} else if (!strcmp(args.output_module_arg, "simple_file")) {
		log_warn("zmap", "the simple_file output interface has been deprecated and "
                                 "will be removed in the future. Users should use the csv "
				 "output module. Newer scan options such as output-fields "
				 "are not supported with this output module."); 
		zconf.output_module = get_output_module_by_name("csv");
		zconf.raw_output_fields = (char*) "saddr";
		zconf.filter_duplicates = 1;
		zconf.filter_unsuccessful = 1;
	} else if (!strcmp(args.output_module_arg, "extended_file")) {
		log_warn("zmap", "the extended_file output interface has been deprecated and "
                                 "will be removed in the future. Users should use the csv "
				 "output module. Newer scan options such as output-fields "
				 "are not supported with this output module."); 
		zconf.output_module = get_output_module_by_name("csv");
		zconf.raw_output_fields = (char*) "classification, saddr, "
						  "daddr, sport, dport, "
						  "seqnum, acknum, cooldown, "
						  "repeat, timestamp-str";
		zconf.filter_duplicates = 0;
	} else {
		zconf.output_module = get_output_module_by_name(args.output_module_arg);
		if (!zconf.output_module) {
		  fprintf(stderr, "%s: specified output module (%s) does not exist\n",
			  CMDLINE_PARSER_PACKAGE, args.output_module_arg);
		  exit(EXIT_FAILURE);
		}
	}
	zconf.probe_module = get_probe_module_by_name(args.probe_module_arg);
	if (!zconf.probe_module) {
		fprintf(stderr, "%s: specified probe module (%s) does not exist\n",
				CMDLINE_PARSER_PACKAGE, args.probe_module_arg);
	  exit(EXIT_FAILURE);
	}

	// now that we know the probe module, let's find what it supports
	memset(&zconf.fsconf, 0, sizeof(struct fieldset_conf));
	// the set of fields made available to a user is constructed
	// of IP header fields + probe module fields + system fields
	fielddefset_t *fds = &(zconf.fsconf.defs);
	gen_fielddef_set(fds, (fielddef_t*) &(ip_fields),
		4);
	gen_fielddef_set(fds, zconf.probe_module->fields,
		zconf.probe_module->numfields);
	gen_fielddef_set(fds, (fielddef_t*) &(sys_fields),
		5);
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
	split_string(zconf.raw_output_fields, &(zconf.output_fields_len),
			&(zconf.output_fields));
	for (int i=0; i < zconf.output_fields_len; i++) {
		log_debug("zmap", "requested output field (%i): %s",
				i,
				zconf.output_fields[i]);
	}
	// generate a translation that can be used to convert output
	// from a probe module to the input for an output module
	fs_generate_fieldset_translation(&zconf.fsconf.translation,
			&zconf.fsconf.defs, zconf.output_fields,
			zconf.output_fields_len);

	// Parse and validate the output filter, if any
	if (args.output_filter_arg) {
		// Run it through yyparse to build the expression tree
		if (!parse_filter_string(args.output_filter_arg)) {
			log_fatal("zmap", "Unable to parse filter expression");
		}

		// Check the fields used against the fieldset in use
		if (!validate_filter(zconf.filter.expression, &zconf.fsconf.defs)) {
			log_fatal("zmap", "Field does not exist");
		}
	}

	SET_BOOL(zconf.dryrun, dryrun);
	SET_BOOL(zconf.quiet, quiet);
	SET_BOOL(zconf.summary, summary);
	zconf.cooldown_secs = args.cooldown_time_arg;
	zconf.senders = args.sender_threads_arg;
	SET_IF_GIVEN(zconf.output_filename, output_file);
	SET_IF_GIVEN(zconf.blacklist_filename, blacklist_file);
	SET_IF_GIVEN(zconf.whitelist_filename, whitelist_file);
	SET_IF_GIVEN(zconf.probe_args, probe_args);
	SET_IF_GIVEN(zconf.output_args, output_args);
	SET_IF_GIVEN(zconf.iface, interface);
	SET_IF_GIVEN(zconf.max_runtime, max_runtime);
	SET_IF_GIVEN(zconf.max_results, max_results);
	SET_IF_GIVEN(zconf.rate, rate);
	SET_IF_GIVEN(zconf.packet_streams, probes);
	

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
			fprintf(stderr, "%s: target port is required for this type of probe\n",
				CMDLINE_PARSER_PACKAGE);
			exit(EXIT_FAILURE);
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
	if (args.seed_given) {
		zconf.seed = args.seed_arg;
		zconf.use_seed = 1;
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
		errno = 0;
		char *end;
	  	double v = strtod(args.max_targets_arg, &end);
		if (end == args.max_targets_arg || errno != 0) {
			fprintf(stderr, "%s: can't convert max-targets to a number\n",
					CMDLINE_PARSER_PACKAGE);
			exit(EXIT_FAILURE);
		}
		if (end[0] == '%' && end[1] == '\0') {
			// treat as percentage
			v = v * ((unsigned long long int)1 << 32) / 100.;
		} else if (end[0] != '\0') {
			fprintf(stderr, "%s: extra characters after max-targets\n",
				  CMDLINE_PARSER_PACKAGE);
			exit(EXIT_FAILURE);
		}
		if (v <= 0) {
			zconf.max_targets = 0;
		}
		else if (v >= ((unsigned long long int)1 << 32)) {
			zconf.max_targets = 0xFFFFFFFF;
		} else {
			zconf.max_targets = v;
		}
	}

	start_zmap();

	cmdline_parser_free(&args);
	free(params);
	return EXIT_SUCCESS;
}

