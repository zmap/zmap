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

#include <pthread.h>

#include "../lib/includes.h"
#include "../lib/blacklist.h"
#include "../lib/logger.h"
#include "../lib/random.h"
#include "../lib/xalloc.h"


#if defined(__APPLE__)
#include <mach/thread_act.h>
#endif

#ifdef JSON
#include <json.h>
#endif

#include "aesrand.h"
#include "zopt.h"
#include "send.h"
#include "recv.h"
#include "state.h"
#include "monitor.h"
#include "get_gateway.h"
#include "filter.h"

#include "output_modules/output_modules.h"
#include "probe_modules/probe_modules.h"

#define MAC_ADDR_LEN 6

pthread_mutex_t cpu_affinity_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t recv_ready_mutex = PTHREAD_MUTEX_INITIALIZER;

static int max(int a, int b) {
	if (a >= b) {
		return a;
	}
	return b;
}

// splits comma delimited string into char*[]. Does not handle
// escaping or complicated setups: designed to process a set
// of fields that the user wants output
static void split_string(char* in, int *len, char***results)
{
	char** fields = xcalloc(MAX_FIELDS, sizeof(char*));
	int retvlen = 0;
	char *currloc = in;
	// parse csv into a set of strings
	while (1) {
		size_t len = strcspn(currloc, ", ");
		if (len == 0) {
			currloc++;
		} else {
			char *new = xmalloc(len+1);
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

// print a string using w length long lines
// attempting to break on spaces.
void fprintw(FILE *f, char *s, size_t w)
{
	if (strlen(s) <= w) {
		fprintf(f, "%s", s);
		return;
	}
	// process each line individually in order to
	// respect existing line breaks in string.
	char *news = strdup(s);
	char *pch = strtok(news, "\n");
	while (pch) {
		if (strlen(pch) <= w) {
			printf("%s\n", pch);
			pch = strtok(NULL, "\n");
			continue;
		}
		char *t = pch;
		while (strlen(t)) {
			size_t numchars = 0; //number of chars to print
			char *tmp = t;
			while (1) {
				size_t new = strcspn(tmp, " ") + 1;
				if (new == strlen(tmp) || new > w) {
					// there are no spaces in the string, so, just
					// print the entire thing on one line;
					numchars += new;
					break;
				} else if (numchars + new > w) {
					// if we added any more, we'd be over w chars so
					// time to print the line and move on to the next.
					break;
				} else {
					tmp += (size_t) new;
					numchars += new;
				}
			}
			fprintf(f, "%.*s\n", (int) numchars, t);
			t += (size_t) numchars;
			if (t > pch + (size_t)strlen(pch)) {
				break;
			}
		}
		pch = strtok(NULL, "\n");
	}
	free(news);
}


//#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__)
#if defined(__APPLE__)
static void set_cpu(void)
{
	pthread_mutex_lock(&cpu_affinity_mutex);
	static int core=0;
	int num_cores = sysconf(_SC_NPROCESSORS_ONLN);

	mach_port_t tid = pthread_mach_thread_np(pthread_self());
	struct thread_affinity_policy policy;
	policy.affinity_tag = core;
	kern_return_t ret = thread_policy_set(tid,THREAD_AFFINITY_POLICY,
					(thread_policy_t) &policy,THREAD_AFFINITY_POLICY_COUNT);
	if (ret != KERN_SUCCESS) {
		log_error("zmap", "can't set thread CPU affinity");
	}
	log_trace("zmap", "set thread %u affinity to core %d",
			pthread_self(), core);
	core = (core + 1) % num_cores;

	pthread_mutex_unlock(&cpu_affinity_mutex);
}

#else

#if defined(__FreeBSD__) || defined(__NetBSD__)
#include <sys/param.h>
#include <sys/cpuset.h>
#define cpu_set_t cpuset_t
#endif

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
#endif

typedef struct send_arg {
	int sock;
	shard_t *shard;
} send_arg_t;

static void* start_send(void *arg)
{
	send_arg_t *v = (send_arg_t *) arg;
	set_cpu();
	send_run(v->sock, v->shard);
	free(v);
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
	if (geteuid() != 0) {
		log_warn("zmap", "unable to drop privs, not root");
		return;
	}
	if ((pw = getpwnam("nobody")) != NULL) {
		if (setuid(pw->pw_uid) == 0) {
			return; // success
		}
	}
	log_fatal("zmap", "Couldn't change UID to 'nobody'");
}

typedef struct mon_start_arg {
	iterator_t *it;
	pthread_mutex_t *recv_ready_mutex;
} mon_start_arg_t;

static void *start_mon(void *arg)
{
	mon_start_arg_t *mon_arg = (mon_start_arg_t *) arg;
	set_cpu();
	monitor_run(mon_arg->it, mon_arg->recv_ready_mutex);
	free(mon_arg);
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
	SU("cnf", "shard-num", (unsigned) zconf.shard_num);
	SU("cnf", "num-shards", (unsigned) zconf.total_shards);
	SU("cnf", "senders", (unsigned) zconf.senders);
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
	// if there are application-level status messages, output
	if (zconf.fsconf.app_success_index >= 0) {
		SU("exc", "app-success-total", zrecv.app_success_total);
		SU("exc", "app-success-unique", zrecv.app_success_unique);
	}
	SU("exc", "success-cooldown-total", zrecv.cooldown_total);
	SU("exc", "success-cooldown-unique", zrecv.cooldown_unique);
	SU("exc", "failure-total", zrecv.failure_total);
	SU("exc", "sendto-failures", zsend.sendto_failures);
	SU("adv", "permutation-gen", zconf.generator);
	SS("exc", "scan-type", zconf.probe_module->name);
}

#ifdef JSON
static void json_metadata(FILE *file)
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

	json_object *obj = json_object_new_object();

	// scanner host name
	char hostname[1024];
	if (gethostname(hostname, 1023) < 0) {
		log_error("json-metadata", "unable to retrieve local hostname");
	} else {
		hostname[1023] = '\0';
		json_object_object_add(obj, "local-hostname", json_object_new_string(hostname));
		struct hostent* h = gethostbyname(hostname);
		if (h) {
			json_object_object_add(obj, "full-hostname", json_object_new_string(h->h_name));
		} else {
			log_error("json-metadata", "unable to retrieve complete hostname");
		}
	}

	json_object_object_add(obj, "target-port",
			json_object_new_int(zconf.target_port));
	json_object_object_add(obj, "source-port-first",
			json_object_new_int(zconf.source_port_first));
	json_object_object_add(obj, "source_port-last",
			json_object_new_int(zconf.source_port_last));
	json_object_object_add(obj, "max-targets", json_object_new_int(zconf.max_targets));
	json_object_object_add(obj, "max-runtime", json_object_new_int(zconf.max_runtime));
	json_object_object_add(obj, "max-results", json_object_new_int(zconf.max_results));
	if (zconf.iface) {
		json_object_object_add(obj, "iface", json_object_new_string(zconf.iface));
	}
	json_object_object_add(obj, "rate", json_object_new_int(zconf.rate));
	json_object_object_add(obj, "bandwidth", json_object_new_int(zconf.bandwidth));
	json_object_object_add(obj, "cooldown-secs", json_object_new_int(zconf.cooldown_secs));
	json_object_object_add(obj, "senders", json_object_new_int(zconf.senders));
	json_object_object_add(obj, "use-seed", json_object_new_int(zconf.use_seed));
	json_object_object_add(obj, "seed", json_object_new_int(zconf.seed));
	json_object_object_add(obj, "generator", json_object_new_int64(zconf.generator));
	json_object_object_add(obj, "hitrate", json_object_new_double(hitrate));
	json_object_object_add(obj, "shard-num", json_object_new_int(zconf.shard_num));
	json_object_object_add(obj, "total-shards", json_object_new_int(zconf.total_shards));

	json_object_object_add(obj, "syslog", json_object_new_int(zconf.syslog));
	json_object_object_add(obj, "filter-duplicates", json_object_new_int(zconf.filter_duplicates));
	json_object_object_add(obj, "filter-unsuccessful", json_object_new_int(zconf.filter_unsuccessful));

	json_object_object_add(obj, "pcap-recv", json_object_new_int(zrecv.pcap_recv));
	json_object_object_add(obj, "pcap-drop", json_object_new_int(zrecv.pcap_drop));
	json_object_object_add(obj, "pcap-ifdrop", json_object_new_int(zrecv.pcap_ifdrop));

	json_object_object_add(obj, "blacklisted", json_object_new_int(zsend.blacklisted));
	json_object_object_add(obj, "first-scanned", json_object_new_int(zsend.first_scanned));
	json_object_object_add(obj, "send-to-failures", json_object_new_int(zsend.sendto_failures));
	json_object_object_add(obj, "total-sent", json_object_new_int(zsend.sent));

	json_object_object_add(obj, "success-total", json_object_new_int(zrecv.success_total));
	json_object_object_add(obj, "success-unique", json_object_new_int(zrecv.success_unique));
	if (zconf.fsconf.app_success_index >= 0) {
		json_object_object_add(obj, "app-success-total", json_object_new_int(zrecv.app_success_total));
		json_object_object_add(obj, "app-success-unique", json_object_new_int(zrecv.app_success_unique));
	}
	json_object_object_add(obj, "success-cooldown-total", json_object_new_int(zrecv.cooldown_total));
	json_object_object_add(obj, "success-cooldown-unique", json_object_new_int(zrecv.cooldown_unique));
	json_object_object_add(obj, "failure-total", json_object_new_int(zrecv.failure_total));

	json_object_object_add(obj, "packet-streams",
			json_object_new_int(zconf.packet_streams));
	json_object_object_add(obj, "probe-module",
			json_object_new_string(((probe_module_t *)zconf.probe_module)->name));
	json_object_object_add(obj, "output-module",
			json_object_new_string(((output_module_t *)zconf.output_module)->name));

	json_object_object_add(obj, "send-start-time",
			json_object_new_string(send_start_time));
	json_object_object_add(obj, "send-end-time",
			json_object_new_string(send_end_time));
	json_object_object_add(obj, "recv-start-time",
			json_object_new_string(recv_start_time));
	json_object_object_add(obj, "recv-end-time",
			json_object_new_string(recv_end_time));

	if (zconf.output_filter_str) {
		json_object_object_add(obj, "output-filter", json_object_new_string(zconf.output_filter_str));
	}
	if (zconf.log_file) {
		json_object_object_add(obj, "log-file", json_object_new_string(zconf.log_file));
	}
	if (zconf.log_directory) {
		json_object_object_add(obj, "log-directory", json_object_new_string(zconf.log_directory));
	}

	if (zconf.destination_cidrs_len) {
		json_object *cli_dest_cidrs = json_object_new_array();
		for (int i=0; i < zconf.destination_cidrs_len; i++) {
			json_object_array_add(cli_dest_cidrs, json_object_new_string(zconf.destination_cidrs[i]));
		}
		json_object_object_add(obj, "cli-cidr-destinations",
				cli_dest_cidrs);
	}
	if (zconf.probe_args) {
		json_object_object_add(obj, "probe-args",
			json_object_new_string(zconf.probe_args));
	}
	if (zconf.output_args) {
		json_object_object_add(obj, "output-args",
			json_object_new_string(zconf.output_args));
	}

	if (zconf.gw_mac) {
		char mac_buf[ (MAC_ADDR_LEN * 2) + (MAC_ADDR_LEN - 1) + 1 ];
		memset(mac_buf, 0, sizeof(mac_buf));
		char *p = mac_buf;
		for(int i=0; i < MAC_ADDR_LEN; i++) {
			if (i == MAC_ADDR_LEN-1) {
				snprintf(p, 3, "%.2x", zconf.gw_mac[i]);
				p += 2;
			} else {
				snprintf(p, 4, "%.2x:", zconf.gw_mac[i]);
				p += 3;
			}
		}
		json_object_object_add(obj, "gateway-mac", json_object_new_string(mac_buf));
	}
	if (zconf.gw_ip) {
		struct in_addr addr;
		addr.s_addr = zconf.gw_ip;
		json_object_object_add(obj, "gateway-ip", json_object_new_string(inet_ntoa(addr)));
	}
	if (zconf.hw_mac) {
		char mac_buf[(ETHER_ADDR_LEN * 2) + (ETHER_ADDR_LEN - 1) + 1];
		char *p = mac_buf;
		for(int i=0; i < ETHER_ADDR_LEN; i++) {
			if (i == ETHER_ADDR_LEN-1) {
				snprintf(p, 3, "%.2x", zconf.hw_mac[i]);
				p += 2;
			} else {
				snprintf(p, 4, "%.2x:", zconf.hw_mac[i]);
				p += 3;
			}
		}
		json_object_object_add(obj, "source-mac", json_object_new_string(mac_buf));
	}

	json_object_object_add(obj, "source-ip-first",
			json_object_new_string(zconf.source_ip_first));
	json_object_object_add(obj, "source-ip-last",
			json_object_new_string(zconf.source_ip_last));
	if (zconf.output_filename) {
		json_object_object_add(obj, "output-filename",
				json_object_new_string(zconf.output_filename));
	}
	if (zconf.blacklist_filename) {
		json_object_object_add(obj,
			"blacklist-filename",
			json_object_new_string(zconf.blacklist_filename));
	}
	if (zconf.whitelist_filename) {
		json_object_object_add(obj,
			"whitelist-filename",
			json_object_new_string(zconf.whitelist_filename));
	}
	json_object_object_add(obj, "dryrun", json_object_new_int(zconf.dryrun));
	json_object_object_add(obj, "summary", json_object_new_int(zconf.summary));
	json_object_object_add(obj, "quiet", json_object_new_int(zconf.quiet));
	json_object_object_add(obj, "log_level", json_object_new_int(zconf.log_level));
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
		json_object_object_add(obj, "blacklisted-networks", blacklisted_cidrs);
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
		json_object_object_add(obj, "whitelisted-networks", whitelisted_cidrs);
	}

	fprintf(file, "%s\n", json_object_to_json_string(obj));
	json_object_put(obj);
}
#endif

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
			log_fatal("zmap", "could not detect default IP address for for %s."
					" Try specifying a source address (-S).", zconf.iface);
		}
		inet_ntop(AF_INET, &default_ip, zconf.source_ip_first, INET_ADDRSTRLEN);
		log_debug("zmap", "no source IP address given. will use default address: %s.",
				zconf.source_ip_first);
	}
	if (!zconf.gw_mac_set) {
		struct in_addr gw_ip;
		if (get_default_gw(&gw_ip, zconf.iface) < 0) {
			log_fatal("zmap", "could not detect default gateway address for %s."
					" Try setting default gateway mac address (-G).",
					zconf.iface);
		}
		log_debug("zmap", "found gateway IP %s on %s", inet_ntoa(gw_ip), zconf.iface);
		zconf.gw_ip = gw_ip.s_addr;

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

	// Seed the RNG
	if (zconf.use_seed) {
		aesrand_init(zconf.seed + 1);
	} else {
		aesrand_init(0);
	}

	log_info("zmap", "output module: %s", zconf.output_module->name);
	if (zconf.output_module && zconf.output_module->init) {
		zconf.output_module->init(&zconf, zconf.output_fields,
				zconf.output_fields_len);
	}

	iterator_t *it = send_init();
	if (!it) {
		log_fatal("zmap", "unable to initialize sending component");
	}
	if (zconf.output_module && zconf.output_module->start) {
		zconf.output_module->start(&zconf, &zsend, &zrecv);
	}

	// start threads
	pthread_t *tsend, trecv, tmon;
	int r = pthread_create(&trecv, NULL, start_recv, NULL);
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
	tsend = xmalloc(zconf.senders * sizeof(pthread_t));
	for (uint8_t i = 0; i < zconf.senders; i++) {
		int sock;
		if (zconf.dryrun) {
			sock = get_dryrun_socket();
		} else {
			sock = get_socket();
		}
		send_arg_t *arg = xmalloc(sizeof(send_arg_t));
		arg->sock = sock;
		arg->shard = get_shard(it, i);
		int r = pthread_create(&tsend[i], NULL, start_send, arg);
		if (r != 0) {
			log_fatal("zmap", "unable to create send thread");
			exit(EXIT_FAILURE);
		}
	}
	log_debug("zmap", "%d sender threads spawned", zconf.senders);
	if (!zconf.quiet) {
		mon_start_arg_t *mon_arg = xmalloc(sizeof(mon_start_arg_t));
		mon_arg->it = it;
		mon_arg->recv_ready_mutex = &recv_ready_mutex;
		int r = pthread_create(&tmon, NULL, start_mon, mon_arg);
		if (r != 0) {
			log_fatal("zmap", "unable to create monitor thread");
			exit(EXIT_FAILURE);
		}
	}

	drop_privs();

	// wait for completion
	for (uint8_t i = 0; i < zconf.senders; i++) {
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
#ifdef JSON
	if (zconf.metadata_filename) {
		json_metadata(zconf.metadata_file);
	}
#endif
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
	  	log_fatal("zmap", "argument `%s' must be between %d and %d\n",
			name, min, max);
	}
}

#define MAC_LEN ETHER_ADDR_LEN
int parse_mac(macaddr_t *out, char *in)
{
	if (strlen(in) < MAC_LEN*3-1)
		return 0;
	char octet[4];
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
	if (args.config_given) {
		params->initialize = 0;
		params->override = 0;
		if (cmdline_parser_config_file(args.config_arg, &args, params) 
				!= 0) {
			exit(EXIT_FAILURE);
		}
	}

	// initialize logging. if no log file or log directory are specified
	// default to using stderr.
	zconf.log_level = args.verbosity_arg;
	zconf.log_file = args.log_file_arg;
	zconf.log_directory = args.log_directory_arg;
	if (args.disable_syslog_given) {
		zconf.syslog = 0;
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
	log_trace("zmap", "zmap main thread started");
	if (zconf.syslog) {
		log_debug("zmap", "syslog support enabled");
	} else {
		log_info("zmap", "syslog support disabled");
	}
	// parse the provided probe and output module s.t. that we can support
	// other command-line helpers (e.g. probe help)
	log_trace("zmap", "requested ouput-module: %s", args.output_module_arg);

	// we changed output module setup after the original version of ZMap was
	// made public. After this setup was removed, many of the original
	// output modules became unnecessary. However, in order to support
	// backwards compatibility, we still allows this output-modules to be
	// specified and then map these into new-style output modules and warn
	// users that they need to be switching to the new module interface.

	// zmap's default behavior is to provide a simple file of the unique IP
	// addresses that responded successfully.
	if (!strcmp(args.output_module_arg, "default")) {
		log_debug("zmap", "no output module provided. will use csv.");
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
	} else if (!strcmp(args.output_module_arg, "redis")) {
		log_warn("zmap", "the redis output interface has been deprecated and "
				 "will be removed in the future. Users should "
				 "either use redis-packed or redis-json in the "
				 "future.");
		zconf.output_module = get_output_module_by_name("redis-packed");
		if (!zconf.output_module) {
			log_fatal("zmap", "%s: specified output module (%s) does not exist\n",
					CMDLINE_PARSER_PACKAGE, args.output_module_arg);
		}
		zconf.raw_output_fields = (char*) "saddr";
		zconf.filter_duplicates = 1;
		zconf.filter_unsuccessful = 1;
		if (args.output_fields_given) {
			log_fatal("redis", "module does not support user defined "
					"output fields");
		}

		if (args.output_filter_given) {
			log_fatal("redis", "module does not support user defined "
					"filters.");
		}
	} else if (!strcmp(args.output_module_arg, "csvredis"))  {
		if (args.output_fields_given) {
			log_fatal("csvredis", "module does not support user defined "
					"output fields");
		}
		// output all available fields to the CSV file
		zconf.raw_output_fields = (char*) "*";
		// module does not support filtering
		if (args.output_filter_given) {
			log_fatal("csvredis", "module does not support user defined "
					"filters.");
		}
		zconf.output_module = get_output_module_by_name("csvredis");
	} else {
		zconf.output_module = get_output_module_by_name(args.output_module_arg);
		if (!zconf.output_module) {
		  log_fatal("zmap", "%s: specified output module (%s) does not exist\n",
				args.output_module_arg);
		  exit(EXIT_FAILURE);
		}
	}
	zconf.probe_module = get_probe_module_by_name(args.probe_module_arg);
	if (!zconf.probe_module) {
		log_fatal("zmap", "specified probe module (%s) does not exist\n",
				args.probe_module_arg);
	  exit(EXIT_FAILURE);
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
		if (zconf.output_module->helptext) {
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
		memset(zconf.gw_mac, 0, MAC_LEN);
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
		log_trace("fieldset", "probe module does not supply "
				      "application success field.");
	} else {
		log_trace("fieldset", "probe module supplies app_success"
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
	// Parse and validate the output filter, if any
	if (args.output_filter_arg) {
		// Run it through yyparse to build the expression tree
		if (!parse_filter_string(args.output_filter_arg)) {
			log_fatal("zmap", "Unable to parse filter expression");
		}

		// Check the fields used against the fieldset in use
		if (!validate_filter(zconf.filter.expression, &zconf.fsconf.defs)) {
			log_fatal("zmap", "Invalid filter");
		}
		zconf.output_filter_str = args.output_filter_arg;
	}

	SET_BOOL(zconf.dryrun, dryrun);
	SET_BOOL(zconf.quiet, quiet);
	SET_BOOL(zconf.summary, summary);
	SET_BOOL(zconf.ignore_invalid_hosts, ignore_invalid_hosts);
	zconf.cooldown_secs = args.cooldown_time_arg;
	SET_IF_GIVEN(zconf.output_filename, output_file);
	SET_IF_GIVEN(zconf.blacklist_filename, blacklist_file);
	SET_IF_GIVEN(zconf.probe_args, probe_args);
	SET_IF_GIVEN(zconf.output_args, output_args);
	SET_IF_GIVEN(zconf.iface, interface);
	SET_IF_GIVEN(zconf.max_runtime, max_runtime);
	SET_IF_GIVEN(zconf.max_results, max_results);
	SET_IF_GIVEN(zconf.rate, rate);
	SET_IF_GIVEN(zconf.packet_streams, probes);

	if (args.metadata_file_arg) {
#ifdef JSON
		zconf.metadata_filename = args.metadata_file_arg;
		if (!strcmp(zconf.metadata_filename, "-")) {
			zconf.metadata_file = stdout;
		} else {
			zconf.metadata_file = fopen(zconf.metadata_filename, "w");
		}
		if (!zconf.metadata_file) {
			log_fatal("metadata", "unable to open metadata file");
		}
		log_trace("metadata", "metdata will be saved to %s",
				zconf.metadata_filename);
#else
		log_fatal("zmap", "JSON support not compiled into ZMap. "
				"Metadata output not supported.");
#endif
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
	if (args.seed_given) {
		zconf.seed = args.seed_arg;
		zconf.use_seed = 1;
	}
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

	// blacklist
	if (blacklist_init(zconf.whitelist_filename, zconf.blacklist_filename,
			   zconf.destination_cidrs, zconf.destination_cidrs_len,
			   NULL, 0)) {
		log_fatal("zmap", "unable to initialize blacklist / whitelist");
	}

	// compute number of targets
	uint64_t allowed = blacklist_count_allowed();
	assert(allowed <= (1LL << 32));
	if (allowed == (1LL << 32)) {
		zsend.targets = 0xFFFFFFFF;
	} else {
		zsend.targets = allowed;
	}
	if (zsend.targets > zconf.max_targets) {
		zsend.targets = zconf.max_targets;
	}

	// Set the correct number of threads, default to num_cores - 1
	if (args.sender_threads_given) {
		zconf.senders = args.sender_threads_arg;
	} else {
		int num_cores = sysconf(_SC_NPROCESSORS_ONLN);
		zconf.senders = max(num_cores - 1, 1);
		if (!zconf.quiet) {
			// If monitoring, save a core for the monitor thread
			zconf.senders = max(zconf.senders - 1, 1);
		}
	}

	if (zconf.senders > zsend.targets) {
		zconf.senders = max(zsend.targets, 1);
	}

	start_zmap();

	fclose(log_location);

	cmdline_parser_free(&args);
	free(params);
	return EXIT_SUCCESS;
}

