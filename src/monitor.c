/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

// module responsible for printing on-screen updates during the scan process

#include "monitor.h"

#include <assert.h>
#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "iterator.h"
#include "recv.h"
#include "state.h"

#include "../lib/lockfd.h"
#include "../lib/logger.h"
#include "../lib/util.h"
#include "../lib/xalloc.h"

#define UPDATE_INTERVAL 1 // seconds
#define NUMBER_STR_LEN 20
#define WARMUP_PERIOD 5
#define MIN_HITRATE_TIME_WINDOW 5 // seconds

// internal monitor status that is used to track deltas
typedef struct internal_scan_status {
	double last_now;
	uint32_t last_sent;
	uint32_t last_tried_sent;
	uint32_t last_send_failures;
	uint32_t last_recv_net_success;
	uint32_t last_recv_app_success;
	uint32_t last_recv_total;
	uint32_t last_pcap_drop;
	double min_hitrate_start;
} int_status_t;

// exportable status information that can be printed to screen
typedef struct export_scan_status {
	uint32_t total_sent;
	uint32_t total_tried_sent;
	uint32_t recv_success_unique;
	uint32_t app_recv_success_unique;
	uint32_t total_recv;
	uint32_t complete;
	uint32_t send_threads;
	double percent_complete;

	double hitrate; // network, e.g. SYN-ACK vs RST
	double
	    app_hitrate; // application level, e.g. DNS response versus correct
			 // lookup.

	double send_rate;
	char send_rate_str[NUMBER_STR_LEN];
	double send_rate_avg;
	char send_rate_avg_str[NUMBER_STR_LEN];

	double recv_rate;
	char recv_rate_str[NUMBER_STR_LEN];
	double recv_avg;
	char recv_avg_str[NUMBER_STR_LEN];
	double recv_total_rate;
	double recv_total_avg;

	double app_success_rate;
	char app_success_rate_str[NUMBER_STR_LEN];
	double app_success_avg;
	char app_success_avg_str[NUMBER_STR_LEN];

	uint32_t pcap_drop;
	uint32_t pcap_ifdrop;
	uint32_t pcap_drop_total;
	char pcap_drop_total_str[NUMBER_STR_LEN];
	double pcap_drop_last;
	char pcap_drop_last_str[NUMBER_STR_LEN];
	double pcap_drop_avg;
	char pcap_drop_avg_str[NUMBER_STR_LEN];

	uint32_t time_remaining;
	char time_remaining_str[NUMBER_STR_LEN];
	uint32_t time_past;
	char time_past_str[NUMBER_STR_LEN];

	uint32_t fail_total;
	double fail_avg;
	double fail_last;
	float seconds_under_min_hitrate;

} export_status_t;

static FILE *status_fd = NULL;

// find minimum of an array of doubles
static double min_d(double array[], int n)
{
	double value = INFINITY;
	for (int i = 0; i < n; i++) {
		if (array[i] < value) {
			value = array[i];
		}
	}
	return value;
}

// estimate time remaining time based on config and state
double compute_remaining_time(double age, uint64_t tried_sent)
{
	if (!zsend.complete) {
		double remaining[] = {INFINITY, INFINITY, INFINITY, INFINITY};
		if (zsend.max_targets) {
			double done = (double)tried_sent /
				      (zsend.max_targets / zconf.total_shards);
			remaining[0] =
			    (1. - done) * (age / done) + zconf.cooldown_secs;
		}
		if (zconf.max_runtime) {
			remaining[1] =
			    (zconf.max_runtime - age) + zconf.cooldown_secs;
		}
		if (zconf.max_results) {
			double done =
			    (double)zrecv.filter_success / zconf.max_results;
			remaining[2] = (1. - done) * (age / done);
		}
		if (zsend.max_index) {
			double done = (double)tried_sent /
				      (zsend.max_index / zconf.total_shards);
			remaining[3] =
			    (1. - done) * (age / done) + zconf.cooldown_secs;
		}
		return min_d(remaining, sizeof(remaining) / sizeof(double));
	} else {
		return zconf.cooldown_secs - (now() - zsend.finish);
	}
}

static void update_pcap_stats(pthread_mutex_t *recv_ready_mutex)
{
	// ask pcap for fresh values
	pthread_mutex_lock(recv_ready_mutex);
	recv_update_stats();
	pthread_mutex_unlock(recv_ready_mutex);
}

static void export_stats(int_status_t *intrnl, export_status_t *exp,
			 iterator_t *it)
{
	uint32_t total_sent = iterator_get_sent(it);
	uint32_t total_tried_sent = iterator_get_tried_sent(it);
	uint32_t total_fail = iterator_get_fail(it);
	uint32_t total_recv = zrecv.pcap_recv;
	uint32_t recv_success = zrecv.success_unique;
	uint32_t app_success = zrecv.app_success_unique;
	double cur_time = now();
	double age = cur_time - zsend.start; // time of entire scan
	// time since the last time we updated
	double delta = cur_time - intrnl->last_now;
	double remaining_secs = compute_remaining_time(age, total_tried_sent);

	// export amount of time the scan has been running
	if (age < WARMUP_PERIOD) {
		exp->time_remaining_str[0] = '\0';
	} else {
		char buf[20];
		time_string(ceil(remaining_secs), 1, buf, sizeof(buf));
		snprintf(exp->time_remaining_str, NUMBER_STR_LEN, " (%s left)",
			 buf);
	}
	exp->time_past = age;
	exp->time_remaining = remaining_secs;
	time_string((int)age, 0, exp->time_past_str, NUMBER_STR_LEN);

	// export recv statistics
	exp->recv_rate = (recv_success - intrnl->last_recv_net_success) / delta;
	number_string(exp->recv_rate, exp->recv_rate_str, NUMBER_STR_LEN);
	exp->recv_avg = recv_success / age;
	number_string(exp->recv_avg, exp->recv_avg_str, NUMBER_STR_LEN);
	exp->recv_total_rate = (total_recv - intrnl->last_recv_total) / delta;
	exp->recv_total_avg = total_recv / age;

	// application level statistics
	if (zconf.fsconf.app_success_index >= 0) {
		exp->app_success_rate =
		    (app_success - intrnl->last_recv_app_success) / delta;
		number_string(exp->app_success_rate, exp->app_success_rate_str,
			      NUMBER_STR_LEN);
		exp->app_success_avg = (app_success / age);
		number_string(exp->app_success_avg, exp->app_success_avg_str,
			      NUMBER_STR_LEN);
	}

	if (!total_sent) {
		exp->hitrate = 0;
		exp->app_hitrate = 0;
	} else {
		exp->hitrate = recv_success * 100.0 / total_sent;
		exp->app_hitrate = app_success * 100.0 / total_sent;
	}

	if (age > WARMUP_PERIOD && exp->hitrate < zconf.min_hitrate) {
		if (fabs(intrnl->min_hitrate_start) < .00001) {
			intrnl->min_hitrate_start = cur_time;
		}
	} else {
		intrnl->min_hitrate_start = 0.0;
	}
	if (fabs(intrnl->min_hitrate_start) < .00001) {
		exp->seconds_under_min_hitrate = 0;
	} else {
		exp->seconds_under_min_hitrate =
		    cur_time - intrnl->min_hitrate_start;
	}
	if (!zsend.complete) {
		exp->send_rate = (total_sent - intrnl->last_sent) / delta;
		number_string(exp->send_rate, exp->send_rate_str,
			      NUMBER_STR_LEN);
		exp->send_rate_avg = total_sent / age;
		number_string(exp->send_rate_avg, exp->send_rate_avg_str,
			      NUMBER_STR_LEN);
	} else {
		exp->send_rate_avg = total_sent / (zsend.finish - zsend.start);
		number_string(exp->send_rate_avg, exp->send_rate_avg_str,
			      NUMBER_STR_LEN);
	}
	// export other pre-calculated values
	exp->total_sent = total_sent;
	exp->total_tried_sent = total_tried_sent;
	exp->percent_complete = 100. * age / (age + remaining_secs);
	exp->recv_success_unique = recv_success;
	exp->app_recv_success_unique = app_success;
	exp->total_recv = total_recv;
	exp->complete = zsend.complete;

	// pcap dropped packets
	exp->pcap_drop = zrecv.pcap_drop;
	exp->pcap_ifdrop = zrecv.pcap_ifdrop;
	exp->pcap_drop_total = exp->pcap_drop + exp->pcap_ifdrop;
	exp->pcap_drop_last =
	    (exp->pcap_drop_total - intrnl->last_pcap_drop) / delta;
	exp->pcap_drop_avg = exp->pcap_drop_total / age;
	number_string(exp->pcap_drop_total, exp->pcap_drop_total_str,
		      NUMBER_STR_LEN);
	number_string(exp->pcap_drop_last, exp->pcap_drop_last_str,
		      NUMBER_STR_LEN);
	number_string(exp->pcap_drop_avg, exp->pcap_drop_avg_str,
		      NUMBER_STR_LEN);

	zsend.sendto_failures = total_fail;
	exp->fail_total = zsend.sendto_failures;
	exp->fail_last = (exp->fail_total - intrnl->last_send_failures) / delta;
	exp->fail_avg = exp->fail_total / age;

	// misc
	exp->send_threads = iterator_get_curr_send_threads(it);

	// Update internal stats
	intrnl->last_now = cur_time;
	intrnl->last_sent = exp->total_sent;
	intrnl->last_recv_net_success = exp->recv_success_unique;
	intrnl->last_recv_app_success = exp->app_recv_success_unique;
	intrnl->last_pcap_drop = exp->pcap_drop_total;
	intrnl->last_send_failures = exp->fail_total;
	intrnl->last_recv_total = exp->total_recv;
}

static void log_drop_warnings(export_status_t *exp)
{
	if (exp->pcap_drop_last / exp->recv_rate > 0.05) {
		log_warn("monitor",
			 "Dropped %.0f packets in the last second, (%u total "
			 "dropped (pcap: %u + iface: %u))",
			 exp->pcap_drop_last, exp->pcap_drop_total,
			 exp->pcap_drop, exp->pcap_ifdrop);
	}
	if (exp->fail_last / exp->send_rate > 0.01) {
		log_warn("monitor",
			 "Failed to send %.0f packets/sec (%u total failures)",
			 exp->fail_last, exp->fail_total);
	}
}

static void onscreen_appsuccess(export_status_t *exp)
{
	// this when probe module handles application-level success rates
	if (!exp->complete) {
		fprintf(stderr,
			"%5s %0.0f%%%s; sent: %u %sp/s (%sp/s avg); "
			"recv: %u %sp/s (%sp/s avg); "
			"app success: %u %sp/s (%sp/s avg); "
			"drops: %sp/s (%sp/s avg); "
			"hitrate: %0.2f%% "
			"app hitrate: %0.2f%%\n",
			exp->time_past_str, exp->percent_complete,
			exp->time_remaining_str, exp->total_sent,
			exp->send_rate_str, exp->send_rate_avg_str,
			exp->recv_success_unique, exp->recv_rate_str,
			exp->recv_avg_str, exp->app_recv_success_unique,
			exp->app_success_rate_str, exp->app_success_avg_str,
			exp->pcap_drop_last_str, exp->pcap_drop_avg_str,
			exp->hitrate, exp->app_hitrate);
	} else {
		fprintf(stderr,
			"%5s %0.0f%%%s; sent: %u done (%sp/s avg); "
			"recv: %u %sp/s (%sp/s avg); "
			"app success: %u %sp/s (%sp/s avg); "
			"drops: %sp/s (%sp/s avg); "
			"hitrate: %0.2f%% "
			"app hitrate: %0.2f%%\n",
			exp->time_past_str, exp->percent_complete,
			exp->time_remaining_str, exp->total_sent,
			exp->send_rate_avg_str, exp->recv_success_unique,
			exp->recv_rate_str, exp->recv_avg_str,
			exp->app_recv_success_unique, exp->app_success_rate_str,
			exp->app_success_avg_str, exp->pcap_drop_last_str,
			exp->pcap_drop_avg_str, exp->hitrate, exp->app_hitrate);
	}
}

static void onscreen_generic(export_status_t *exp)
{
	if (!exp->complete) {
		fprintf(stderr,
			"%5s %0.0f%%%s; send: %u %sp/s (%sp/s avg); "
			"recv: %u %sp/s (%sp/s avg); "
			"drops: %sp/s (%sp/s avg); "
			"hitrate: %0.2f%%\n",
			exp->time_past_str, exp->percent_complete,
			exp->time_remaining_str, exp->total_sent,
			exp->send_rate_str, exp->send_rate_avg_str,
			exp->recv_success_unique, exp->recv_rate_str,
			exp->recv_avg_str, exp->pcap_drop_last_str,
			exp->pcap_drop_avg_str, exp->hitrate);
	} else {
		fprintf(stderr,
			"%5s %0.0f%%%s; send: %u done (%sp/s avg); "
			"recv: %u %sp/s (%sp/s avg); "
			"drops: %sp/s (%sp/s avg); "
			"hitrate: %0.2f%%\n",
			exp->time_past_str, exp->percent_complete,
			exp->time_remaining_str, exp->total_sent,
			exp->send_rate_avg_str, exp->recv_success_unique,
			exp->recv_rate_str, exp->recv_avg_str,
			exp->pcap_drop_last_str, exp->pcap_drop_avg_str,
			exp->hitrate);
	}
	fflush(stderr);
}

static FILE *init_status_update_file(char *path)
{
	FILE *f = fopen(path, "w");
	if (!f) {
		log_fatal("csv", "could not open status updates file (%s): %s",
			  zconf.status_updates_file, strerror(errno));
	}
	log_debug("monitor", "status updates CSV will be saved to %s",
		  zconf.status_updates_file);
	fprintf(
	    f,
	    "real-time,time-elapsed,time-remaining,"
	    "percent-complete,hit-rate,active-send-threads,"
	    "sent-total,sent-last-one-sec,sent-avg-per-sec,"
	    "recv-success-total,recv-success-last-one-sec,recv-success-avg-per-sec,"
	    "recv-total,recv-total-last-one-sec,recv-total-avg-per-sec,"
	    "pcap-drop-total,drop-last-one-sec,drop-avg-per-sec,"
	    "sendto-fail-total,sendto-fail-last-one-sec,sendto-fail-avg-per-sec\n");
	fflush(f);
	return f;
}

static void update_status_updates_file(export_status_t *exp, FILE *f)
{
	struct timeval now;
	char timestamp[256];
	gettimeofday(&now, NULL);
	time_t sec = now.tv_sec;
	struct tm *ptm = localtime(&sec);
	strftime(timestamp, 20, "%Y-%m-%d %H:%M:%S", ptm);

	fprintf(f,
		"%s,%u,%u,"
		"%f,%f,%u,"
		"%u,%.0f,%.0f,"
		"%u,%.0f,%.0f,"
		"%u,%.0f,%.0f,"
		"%u,%.0f,%.0f,"
		"%u,%.0f,%.0f\n",
		timestamp, exp->time_past, exp->time_remaining,
		exp->percent_complete, exp->hitrate, exp->send_threads,
		exp->total_sent, exp->send_rate, exp->send_rate_avg,
		exp->recv_success_unique, exp->recv_rate, exp->recv_avg,
		exp->total_recv, exp->recv_total_rate, exp->recv_total_avg,
		exp->pcap_drop_total, exp->pcap_drop_last, exp->pcap_drop_avg,
		exp->fail_total, exp->fail_last, exp->fail_avg);
	fflush(f);
}

static inline void check_min_hitrate(export_status_t *exp)
{
	if (exp->seconds_under_min_hitrate >= MIN_HITRATE_TIME_WINDOW) {
		log_fatal("monitor",
			  "hitrate below %.0f for %.0f seconds. aborting scan.",
			  zconf.min_hitrate, exp->seconds_under_min_hitrate);
	}
}

static inline void check_max_sendto_failures(export_status_t *exp)
{
	if (zconf.max_sendto_failures >= 0 &&
	    exp->fail_total > (uint32_t)zconf.max_sendto_failures) {
		log_fatal("monitor",
			  "maximum number of sendto failures (%i) exceeded",
			  zconf.max_sendto_failures);
	}
}

void monitor_init(void)
{
	if (zconf.status_updates_file) {
		status_fd = init_status_update_file(zconf.status_updates_file);
		assert(status_fd);
	}
}

void monitor_run(iterator_t *it, pthread_mutex_t *lock)
{
	int_status_t *internal_status = xmalloc(sizeof(int_status_t));
	export_status_t *export_status = xmalloc(sizeof(export_status_t));

	while (!(zsend.complete && zrecv.complete)) {
		update_pcap_stats(lock);
		export_stats(internal_status, export_status, it);
		log_drop_warnings(export_status);
		check_min_hitrate(export_status);
		check_max_sendto_failures(export_status);
		if (!zconf.quiet) {
			lock_file(stderr);
			if (zconf.fsconf.app_success_index >= 0) {
				onscreen_appsuccess(export_status);
			} else {
				onscreen_generic(export_status);
			}
			unlock_file(stderr);
		}
		if (status_fd) {
			update_status_updates_file(export_status, status_fd);
		}
		sleep(UPDATE_INTERVAL);
	}
	if (!zconf.quiet) {
		lock_file(stderr);
		fflush(stderr);
		unlock_file(stderr);
	}
	if (status_fd) {
		fflush(status_fd);
		fclose(status_fd);
	}
}
