/*
 * ZMap Copyright 2013 Regents of the University of Michigan 
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

// module responsible for printing on-screen updates during the scan process

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <math.h>

#include "monitor.h"

#include "iterator.h"
#include "recv.h"
#include "state.h"

#include "../lib/logger.h"

#define UPDATE_INTERVAL 1 //seconds

static double last_now = 0.0;
static uint32_t last_sent = 0;
static uint32_t last_rcvd = 0;
static uint32_t last_drop = 0;
static uint32_t last_failures = 0;

static double min_d(double array[], int n)
{
	double value=INFINITY;
	for (int i=0; i<n; i++) {
		if (array[i] < value) {
			value = array[i];
		}
	}
	return value;
}

// pretty print elapsed (or estimated) number of seconds
static void time_string(uint32_t time, int est, char *buf, size_t len)
{
  	int y = time / 31556736;
  	int d = (time % 31556736) / 86400;
	int h = (time % 86400) / 3600;
	int m = (time % 3600) / 60;
	int s = time % 60;

	if (est) {
		if (y > 0) {
			snprintf(buf, len, "%d years", y);
		} else if (d > 9) {
			snprintf(buf, len, "%dd", d);
		} else if (d > 0) {
			snprintf(buf, len, "%dd%02dh", d, h);
		} else if (h > 9) {
			snprintf(buf, len, "%dh", h);
		} else if (h > 0) {
			snprintf(buf, len, "%dh%02dm", h, m);
		} else if (m > 9) {
			snprintf(buf, len, "%dm", m);
		} else if (m > 0) {
			snprintf(buf, len, "%dm%02ds", m, s);
		} else {
			snprintf(buf, len, "%ds", s);
		}
	} else {
		if (d > 0) {
			snprintf(buf, len, "%dd%d:%02d:%02d", d, h, m, s);
		} else if (h > 0) {
			snprintf(buf, len, "%d:%02d:%02d", h, m, s);
		} else {
			snprintf(buf, len, "%d:%02d", m, s);
		}
	}
}

// pretty print quantities
static void number_string(uint32_t n, char *buf, size_t len)
{
	int figs = 0;
	if (n < 1000) {
		snprintf(buf, len, "%u ", n);
	} else if (n < 1000000) {
		if (n < 10000) {
		figs = 2;
		} else if (n < 100000) {
		figs = 1;
		}
		snprintf(buf, len, "%0.*f K", figs, (float)n/1000.);
	} else {
		if (figs < 10000000) {
		figs = 2;
		} else if (figs < 100000000) {
			figs = 1;
		}
		snprintf(buf, len, "%0.*f M", figs, (float)n/1000000.);
	}
}

// estimate time remaining time based on config and state
double compute_remaining_time(double age, uint64_t sent)
{
	if (!zsend.complete) {
		double remaining[] = {INFINITY, INFINITY, INFINITY};
		if (zsend.targets) {
			double done = (double) sent/zsend.targets;
			remaining[0] = (1. - done)*(age/done) + zconf.cooldown_secs;
		}
		if (zconf.max_runtime) {
			remaining[1] = (zconf.max_runtime - age)+zconf.cooldown_secs;
		}
		if (zconf.max_results) {
			double done = (double)zrecv.success_unique/zconf.max_results;
			remaining[2] = (1. - done)*(age/done);
		}
		return min_d(remaining, sizeof(remaining)/sizeof(double));
	} else {
		return zconf.cooldown_secs - (now() - zsend.finish);
	}
}

static void monitor_update(iterator_t *it, pthread_mutex_t *recv_ready_mutex)
{
	uint32_t total_sent = iterator_get_sent(it);
	if (last_now > 0.0) {
		double age = now() - zsend.start;
		double delta = now() - last_now;
		double remaining_secs = compute_remaining_time(age, total_sent);
		double percent_complete = 100.*age/(age + remaining_secs);


		// ask pcap for fresh values
		pthread_mutex_lock(recv_ready_mutex);
		recv_update_pcap_stats();
		pthread_mutex_unlock(recv_ready_mutex);

		// format times for display
		char time_left[20];
		if (age < 5) {
			time_left[0] = '\0';
		} else {
			char buf[20];
			time_string((int)remaining_secs, 1, buf, sizeof(buf));
			snprintf(time_left, sizeof(time_left), " (%s left)", buf);
		}
		char time_past[20];
		time_string((int)age, 0, time_past, sizeof(time_past));

		char send_rate[20], send_avg[20],
			 recv_rate[20], recv_avg[20],
			 pcap_drop[20], pcap_drop_avg[20];
		// recv stats
		number_string((zrecv.success_unique - last_rcvd)/delta,
						recv_rate, sizeof(recv_rate));
		number_string((zrecv.success_unique/age), recv_avg, sizeof(recv_avg));
		// dropped stats
		number_string((zrecv.pcap_drop + zrecv.pcap_ifdrop - last_drop)/delta,
						pcap_drop, sizeof(pcap_drop));
		number_string(((zrecv.pcap_drop + zrecv.pcap_ifdrop)/age),
						pcap_drop_avg, sizeof(pcap_drop_avg));

		// Warn if we drop > 5% of our average receive rate
		uint32_t drop_rate = (uint32_t)((zrecv.pcap_drop + zrecv.pcap_ifdrop - last_drop) / delta);
		if (drop_rate > (uint32_t)((zrecv.success_unique - last_rcvd) / delta) / 20) {
			log_warn("monitor", "Dropped %d packets in the last second, (%d total dropped (pcap: %d + iface: %d))",
					 drop_rate, zrecv.pcap_drop + zrecv.pcap_ifdrop, zrecv.pcap_drop, zrecv.pcap_ifdrop);
		}	

		// Warn if we fail to send > 1% of our average send rate
		uint32_t fail_rate = (uint32_t)((zsend.sendto_failures - last_failures) / delta); // failures/sec
		if (fail_rate > ((total_sent / age) / 100)) {
			log_warn("monitor", "Failed to send %d packets/sec (%d total failures)",
					 fail_rate, zsend.sendto_failures);
		}
		float hits;
		if (!total_sent) {
			hits = 0;
		} else {
			hits = zrecv.success_unique*100./total_sent;
		}
		if (!zsend.complete) {
			// main display (during sending)
			number_string((total_sent - last_sent)/delta,
							send_rate, sizeof(send_rate));
			number_string((total_sent/age), send_avg, sizeof(send_avg));
			fprintf(stderr,
					"%5s %0.0f%%%s; send: %u %sp/s (%sp/s avg); "
					"recv: %u %sp/s (%sp/s avg); "
					"drops: %sp/s (%sp/s avg); "
					"hits: %0.2f%%\n", 
					time_past,
					percent_complete,
					time_left,
					total_sent,
					send_rate,
					send_avg,
					zrecv.success_unique,
					recv_rate,
					recv_avg,
					pcap_drop,
					pcap_drop_avg,
					hits);
		} else {
		  	// alternate display (during cooldown)
			number_string((total_sent/(zsend.finish - zsend.start)), send_avg, sizeof(send_avg));
			fprintf(stderr, 
					"%5s %0.0f%%%s; send: %u done (%sp/s avg); "
					"recv: %u %sp/s (%sp/s avg); "
					"drops: %sp/s (%sp/s avg); "
					"hits: %0.2f%%\n", 
					time_past,
					percent_complete,
					time_left,
					total_sent,
					send_avg,
					zrecv.success_unique,
					recv_rate,
					recv_avg,
					pcap_drop,
					pcap_drop_avg,
					hits);
		}
	}
	last_now  = now();
	last_sent = total_sent;
	last_rcvd = zrecv.success_unique;
	last_drop = zrecv.pcap_drop + zrecv.pcap_ifdrop;
	last_failures = zsend.sendto_failures;
}

void monitor_run(iterator_t *it, pthread_mutex_t *lock)
{
	while (!(zsend.complete && zrecv.complete))  {
		monitor_update(it, lock);
		sleep(UPDATE_INTERVAL);
	}
}

