/*
* ZTee Copyright 2014 Regents of the University of Michigan
*
* Licensed under the Apache License, Version 2.0 (the "License"); you may not
* use this file except in compliance with the License. You may obtain a copy
* of the License at http://www.apache.org/licenses/LICENSE-2.0
*/

// without defining this, FreeBSD throws a warning.
#define _WITH_GETLINE
#include <stdio.h>

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <errno.h>
#include <getopt.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>

#include "../lib/lockfd.h"
#include "../lib/logger.h"
#include "../lib/queue.h"
#include "../lib/util.h"
#include "../lib/xalloc.h"
#include "../lib/csv.h"

#include "topt.h"

typedef enum file_format { FORMAT_CSV, FORMAT_JSON, FORMAT_RAW } format_t;
static const char *format_names[] = { "csv", "json", "raw" };

typedef struct ztee_conf {
	// Files
	char *output_filename;
	char *status_updates_filename;
	char *log_file_name;
	FILE *output_file;
	FILE *status_updates_file;
	FILE *log_file;

	// Log level
	int log_level;

	// Input formats
	format_t in_format;
	format_t out_format;

	// Output config
	int success_only;

	// Monitor config
	int monitor;

	// Field indices
	size_t ip_field;
	size_t success_field;

} ztee_conf_t;

static ztee_conf_t tconf;

static int print_from_csv(char *line);

static format_t test_input_format(char *line, size_t len) {
	// Check for empty input, remember line contains '\n'
	if (len < 2) {
		return FORMAT_RAW;
	}
	if (len >= 3) {
		// If the input is JSON, the line should look like
		// {.......}\n
		if (line[0] == '{' && line[len - 2] == '}') {
			return FORMAT_JSON;
		}
	}
	if (strchr(line, ',') != NULL) {
		return FORMAT_CSV;
	}
	return FORMAT_RAW;
}

int done = 0;
int process_done = 0;
int total_read_in = 0;
int read_in_last_sec = 0;
int total_written = 0;

double start_time;

pthread_t threads[3];

//one thread reads in
//one thread writes out and parses

//pops next element and determines what to do
//if zqueue_t is empty and read_in is finished, then
//it exits
void *process_queue (void* my_q);

//uses fgets to read from stdin and add it to the zqueue_t
void *read_in (void* my_q);

//does the same as find UP but finds only successful IPs, determined by the
//is_successful field and flag
void find_successful_IP (char* my_string);

//finds IP in the string of csv and sends it to stdout for zgrab
//you need to know what position is the csv string the ip field is in
//zero indexed
void find_IP (char* my_string);

//writes a csv string out to csv file
//fprintf(stderr, "Is empty inside if %i\n", is_empty(queue));
void write_out_to_file (char* data);

//figure out how many fields are present if it is a csv
void figure_out_fields (char* data);

//check that the output file is either in a csv form or json form
//throws error is it is not either
//NOTE: JSON OUTPUT NOT IMPLEMENTED
void output_file_is_csv();

void print_thread_error();

//monitor code for ztee
//executes every second
void *monitor_ztee(void *my_q);

#define SET_IF_GIVEN(DST,ARG) \
	{ if (args.ARG##_given) { (DST) = args.ARG##_arg; }; }
#define SET_BOOL(DST,ARG) \
	{ if (args.ARG##_given) { (DST) = 1; }; }

int main(int argc, char *argv[])
{
	struct gengetopt_args_info args;
	struct cmdline_parser_params *params;
	params = cmdline_parser_params_create();
	assert(params);
	params->initialize = 1;
	params->override = 0;
	params->check_required = 0;

	if (cmdline_parser_ext(argc, argv, &args, params) != 0) {
		exit(EXIT_SUCCESS);
	}

	signal(SIGPIPE, SIG_IGN);

	// Handle help text and version
	if (args.help_given) {
		cmdline_parser_print_help();
		exit(EXIT_SUCCESS);
	}
	if (args.version_given) {
		cmdline_parser_print_version();
		exit(EXIT_SUCCESS);
	}

	// Try opening the log file
	tconf.log_level = ZLOG_WARN;
	if (args.log_file_given) {
		tconf.log_file = fopen(args.log_file_arg, "w");
	} else {
		tconf.log_file = stderr;
	}

	// Check for an error opening the log file
	if (tconf.log_file == NULL) {
		log_init(stderr, tconf.log_level, 0, "ztee");
		log_fatal("ztee", "Could not open log file");
	}

	// Actually init the logging infrastructure
	log_init(tconf.log_file, tconf.log_level, 0, "ztee");

	// Check for an output file
	if (args.inputs_num < 1) {
		log_fatal("ztee", "No output file specified");
	}
	if (args.inputs_num > 1) {
		log_fatal("ztee", "Extra positional arguments starting with %s",
				args.inputs[1]);
	}

	tconf.output_filename = args.inputs[0];
	tconf.output_file = fopen(tconf.output_filename, "w");
	if (!tconf.output_file) {
		log_fatal("ztee", "Could not open output file %s, %s",
				tconf.output_filename, strerror(errno));
	}

	// Read actual options
	int raw = 0;
	SET_BOOL(tconf.success_only, success_only);
	SET_BOOL(tconf.monitor, monitor);
	SET_BOOL(raw, raw);

	// Open the status update file if necessary
	if (args.status_updates_file_given) {
		// Try to open the status output file
		char *filename = args.status_updates_file_arg;
		FILE *file = fopen(filename, "w");
		if (!file) {
			char *err = strerror(errno);
			log_fatal("ztee", "unable to open status updates file %s (%s)",
					filename, err);
		}
		// Set the variables in state
		tconf.status_updates_filename = filename;
		tconf.status_updates_file = file;
	}

	// Read the first line of the input file
	size_t first_line_len = 1024;
	char *first_line = xmalloc(first_line_len);
	if (getline(&first_line, &first_line_len, stdin) < 0) {
		log_fatal("ztee", "reading input to test format failed");
	}
	// Detect the input format
	if (!raw) {
		format_t format = test_input_format(first_line, first_line_len);
		log_info("ztee", "detected input format %s", format_names[format]);
		tconf.in_format = format;
	} else {
		tconf.in_format = FORMAT_RAW;
		log_info("ztee", "raw input");
	}

	if (tconf.in_format == FORMAT_JSON) {
		log_fatal("ztee", "json input not implemented");
	}

	// Find fields if needed
	char *header = strdup(first_line);
	int found_success = 0;
	int found_ip = 0;
	if (tconf.in_format == FORMAT_CSV) {
		static const char *success_names[] = { "success" };
		static const char *ip_names[] = { "saddr", "ip" };
		int success_idx = csv_find_index(header, success_names, 1);
		if (success_idx >= 0) {
			found_success = 1;
			tconf.success_field = (size_t) success_idx;
		}
		int ip_idx = csv_find_index(header, ip_names, 2);
		if (found_ip >= 0) {
			found_ip = 1;
			tconf.ip_field = (size_t) ip_idx;
		}
		if (!found_ip) {
			log_fatal("ztee", "Unable to find IP/SADDR field");
		}
	}



	if (tconf.success_only) {
		if (tconf.in_format != FORMAT_CSV) {
			log_fatal("ztee", "success filter requires csv input");
		}
		if (!found_success) {
			log_fatal("ztee", "Could not find success field");
		}
	}


	// Make the queue
	zqueue_t* queue = queue_init();
	assert(queue);

	// Add the first line to the queue if needed
	push_back(first_line, queue);

	// Start the regular read thread
	pthread_t read_thread;
	if (pthread_create(&read_thread, NULL, read_in, queue)) {
		log_fatal("ztee", "unable to start read thread");
	}

	// Record the start time
	start_time = now();

	// Start the process thread
	pthread_t process_thread;
	if (pthread_create(&process_thread, NULL, process_queue, queue)) {
		log_fatal("ztee", "unable to start process thread");
	}

	// Start the monitor thread if necessary, and join to it
	if (tconf.monitor || tconf.status_updates_file) {
		pthread_t monitor_thread;
		if (pthread_create(&monitor_thread, NULL, monitor_ztee, queue)) {
			log_fatal("ztee", "unable to create monitor thread");
		}
		pthread_join(monitor_thread, NULL);
	}

	// Join to the remaining threads,
	pthread_join(read_thread, NULL);
	pthread_join(process_thread, NULL);
	return 0;
}

void *process_queue(void* arg)
{
	zqueue_t *queue = arg;
	FILE *output_file = tconf.output_file;
	while (!process_done) {

		pthread_mutex_lock(&queue->lock);
		while (!done && is_empty(queue)) {
			pthread_cond_wait(&queue->empty, &queue->lock);
		}
		if (done && is_empty(queue)) {
			process_done = 1;
			pthread_mutex_unlock(&queue->lock);
			continue;
		}
		znode_t *node = pop_front_unsafe(queue);
		pthread_mutex_unlock(&queue->lock);


		// Write raw data to output file
		fprintf(output_file, "%s", node->data);
		fflush(output_file);
		if (ferror(output_file)) {
			log_fatal("ztee", "Error writing to output file");
		}

		// Dump to stdout
		switch (tconf.in_format) {
		case FORMAT_JSON:
			log_fatal("ztee", "JSON input format unimplemented");
			break;
		case FORMAT_CSV:
			print_from_csv(node->data);
			break;
		default:
			// Handle raw
			fprintf(stdout, "%s", node->data);
			break;
		}

		// Check to see if write failed
		fflush(stdout);
		if (ferror(stdout)) {
			log_fatal("ztee", "%s", "Error writing to stdout");
		}

		// Record output lines
		total_written++;

		// Free the memory
		free(node->data);
		free(node);
	}
	process_done = 1;
	fflush(output_file);
	fclose(output_file);
	return NULL;
}

void *read_in(void* arg)
{
	// Allocate buffers
	zqueue_t *queue = (zqueue_t*) arg;
	size_t length = 1000;
	char *input = xcalloc(sizeof(char), length);;

	// Read in from stdin and add to back of linked list
	while (getline(&input, &length, stdin) > 0) {
		push_back(input, queue);

		total_read_in++;
		read_in_last_sec++;
	}
	pthread_mutex_lock(&queue->lock);
	done = 1;
	pthread_cond_signal(&queue->empty);
	pthread_mutex_unlock(&queue->lock);
	return NULL;
}

int print_from_csv(char *line)
{
	if (total_written == 0) {
		return 1;
	}
	if (tconf.success_only) {
		char *success_entry = csv_get_index(line, tconf.success_field);
		if (success_entry == NULL) {
			return 1;
		}
		int success = 0;
		if (atoi(success_entry)) {
			success = 1;
		} else if (strcasecmp(success_entry, "true") == 0) {
			success = 1;
		}
		if (!success) {
			return 1;
		}
	}
	// Find the ip
	char *ip = csv_get_index(line, tconf.ip_field);
	int ret = fprintf(stdout, "%s\n", ip);
	if (ferror(stdout)) {
		log_fatal("ztee", "unable to write to stdout");
	}
	return ret;
}

void output_file_is_csv()
{
	return;
	/*
	char *dot = strrchr(output_filename);
	if dot == NULL {
		return;
	}
	*/
	/*
	int length = strlen(output_filename);
	char *end_of_file = malloc(sizeof(char*) *4);
	strncpy(end_of_file, output_filename+(length - 3), 3);
	end_of_file[4] = '\0';
	const char *csv = "csv\n";
	const char *json = "jso\n";
	if(!strncmp(end_of_file, csv, 3) && !strncmp(end_of_file, json, 3)){
		log_fatal("ztee", "Invalid output format");
	}
	if(!strncmp(end_of_file, csv, 3)) output_csv = 1;
	if(!strncmp(end_of_file, json, 3)) output_csv = 0;
	*/
}

void print_thread_error(char* string)
{
	fprintf(stderr, "Could not create thread %s\n", string);
	return;
}

#define TIME_STR_LEN 20

typedef struct ztee_stats {
	// Read stats
	uint32_t total_read;
	uint32_t read_per_sec_avg;
	uint32_t read_last_sec;

	// Buffer stats
	uint32_t buffer_cur_size;
	uint32_t buffer_avg_size;
	uint64_t _buffer_size_sum;

	// Duration
	double _last_age;
	uint32_t time_past;
	char time_past_str[TIME_STR_LEN];
} stats_t;

void update_stats(stats_t *stats, zqueue_t *queue)
{
	double age = now() - start_time;
	double delta = age - stats->_last_age;
	stats->_last_age = age;

	stats->time_past = age;
	time_string((int)age, 0, stats->time_past_str, TIME_STR_LEN);

	uint32_t total_read = total_read_in;
	stats->read_last_sec = (total_read - stats->total_read) / delta;
	stats->total_read = total_read;
	stats->read_per_sec_avg = stats->total_read / age;

	stats->buffer_cur_size = get_size(queue);
	stats->_buffer_size_sum += stats->buffer_cur_size;
	stats->buffer_avg_size = stats->_buffer_size_sum / age;
}

void *monitor_ztee(void* arg)
{
	zqueue_t *queue = (zqueue_t *) arg;
	stats_t *stats = xmalloc(sizeof(stats_t));

	if (tconf.status_updates_file) {
		fprintf(tconf.status_updates_file,
				"time_past,total_read_in,read_in_last_sec,read_per_sec_avg,"
				"buffer_current_size,buffer_avg_size\n");
		fflush(tconf.status_updates_file);
		if (ferror(tconf.status_updates_file)) {
			log_fatal("ztee", "unable to write to status updates file");
		}
	}
	while (!process_done) {
		sleep(1);

		update_stats(stats, queue);
		if (tconf.monitor) {
			lock_file(stderr);
			fprintf(stderr, "%5s read_rate: %u rows/s (avg %u rows/s), buffer_size: %u (avg %u)\n",
					stats->time_past_str,
					stats->read_last_sec,
					stats->read_per_sec_avg,
					stats->buffer_cur_size,
					stats->buffer_avg_size);
			fflush(stderr);
			unlock_file(stderr);
			if (ferror(stderr)) {
				log_fatal("ztee", "unable to write status updates to stderr");
			}
		}
		if (tconf.status_updates_file) {
			fprintf(tconf.status_updates_file, "%u,%u,%u,%u,%u,%u\n",
					stats->time_past,
					stats->total_read,
					stats->read_last_sec,
					stats->read_per_sec_avg,
					stats->buffer_cur_size,
					stats->buffer_avg_size);
			fflush(tconf.status_updates_file);
			if (ferror(tconf.status_updates_file)) {
				log_fatal("ztee", "unable to write to status updates file");
			}
		}
	}
	if (tconf.monitor) {
		lock_file(stderr);
		fflush(stderr);
		unlock_file(stderr);
	}
	if (tconf.status_updates_file) {
		fflush(tconf.status_updates_file);
		fclose(tconf.status_updates_file);
	}
	return NULL;
}
