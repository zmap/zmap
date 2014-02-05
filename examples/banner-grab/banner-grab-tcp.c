/*
 * Banner Grab Copyright 2013 Regents of the University of Michigan 
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "logger.h"

#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ulimit.h>

#define MAX_BANNER_LEN 1024
#define BASE64_ALPHABET  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

struct config {
	uint16_t port;
	int connect_timeout;	// how long to wait for connecting (seconds)
	int read_timeout;		// how long to wait once connected for the banner (seconds)
	int current_running;
	int max_concurrent;
	struct event_base *base;
	struct bufferevent *stdin_bev;
	int stdin_closed;
	enum {FORMAT_HEX, FORMAT_BASE64, FORMAT_ASCII} format;
	char *send_str;
	long send_str_size;

	struct stats_st {
		int init_connected_hosts;	// Number of hosts we have even tried to connect to
		int connected_hosts;		// # hosts that picked up
		int conn_timed_out;			// # hosts that timed out during connection
		int read_timed_out;			// # hosts that connected, but sent no data (banner)
		int timed_out;				// # hosts that timed out at all (conn_timed_out+read_timed_out)?
		int completed_hosts;		// # hosts that presented a banner
	} stats;
};


struct state {
	struct config *conf;
	uint32_t ip;
	enum {CONNECTING, CONNECTED, RECEIVED} state;
};

void stdin_readcb(struct bufferevent *bev, void *arg);

void print_status(evutil_socket_t fd, short events, void *arg)
{
	struct event *ev;
	struct config *conf = arg;
	struct event_base *base = conf->base;
	struct timeval status_timeout = {1, 0};
	ev = evtimer_new(base, print_status, conf);
	evtimer_add(ev, &status_timeout);
	(void)fd; (void)events;

	log_info("banner-grab-tcp", "(%d/%d in use) - Totals: %d inited, %d connected, %d conn timeout, %d read timeout %d completed", 
			conf->current_running, conf->max_concurrent, 
			conf->stats.init_connected_hosts,
			conf->stats.connected_hosts, conf->stats.conn_timed_out, 
			conf->stats.read_timed_out, conf->stats.completed_hosts);
}

void decrement_cur_running(struct state *st)
{	
	struct config *conf = st->conf;
	conf->current_running--;
	log_debug("banner-grab-tcp", "done, down to %d",
			conf->current_running);
	if (evbuffer_get_length(bufferevent_get_input(conf->stdin_bev)) > 0) {
		stdin_readcb(conf->stdin_bev, conf);
	}
	free(st);

	if (conf->stdin_closed && conf->current_running == 0) {
		// Done
		log_info("banner-grab-tcp", "done");
		print_status(0, 0, conf);
		exit(0);
	}

}

void connect_cb(struct bufferevent *bev, short events, void *arg)
{
	struct state *st = arg;
	struct config *conf = st->conf;
	struct in_addr addr;
	addr.s_addr = st->ip;
	if (events & BEV_EVENT_CONNECTED) {
		struct timeval tv = {st->conf->read_timeout, 0};
		log_debug("banner-grab-tcp", "%s connected", inet_ntoa(addr));
	
		// Send data
		if (conf->send_str) {
			struct evbuffer *evout = bufferevent_get_output(bev);
			// HACK!!! TODO: make some messy parser that replaces ${IP} with IP etc
			// and allow null characters
			evbuffer_add_printf(evout, conf->send_str,
					inet_ntoa(addr), inet_ntoa(addr), inet_ntoa(addr), inet_ntoa(addr));	
		}

		// Change from connect timeout to read timeout
		bufferevent_set_timeouts(bev, &tv, &tv);

		// Update state/stats
		st->state = CONNECTED;
		st->conf->stats.connected_hosts++;
	} else {
		if (st->state == CONNECTED) {
			// Print out that we just didn't receive data
			printf("%s X\n", inet_ntoa(addr));
			fflush(stdout);

			st->conf->stats.read_timed_out++;
		} else {
			st->conf->stats.conn_timed_out++;
		}
		log_debug("banner-grab-tcp", "%s bailing..", inet_ntoa(addr));
		bufferevent_free(bev);
		st->conf->stats.timed_out++;
		decrement_cur_running(st);
	}
}

// Grab these bytes, and close the connection.
// Even if we don't need to read any bytes,
// we have to have this so that libevent thinks we have
// a read event, so that it can timeout TCP connects
// (as a read timeout)
void read_cb(struct bufferevent *bev, void *arg)
{
	struct evbuffer *in = bufferevent_get_input(bev);
	struct state *st = arg;
	size_t len = evbuffer_get_length(in);
	struct in_addr addr;
	addr.s_addr = st->ip;

	log_debug("banner-grab-tcp", "read_cb for %s", inet_ntoa(addr));

	if (len > MAX_BANNER_LEN) {
		len = MAX_BANNER_LEN;
	}

	if (len > 0) {
		// Grab the banner	
		unsigned int i;
		unsigned char *buf = malloc(len+1);

		st->state = RECEIVED;

		if (!buf) {
			log_fatal("banner-grab-tcp", "cannot alloc %d byte buf", len+1);
			return;
		}
		evbuffer_remove(in, buf, len);
		
		printf("%s ", inet_ntoa(addr));

		if (st->conf->format == FORMAT_ASCII) {
			// Ascii
			buf[len] = '\0';
			printf("%s\n", buf);
		} else if (st->conf->format == FORMAT_HEX) {
			// Hex output
			for (i=0; i<len; i++) {
				printf("%02x", buf[i]);
			}
			printf("\n");
		} else if (st->conf->format == FORMAT_BASE64) {
			// Base64
			int i=0;
			char out[4] = {0,0,0,0};
			while (i < len) {
				uint32_t value = 0;
				value += (i < len) ? buf[i++] << 16 : 0; 	
				value += (i < len) ? buf[i++] <<  8 : 0;
				value += (i < len) ? buf[i++]       : 0;
				out[0] = BASE64_ALPHABET[(value >> 18) & 0x3F];
				out[1] = BASE64_ALPHABET[(value >> 12) & 0x3F];                                                                           
				out[2] = BASE64_ALPHABET[(value >>  6) & 0x3F];
				out[3] = BASE64_ALPHABET[(value      ) & 0x3F];
				if (i < len) {
					printf("%c%c%c%c", out[0], out[1], out[2], out[3]);
				}
			}
			if (len > 0) {
				switch (len % 3) {
				case 1:
					out[2] = '=';
				case 2:
					out[3] = '=';
				default:
					break;
				}
				printf("%c%c%c%c\n", out[0], out[1], out[2], out[3]);
			}
		}
		fflush(stdout);

		free(buf);
		st->conf->stats.completed_hosts++;
	}
	bufferevent_free(bev);
	decrement_cur_running(st);
}

void grab_banner(struct state *st)
{
	struct sockaddr_in addr;
	struct bufferevent *bev;
	struct timeval read_to = {st->conf->connect_timeout, 0};

	addr.sin_family = AF_INET;
	addr.sin_port = htons(st->conf->port);
	addr.sin_addr.s_addr = st->ip;
	log_debug("banner-grab-tcp", "connect %s:%d", 
			  inet_ntoa(addr.sin_addr), st->conf->port);

	bev = bufferevent_socket_new(st->conf->base, -1, BEV_OPT_CLOSE_ON_FREE);

	bufferevent_set_timeouts(bev, &read_to, &read_to);

	bufferevent_setcb(bev, read_cb, NULL, connect_cb, st);
	bufferevent_enable(bev, EV_READ);

	st->state = CONNECTING;

	st->conf->stats.init_connected_hosts++;

	if (bufferevent_socket_connect(bev, 
		(struct sockaddr *)&addr, sizeof(addr)) < 0) {
		log_warn("banner-grab-tcp", "could not connect socket %d (%d open) %d %d", 
			bufferevent_getfd(bev), st->conf->current_running, errno, ENFILE);
		perror("connect");

		
		bufferevent_free(bev);
		decrement_cur_running(st);
		return;
	}
}

void stdin_eventcb(struct bufferevent *bev, short events, void *ptr) {
	struct config *conf = ptr;

	if (events & BEV_EVENT_EOF) {
		log_debug("banner-grab-tcp", 
				  "received EOF; quitting after buffer empties");
		conf->stdin_closed = 1; 
		if (conf->current_running == 0) {
			log_info("banner-grab-tcp", "done");
			print_status(0, 0, conf);
			exit(0);
		}
	} 
}

void stdin_readcb(struct bufferevent *bev, void *arg)
{
	struct evbuffer *in = bufferevent_get_input(bev);
	struct config *conf = arg;

	log_debug("banner-grab-tcp", "stdin cb %d < %d ?", 
		conf->current_running, conf->max_concurrent);

	while (conf->current_running < conf->max_concurrent && 
		   evbuffer_get_length(in) > 0) {
		char *ip_str;
		size_t line_len;
		char *line = evbuffer_readln(in, &line_len, EVBUFFER_EOL_LF);
		struct state *st;
		if (!line)
			break;
		log_debug("banner-grab-tcp", "line: %s", line);

		ip_str = line;
		/*
		port_str = strstr(line, ":") + 1;
		if (!port_str)
			port_str = strstr(line, " ") + 1;
		if (!port_str)
			break;

		*(port_str-1) = '\0';
		port = atoi(port_str);
		*/
		//printf("scanning %s:%d\n", ip
		
		conf->current_running++;
		st = malloc(sizeof(*st));
		st->conf = conf;
		st->ip = inet_addr(ip_str);
		grab_banner(st);
	}
}

int main(int argc, char *argv[])
{
	struct event_base *base;
	struct event *status_timer;
	struct timeval status_timeout = {1, 0};
	int c;
	struct option long_options[] = {
		{"concurrent", required_argument, 0, 'c'},
		{"port", required_argument, 0, 'p'},
		{"conn-timeout", required_argument, 0, 't'},
		{"read-timeout", required_argument, 0, 'r'},
		{"verbosity", required_argument, 0, 'v'},
		{"format", no_argument, 0, 'f'},
		{"data", required_argument, 0, 'd'},
		{0, 0, 0, 0} };

	struct config conf;
	int ret;
	FILE *fp;

	log_init(stderr, LOG_INFO, 0, "banner-grab");

	ret = ulimit(4, 1000000);	// Allow us to open 1 million fds (instead of 1024)
	if (ret < 0) {
		log_fatal("banner-grab-tcp", "cannot set ulimit");
		perror("ulimit");
		exit(1);
	}

	base = event_base_new();
	conf.base = base;

	// buffer stdin as an event
	conf.stdin_bev = bufferevent_socket_new(base, 0, BEV_OPT_DEFER_CALLBACKS);
	bufferevent_setcb(conf.stdin_bev, stdin_readcb, NULL, stdin_eventcb, &conf);
	bufferevent_enable(conf.stdin_bev, EV_READ);

	// Status timer
	status_timer = evtimer_new(base, print_status, &conf);
	evtimer_add(status_timer, &status_timeout);

	// Defaults
	conf.max_concurrent = 1;
	conf.current_running = 0;
	memset(&conf.stats, 0, sizeof(conf.stats));
	conf.connect_timeout = 4;
	conf.read_timeout = 4;
	conf.stdin_closed = 0;
	conf.format = FORMAT_BASE64;
	conf.send_str = NULL;

	// Parse command line args
	while (1) {
		int option_index = 0;
		c = getopt_long(argc, argv, "c:p:t:r:v:f:d:",
				long_options, &option_index);

		if (c < 0) {
			break;
		}

		switch (c) {
		case 'c':
			conf.max_concurrent = atoi(optarg);
			break;
		case 'p':
			conf.port = atoi(optarg);
			break;
		case 't':
			conf.connect_timeout = atoi(optarg);
			break;
		case 'r':
			conf.read_timeout = atoi(optarg);
			break;
		case 'v':
			if (atoi(optarg) >= 0 && atoi(optarg) <= 5) {
				log_init(stderr, atoi(optarg), 0, "banner-grab");
			}
			break;
		case 'f':
			if (strcmp(optarg, "hex") == 0) {
				conf.format = FORMAT_HEX;
			} else if (strcmp(optarg, "base64") == 0) {
				conf.format = FORMAT_BASE64;
			} else if (strcmp(optarg, "ascii") == 0) {
				conf.format = FORMAT_ASCII;
			} else {
				log_fatal("banner-grab-tcp", "Unknown format '%s'; use 'hex', 'base64', or 'ascii'",
						  optarg);
			}
			break;
		case 'd':
			fp = fopen(optarg, "r");
			if (!fp) {
				log_error("banner-grab-tcp", "Could not open send data file '%s':", optarg);
				perror("fopen");
				exit(-1);
			}
			fseek(fp, 0L, SEEK_END);
			conf.send_str_size = ftell(fp);
			fseek(fp, 0L, SEEK_SET);
			//assert(conf.send_str_size < 10000);	// jumbo frames?
			conf.send_str = malloc(conf.send_str_size+1);
			if (!conf.send_str) {
				log_fatal("banner-grab-tcp", "Could not malloc %d bytes", conf.send_str_size+1);
			}
			if (fread(conf.send_str, conf.send_str_size, 1, fp) != 1) {
				log_fatal("banner-grab-tcp", "Couldn't read from send data file '%s':", optarg);
			}
			conf.send_str[conf.send_str_size] = '\0';
			fclose(fp);	
			break;
		case '?':
			printf("Usage:\n");
			printf("\t%s [-c max_concurrency] [-t connect_timeout] [-r read_timeout] \n\t"
				   "[-v verbosity=0-5] [-d send_data_file] [-f ascii|hex|base64] -p port\n", argv[0]);
			exit(1);
		default:
			log_info("banner-grab-tcp", "hmmm..");
			break;
		}
	}
	
	log_info("banner-grab-tcp", "Using port %d with max_concurrency %d, %d s conn timeout, %d s read timeout",
			conf.port, conf.max_concurrent, conf.connect_timeout, conf.read_timeout);

	event_base_dispatch(base);

	return 0;
}

