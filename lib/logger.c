/*
 * Logger Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sys/time.h>
#include <time.h>
#include <syslog.h>
#include <math.h>
#include <pthread.h>

#include "logger.h"
#include "xalloc.h"
#include "lockfd.h"

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static enum LogLevel log_output_level = ZLOG_INFO;

static FILE *log_output_stream = NULL;
static int color = 0;

static int log_to_syslog = 0;

static const char *log_level_name[] = {"FATAL", "ERROR", "WARN",
				       "INFO",  "DEBUG", "TRACE"};

#define RED "\x1b[31m"
#define GREEN "\x1b[32m"
#define YELLOW "\x1b[33m"
#define BLUE "\x1b[34m"
#define MAGENTA "\x1b[35m"
#define CYAN "\x1b[36m"
#define RESET "\033[0m"

#define COLOR(x)                                                               \
	do {                                                                   \
		if (color)                                                     \
			fprintf(log_output_stream, "%s", x);                   \
	} while (0)

static const char *color_for_level(enum LogLevel level)
{
	switch (level) {
	case ZLOG_FATAL:
		return RED;
	case ZLOG_ERROR:
		return MAGENTA;
	case ZLOG_WARN:
		return YELLOW;
	case ZLOG_INFO:
		return GREEN;
	case ZLOG_DEBUG:
		return BLUE;
	case ZLOG_TRACE:
		return RESET;
	default:
		return RESET;
	}
}

static int LogLogVA(enum LogLevel level, const char *loggerName,
		    const char *logMessage, va_list args)
{
	if (level <= log_output_level) {
		if (!log_output_stream) {
			log_output_stream = stderr;
		}
		// if logging to a shared output channel, then use a global
		// lock across ZMap. Otherwise, if we're logging to a file,
		// only lockin with the module, in order to avoid having
		// corrupt log entries.
		if (log_output_stream == stdout ||
		    log_output_stream == stderr) {
			lock_file(log_output_stream);
		} else {
			pthread_mutex_lock(&mutex);
		}
		if (color) {
			COLOR(color_for_level(level));
		}

		const char *levelName = log_level_name[level];
		struct timeval now;
		char timestamp[256];
		gettimeofday(&now, NULL);
		time_t sec = now.tv_sec;
		struct tm *ptm = localtime(&sec);
		strftime(timestamp, 20, "%b %d %H:%M:%S", ptm);
		fprintf(log_output_stream, "%s.%03ld [%s] ", timestamp,
			(long)now.tv_usec / 1000, levelName);
		if (loggerName) {
			fprintf(log_output_stream, "%s: ", loggerName);
		}
		if (logMessage) {
			vfprintf(log_output_stream, logMessage, args);
		}
		if (loggerName || logMessage) {
			fputs("\n", log_output_stream);
		}
		if (color) {
			COLOR(RESET);
		}
		fflush(log_output_stream);
		if (log_output_stream == stdout ||
		    log_output_stream == stderr) {
			unlock_file(log_output_stream);
		} else {
			pthread_mutex_unlock(&mutex);
		}
	}
	return EXIT_SUCCESS;
}

int log_fatal(const char *name, const char *message, ...)
{
	va_list va;
	va_start(va, message);
	LogLogVA(ZLOG_FATAL, name, message, va);
	va_end(va);

	if (log_to_syslog) {
		va_start(va, message);
		vsyslog(LOG_MAKEPRI(LOG_USER, LOG_CRIT), message, va);
		va_end(va);
	}

	exit(EXIT_FAILURE);
}

int log_error(const char *name, const char *message, ...)
{
	va_list va;
	va_start(va, message);
	int ret = LogLogVA(ZLOG_ERROR, name, message, va);
	va_end(va);

	if (log_to_syslog) {
		va_start(va, message);
		vsyslog(LOG_MAKEPRI(LOG_USER, LOG_ERR), message, va);
		va_end(va);
	}

	return ret;
}

int log_warn(const char *name, const char *message, ...)
{
	va_list va;
	va_start(va, message);
	int ret = LogLogVA(ZLOG_WARN, name, message, va);
	va_end(va);

	if (log_to_syslog) {
		va_start(va, message);
		vsyslog(LOG_MAKEPRI(LOG_USER, LOG_WARNING), message, va);
		va_end(va);
	}

	return ret;
}

int log_info(const char *name, const char *message, ...)
{
	va_list va;
	va_start(va, message);
	int ret = LogLogVA(ZLOG_INFO, name, message, va);
	va_end(va);

	char *prefixed = xmalloc(strlen(name) + strlen(message) + 3);
	strcpy(prefixed, name);
	strcat(prefixed, ": ");
	strcat(prefixed, message);

	if (log_to_syslog) {
		va_start(va, message);
		vsyslog(LOG_MAKEPRI(LOG_USER, LOG_INFO), prefixed, va);
		va_end(va);
	}

	free(prefixed);

	return ret;
}

int log_debug(const char *name, const char *message, ...)
{
	va_list va;
	va_start(va, message);
	int ret = LogLogVA(ZLOG_DEBUG, name, message, va);
	va_end(va);

	char *prefixed = xmalloc(strlen(name) + strlen(message) + 3);
	strcpy(prefixed, name);
	strcat(prefixed, ": ");
	strcat(prefixed, message);

	if (log_to_syslog) {
		va_start(va, message);
		vsyslog(LOG_MAKEPRI(LOG_USER, LOG_DEBUG), prefixed, va);
		va_end(va);
	}

	free(prefixed);

	return ret;
}

#ifdef DEBUG
extern int log_trace(const char *name, const char *message, ...)
{
	va_list va;
	va_start(va, message);
	int ret = LogLogVA(ZLOG_TRACE, name, message, va);
	va_end(va);

	char *prefixed = xmalloc(strlen(name) + strlen(message) + 3);
	strcpy(prefixed, name);
	strcat(prefixed, ": ");
	strcat(prefixed, message);

	if (log_to_syslog) {
		va_start(va, message);
		vsyslog(LOG_MAKEPRI(LOG_USER, LOG_DEBUG), prefixed, va);
		va_end(va);
	}

	free(prefixed);

	return ret;
}
#endif

int log_init(FILE *stream, enum LogLevel level, int syslog_enabled,
	     const char *appname)
{
	log_output_stream = stream;
	log_output_level = level;
	if (syslog_enabled) {
		log_to_syslog = 1;
		openlog(appname, 0, LOG_USER); // no options
	}
	if (isatty(fileno(log_output_stream))) {
		color = 1;
	}
	return 0;
}

void check_and_log_file_error(FILE *file, const char *name)
{
	if (ferror(file)) {
		log_fatal(name, "unable to write to file");
	}
}

double now(void)
{
	struct timeval now;
	gettimeofday(&now, NULL);
	return (double)now.tv_sec + (double)now.tv_usec / 1000000.;
}

size_t dstrftime(char *buf, size_t maxsize, const char *format, double tm)
{
	struct timeval tv;
	double tm_floor;
	tm_floor = floor(tm);
	tv.tv_sec = (long)tm_floor;
	tv.tv_usec = (long)(tm - floor(tm)) * 1000000;
	return strftime(buf, maxsize, format, localtime((const time_t *)&tv));
}
