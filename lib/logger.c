/*
 * Logger Copyright 2013 Regents of the University of Michigan 
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */
 
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sys/time.h>
#include <time.h>
#include <math.h>

#include "logger.h"

#ifndef HEADER_ZUTIL_LOGGER_H
#define HEADER_ZUTIL_LOGGER_H

static enum LogLevel log_output_level = LOG_INFO;

static FILE *log_output_stream = NULL;

static const char *log_level_name[] = { 
	"FATAL", "ERROR", "WARN", "INFO", "DEBUG", "TRACE" };

static int LogLogVA(enum LogLevel level, const char *loggerName,
		const char *logMessage, va_list args)
{
	if (!log_output_stream) {
		log_output_stream = stdout;
	}
	if (level <= log_output_level) {
		const char *levelName = log_level_name[level];

		struct timeval now;
		char timestamp[256];
		gettimeofday(&now, NULL);
		time_t sec = now.tv_sec;
		struct tm* ptm = localtime(&sec);
		strftime(timestamp, 20, "%b %d %H:%M:%S", ptm);
		fprintf(log_output_stream, "%s.%03ld [%s] ", 
				timestamp, (long) now.tv_usec/1000, levelName);
		if (loggerName) {
			fprintf(log_output_stream, "%s: ", loggerName);
		}
		if (logMessage) {
			vfprintf(log_output_stream, logMessage, args);
		}
		if (loggerName || logMessage) {
			fputs("\n", log_output_stream);
		}
		fflush(log_output_stream);
	}
	return 0;
}

int log_fatal(const char *name, const char *message, ...) {
	va_list va; va_start(va, message);
	LogLogVA(LOG_FATAL, name, message, va);
	va_end(va);
	exit(EXIT_FAILURE);
}

int log_error(const char *name, const char *message, ...) {
	va_list va; va_start(va, message);
	int ret = LogLogVA(LOG_ERROR, name, message, va);
	va_end(va);
	return ret;
}

int log_warn(const char *name, const char *message, ...) {
	va_list va; va_start(va, message);
	int ret = LogLogVA(LOG_WARN, name, message, va);
	va_end(va);
	return ret;
}

int log_info(const char *name, const char *message, ...) {
	va_list va; va_start(va, message);
	int ret = LogLogVA(LOG_INFO, name, message, va);
	va_end(va);
	return ret;
}

int log_debug(const char *name, const char *message, ...) {
	va_list va; va_start(va, message);
	int ret = LogLogVA(LOG_DEBUG, name, message, va);
	va_end(va);
	return ret;
}

extern int log_trace(const char *name, const char *message, ...) {
	va_list va; va_start(va, message);
	int ret = LogLogVA(LOG_TRACE, name, message, va);
	va_end(va);
	return ret;
}

int log_init(FILE *stream, enum LogLevel level)
{
	log_output_stream = stream;
	log_output_level = level;
	return 0;
}

double now(void)
{
	struct timeval now;     
	gettimeofday(&now, NULL);       
	return (double)now.tv_sec + (double)now.tv_usec/1000000.;
}

size_t dstrftime(char *buf, size_t maxsize, const char *format, double tm)
{
	struct timeval tv;
	double tm_floor;
	tm_floor = floor(tm);
	tv.tv_sec = (long) tm_floor;
	tv.tv_usec = (long) (tm - floor(tm)) * 1000000;
	return strftime(buf, maxsize, format, localtime((const time_t*) &tv));
}

#endif
