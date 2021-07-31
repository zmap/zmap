/*
 * Copyright 2021 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>

#ifndef LOGGER_H
#define LOGGER_H

#ifdef __cplusplus
extern "C" {
#endif

// do not collide with constants defined in syslog.h
enum LogLevel {
	ZLOG_FATAL,
	ZLOG_ERROR,
	ZLOG_WARN,
	ZLOG_INFO,
	ZLOG_DEBUG,
	ZLOG_TRACE,
	ZNUM_LOGLEVELS
};

int log_fatal(const char *loggerName, const char *logMessage, ...)
    __attribute__((noreturn));

int log_error(const char *loggerName, const char *logMessage, ...);

int log_warn(const char *loggerName, const char *logMessage, ...);

int log_info(const char *loggerName, const char *logMessage, ...);

int log_debug(const char *loggerName, const char *logMessage, ...);

#ifdef DEBUG
int log_trace(const char *loggerName, const char *logMessage, ...);
#else
#define log_trace(...) ;
#endif

int log_init(FILE *stream, enum LogLevel level, int syslog_enabled,
	     const char *syslog_app);

void check_and_log_file_error(FILE *file, const char *name);

size_t dstrftime(char *, size_t, const char *, double);

double now();

#ifdef __cplusplus
}
#endif

#endif // _LOGGER_H
