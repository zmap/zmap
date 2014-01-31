#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>

#ifndef LOGGER_H
#define LOGGER_H

// do not collide with constants defined in syslog.h
enum LogLevel { ZLOG_FATAL, ZLOG_ERROR, ZLOG_WARN, ZLOG_INFO, ZLOG_DEBUG, ZLOG_TRACE,
					ZNUM_LOGLEVELS };

int log_fatal(const char *loggerName, const char *logMessage, ...) __attribute__((noreturn));

int log_error(const char *loggerName, const char *logMessage, ...);

int log_warn(const char *loggerName, const char *logMessage, ...);

int log_info(const char *loggerName, const char *logMessage, ...);

int log_debug(const char *loggerName, const char *logMessage, ...);

int log_trace(const char *loggerName, const char *logMessage, ...);

int log_init(FILE *stream, enum LogLevel level,
		int syslog_enabled, const char *syslog_app);

size_t dstrftime(char *, size_t, const char *, double);

double now();

#endif // _LOGGER_H

