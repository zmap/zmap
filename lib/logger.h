#include <stdio.h>
#include <stdarg.h>

#ifndef LOGGER_H
#define LOGGER_H

enum LogLevel { LOG_FATAL, LOG_ERROR, LOG_WARN, LOG_INFO, LOG_DEBUG, LOG_TRACE,
					NUM_LOGLEVELS };

int log_fatal(const char *loggerName, const char *logMessage, ...) __attribute__((noreturn));

int log_error(const char *loggerName, const char *logMessage, ...);

int log_warn(const char *loggerName, const char *logMessage, ...);

int log_info(const char *loggerName, const char *logMessage, ...);

int log_debug(const char *loggerName, const char *logMessage, ...);

int log_trace(const char *loggerName, const char *logMessage, ...);

int log_init(FILE *stream, enum LogLevel level);

size_t dstrftime(char *, size_t, const char *, double);

double now();

#endif // _LOGGER_H

