/*
 * logger.h — Structured logging API for the Sentinel daemon.
 * Dual output: syslog (LOG_DAEMON) + rotating log file.
 */

#ifndef SENTINEL_LOGGER_H
#define SENTINEL_LOGGER_H

#include <stdio.h>

/* Log severity levels */
typedef enum {
    LOG_LVL_INFO,
    LOG_LVL_WARN,
    LOG_LVL_ERROR
} log_level_t;

/* Default log file path */
#define SENTINEL_LOG_FILE "/var/log/sentinel.log"

/* Maximum log file size before rotation (5 MB) */
#define SENTINEL_LOG_MAX_SIZE (5 * 1024 * 1024)

/**
 * Initialise the logging subsystem.
 * Opens syslog and the log file.
 * Returns 0 on success, -1 on failure.
 */
int logger_init(const char *log_path);

/**
 * Shut down the logging subsystem.
 * Closes syslog and the log file handle.
 */
void logger_shutdown(void);

/**
 * Write a log entry at the given severity level.
 * printf-style format string is accepted.
 */
void logger_log(log_level_t level, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

/* Convenience macros */
#define log_info(...)  logger_log(LOG_LVL_INFO,  __VA_ARGS__)
#define log_warn(...)  logger_log(LOG_LVL_WARN,  __VA_ARGS__)
#define log_error(...) logger_log(LOG_LVL_ERROR, __VA_ARGS__)

#endif /* SENTINEL_LOGGER_H */
