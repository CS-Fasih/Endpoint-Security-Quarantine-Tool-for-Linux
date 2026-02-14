/*
 * logger.c — Dual-output logging: syslog + rotating log file.
 *
 * Part of the Sentinel Endpoint Security daemon.
 */

#include "logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <syslog.h>
#include <pthread.h>

/* ── Private state ──────────────────────────────────────────────────────── */

static FILE          *s_logfile    = NULL;
static char           s_logpath[512];
static pthread_mutex_t s_log_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ── Helpers ────────────────────────────────────────────────────────────── */

static const char *level_str(log_level_t lvl)
{
    switch (lvl) {
    case LOG_LVL_INFO:  return "INFO";
    case LOG_LVL_WARN:  return "WARN";
    case LOG_LVL_ERROR: return "ERROR";
    default:            return "????";
    }
}

static int level_to_syslog(log_level_t lvl)
{
    switch (lvl) {
    case LOG_LVL_INFO:  return LOG_INFO;
    case LOG_LVL_WARN:  return LOG_WARNING;
    case LOG_LVL_ERROR: return LOG_ERR;
    default:            return LOG_DEBUG;
    }
}

/* Rotate the log file if it exceeds the size limit. */
static void maybe_rotate(void)
{
    if (!s_logfile) return;

    struct stat st;
    if (fstat(fileno(s_logfile), &st) == 0 &&
        st.st_size >= SENTINEL_LOG_MAX_SIZE) {

        fclose(s_logfile);

        char backup[520];
        snprintf(backup, sizeof(backup), "%s.1", s_logpath);
        rename(s_logpath, backup);                    /* best-effort */

        s_logfile = fopen(s_logpath, "a");
    }
}

/* ── Public API ─────────────────────────────────────────────────────────── */

int logger_init(const char *log_path)
{
    const char *path = log_path ? log_path : SENTINEL_LOG_FILE;
    snprintf(s_logpath, sizeof(s_logpath), "%s", path);

    openlog("sentinel", LOG_PID | LOG_NDELAY, LOG_DAEMON);

    s_logfile = fopen(s_logpath, "a");
    if (!s_logfile) {
        syslog(LOG_ERR, "Failed to open log file: %s", s_logpath);
        /* Non-fatal — we still have syslog. */
    }

    syslog(LOG_INFO, "Sentinel logger initialised (file: %s)", s_logpath);
    return 0;
}

void logger_shutdown(void)
{
    pthread_mutex_lock(&s_log_mutex);

    if (s_logfile) {
        fclose(s_logfile);
        s_logfile = NULL;
    }

    pthread_mutex_unlock(&s_log_mutex);
    closelog();
}

void logger_log(log_level_t level, const char *fmt, ...)
{
    va_list ap;

    /* ── syslog ─────────────────────────────────────────────────────── */
    va_start(ap, fmt);
    vsyslog(level_to_syslog(level), fmt, ap);
    va_end(ap);

    /* ── file log ───────────────────────────────────────────────────── */
    pthread_mutex_lock(&s_log_mutex);
    maybe_rotate();

    if (s_logfile) {
        time_t     now = time(NULL);
        struct tm  tm_buf;
        char       timebuf[32];
        localtime_r(&now, &tm_buf);
        strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", &tm_buf);

        fprintf(s_logfile, "[%s] [%5s] ", timebuf, level_str(level));

        va_start(ap, fmt);
        vfprintf(s_logfile, fmt, ap);
        va_end(ap);

        fputc('\n', s_logfile);
        fflush(s_logfile);
    }

    pthread_mutex_unlock(&s_log_mutex);
}
