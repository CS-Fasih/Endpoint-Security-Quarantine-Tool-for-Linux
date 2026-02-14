/*
 * main.c — Sentinel daemon entry point.
 *
 * Initialises all subsystems (logger, scanner, quarantine, monitor, alert),
 * starts the inotify monitor on a dedicated thread, and services the
 * WebSocket alert server on the main thread.
 *
 * Part of the Sentinel Endpoint Security daemon.
 */

#include "logger.h"
#include "monitor.h"
#include "scanner.h"
#include "quarantine.h"
#include "alert.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>

/* ── Globals ────────────────────────────────────────────────────────────── */

static volatile int      g_running = 1;
static monitor_ctx_t    *g_monitor = NULL;

/* Directories to watch (NULL-terminated). */
static const char *WATCH_DIRS[] = { "/home", "/tmp", NULL };

/* ── Signal handling ────────────────────────────────────────────────────── */

static void signal_handler(int sig)
{
    (void)sig;
    g_running = 0;
    if (g_monitor) monitor_stop(g_monitor);
}

static void install_signal_handlers(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);

    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);

    /* Ignore SIGPIPE (broken WebSocket connections). */
    signal(SIGPIPE, SIG_IGN);
}

/* ── File-event callback ────────────────────────────────────────────────── */

/**
 * Called by the monitor thread whenever a file event is detected.
 * This is the core pipeline: detect → scan → quarantine → alert.
 */
static void on_file_event(const char *filepath, void *user_data)
{
    (void)user_data;

    /* Skip the quarantine directory itself. */
    if (strncmp(filepath, QUARANTINE_DIR, strlen(QUARANTINE_DIR)) == 0)
        return;

    /* Skip manifest and log files. */
    const char *base = strrchr(filepath, '/');
    base = base ? base + 1 : filepath;
    if (base[0] == '.') return;

    /* Verify file still exists and is accessible. */
    struct stat st;
    if (stat(filepath, &st) != 0 || !S_ISREG(st.st_mode))
        return;

    /* Skip very small files (< 4 bytes) and very large files (> 100 MB). */
    if (st.st_size < 4 || st.st_size > 100 * 1024 * 1024)
        return;

    log_info("Scanning file: %s (%ld bytes)", filepath, (long)st.st_size);

    /* Send to ClamAV scanner. */
    scan_report_t report;
    if (scanner_scan_file(filepath, &report) != 0) {
        log_error("Scanner communication error for: %s", filepath);
        alert_broadcast(ALERT_TYPE_STATUS, filepath, NULL,
                        "Scanner communication error");
        return;
    }

    switch (report.result) {

    case SCAN_RESULT_CLEAN:
        log_info("File clean: %s", filepath);
        alert_broadcast(ALERT_TYPE_SCAN_CLEAN, filepath, NULL, "File is clean");
        break;

    case SCAN_RESULT_INFECTED:
        log_warn("THREAT in %s: %s", filepath, report.threat_name);

        /* Quarantine the file. */
        if (quarantine_file(filepath, report.threat_name) == 0) {
            alert_broadcast(ALERT_TYPE_SCAN_THREAT, filepath,
                            report.threat_name, "File quarantined");
        } else {
            alert_broadcast(ALERT_TYPE_SCAN_THREAT, filepath,
                            report.threat_name,
                            "CRITICAL: quarantine failed!");
        }
        break;

    case SCAN_RESULT_ERROR:
        log_error("Scan error for %s", filepath);
        alert_broadcast(ALERT_TYPE_STATUS, filepath, NULL, "Scan error");
        break;
    }
}

/* ── Monitor thread ─────────────────────────────────────────────────────── */

static void *monitor_thread(void *arg)
{
    monitor_ctx_t *ctx = (monitor_ctx_t *)arg;
    monitor_run(ctx);
    return NULL;
}

/* ── Main ───────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    /* ── 1. Logger ──────────────────────────────────────────────────── */
    if (logger_init(NULL) != 0) {
        fprintf(stderr, "Failed to initialise logger\n");
        return 1;
    }

    log_info("═══════════════════════════════════════════════════════");
    log_info("  Sentinel Endpoint Security Daemon — Starting");
    log_info("═══════════════════════════════════════════════════════");

    install_signal_handlers();

    /* ── 2. Quarantine subsystem ────────────────────────────────────── */
    if (quarantine_init() != 0) {
        log_error("Failed to initialise quarantine subsystem.");
        logger_shutdown();
        return 1;
    }

    /* ── 3. ClamAV scanner ──────────────────────────────────────────── */
    if (scanner_init(NULL) != 0) {
        log_warn("Scanner init returned error — will retry on first scan.");
    }

    /* ── 4. WebSocket alert server ──────────────────────────────────── */
    if (alert_server_init(ALERT_WS_PORT) != 0) {
        log_error("Failed to start WebSocket alert server.");
        quarantine_shutdown();
        scanner_shutdown();
        logger_shutdown();
        return 1;
    }

    /* ── 5. File monitor (on a separate thread) ─────────────────────── */
    g_monitor = monitor_create(WATCH_DIRS, on_file_event, NULL);
    if (!g_monitor) {
        log_error("Failed to create file monitor.");
        alert_server_shutdown();
        quarantine_shutdown();
        scanner_shutdown();
        logger_shutdown();
        return 1;
    }

    pthread_t mon_tid;
    if (pthread_create(&mon_tid, NULL, monitor_thread, g_monitor) != 0) {
        log_error("Failed to launch monitor thread.");
        monitor_destroy(g_monitor);
        alert_server_shutdown();
        quarantine_shutdown();
        scanner_shutdown();
        logger_shutdown();
        return 1;
    }

    log_info("All subsystems initialised.  Entering main event loop.");
    alert_broadcast(ALERT_TYPE_STATUS, "sentinel", NULL, "Daemon started");

    /* ── 6. Main loop: service WebSocket events ─────────────────────── */
    while (g_running) {
        alert_server_service(200);  /* 200 ms timeout */
    }

    /* ── 7. Graceful shutdown ───────────────────────────────────────── */
    log_info("Shutting down Sentinel daemon...");

    monitor_stop(g_monitor);
    pthread_join(mon_tid, NULL);
    monitor_destroy(g_monitor);

    alert_broadcast(ALERT_TYPE_STATUS, "sentinel", NULL, "Daemon stopping");
    alert_server_service(100);
    alert_server_shutdown();

    quarantine_shutdown();
    scanner_shutdown();

    log_info("Sentinel daemon stopped.");
    logger_shutdown();

    return 0;
}
