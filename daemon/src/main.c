/*
 * main.c — Sentinel daemon entry point (refactored).
 *
 * Architectural fixes applied:
 *   Fix 1: Thread pool — on_file_event() enqueues paths into a bounded
 *          work queue; N worker threads handle ClamAV scanning in parallel.
 *   Fix 2: UNIX domain socket IPC — no more TCP WebSocket.
 *   Fix 3: Inotify limits handled in monitor.c (ENOSPC graceful fallback).
 *   Fix 4: State sync — on GUI connect ("sync_state"), the daemon reads
 *          the quarantine manifest and sends the full list to that client.
 *
 * Part of the Sentinel Endpoint Security daemon.
 */

#include "logger.h"
#include "monitor.h"
#include "scanner.h"
#include "quarantine.h"
#include "alert.h"
#include "threadpool.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <errno.h>
#include <json-c/json.h>

/* ── Globals ────────────────────────────────────────────────────────────── */

static volatile int      g_running = 1;
static monitor_ctx_t    *g_monitor = NULL;
static threadpool_t     *g_pool    = NULL;

/* Directories to watch (NULL-terminated). */
static const char *WATCH_DIRS[] = { "/home", "/tmp", NULL };

/* Thread pool sizing */
#define WORKER_THREADS   4
#define QUEUE_CAPACITY 256

/* ── Fail-safe scan configuration ───────────────────────────────────────── */

/*
 * Number of times to retry a scan when clamd is unreachable.
 * After exhausting retries the file is locked down (chmod 0000).
 */
#define SCAN_MAX_RETRIES    3

/* Seconds to sleep between retry attempts. */
#define SCAN_RETRY_DELAY_S  2

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

    /* Ignore SIGPIPE (broken socket writes). */
    signal(SIGPIPE, SIG_IGN);
}

/* ── Scan worker function (runs in thread pool) ─────────────────────────── */

/**
 * Executed by each thread-pool worker for every dequeued file path.
 * This is the FAIL-SAFE pipeline:
 *
 *   1. Store the original permissions.
 *   2. Strip execute permission immediately (chmod a-x) so a potentially
 *      malicious file cannot run while we are analysing it.
 *   3. Attempt the ClamAV scan, retrying up to SCAN_MAX_RETRIES times
 *      if clamd is unreachable.
 *   4. On success (clean): restore original permissions.
 *   5. On threat: quarantine as before.
 *   6. On exhausted retries (scanner offline): LOCKDOWN the file to
 *      permissions 0000 and alert the GUI.  This prevents the old
 *      "fail-open" flaw where malware could execute while the scanner
 *      was down.
 *
 * IMPORTANT: This function takes ownership of `filepath` and MUST free() it.
 */
static void scan_worker(char *filepath, void *user_data)
{
    (void)user_data;

    log_info("[worker] Scanning: %s", filepath);

    /* ── Step 1: Save original permissions ──────────────────────────── */
    struct stat orig_st;
    mode_t orig_mode = 0644;   /* Sane fallback if stat fails. */
    if (stat(filepath, &orig_st) == 0) {
        orig_mode = orig_st.st_mode;
    }

    /* ── Step 2: Strip execute permission (fail-closed posture) ─────── */
    /*
     * Remove the execute bits for owner, group, and others.  This ensures
     * the file cannot be launched while ClamAV is analysing it.
     */
    mode_t noexec_mode = orig_mode & (mode_t)(~(S_IXUSR | S_IXGRP | S_IXOTH));
    if (noexec_mode != orig_mode) {
        if (chmod(filepath, noexec_mode) != 0) {
            log_warn("[worker] chmod a-x failed for %s: %s (continuing)",
                     filepath, strerror(errno));
        } else {
            log_info("[worker] Stripped execute permission from: %s", filepath);
        }
    }

    /* ── Step 3: Attempt the scan (with retry loop) ─────────────────── */
    scan_report_t report;
    int scan_ok  = 0;   /* 1 = scanner_scan_file() returned 0 (got a result) */
    int attempts = 0;

    for (attempts = 0; attempts <= SCAN_MAX_RETRIES; attempts++) {
        if (attempts > 0) {
            /*
             * Before retrying, check if the file still exists.
             * Transient files (browser temp, build artifacts, etc.) often
             * disappear within milliseconds.  Retrying on a dead path just
             * wastes a worker thread for (retries × delay) seconds.
             */
            struct stat retry_st;
            if (stat(filepath, &retry_st) != 0) {
                log_info("[worker] File vanished before retry: %s — skipping",
                         filepath);
                free(filepath);
                return;
            }

            log_warn("[worker] Retry %d/%d for %s — waiting %ds ...",
                     attempts, SCAN_MAX_RETRIES, filepath, SCAN_RETRY_DELAY_S);
            alert_broadcast(ALERT_TYPE_STATUS, filepath, NULL,
                            "Scanner offline — retrying...");
            sleep(SCAN_RETRY_DELAY_S);
        }

        if (scanner_scan_file(filepath, &report) == 0) {
            scan_ok = 1;
            break;
        }
        log_error("[worker] Scanner communication error (attempt %d) for: %s",
                  attempts + 1, filepath);
    }

    /* ── Step 4: Handle the result ──────────────────────────────────── */

    if (!scan_ok) {
        /*
         * FAIL-SAFE LOCKDOWN:  clamd is unreachable after all retries.
         * We refuse to let the file remain accessible — lock it down
         * with permissions 0000 (no access for anyone except root via
         * bypass).  This is the security-critical path that prevents
         * the old "fail-open" vulnerability.
         */
        log_error("[worker] LOCKDOWN: Scanner offline after %d retries — "
                  "locking file: %s", SCAN_MAX_RETRIES, filepath);

        if (chmod(filepath, 0000) != 0) {
            log_error("[worker] CRITICAL: chmod 0000 failed for %s: %s",
                      filepath, strerror(errno));
        }

        alert_broadcast(ALERT_TYPE_STATUS, filepath, NULL,
                        "Scanner offline. File locked down (chmod 0000).");
        free(filepath);
        return;
    }

    switch (report.result) {

    case SCAN_RESULT_CLEAN:
        log_info("[worker] File clean: %s", filepath);
        alert_broadcast(ALERT_TYPE_SCAN_CLEAN, filepath, NULL, "File is clean");

        /* Restore original permissions — the file is safe. */
        if (chmod(filepath, orig_mode) != 0) {
            log_warn("[worker] Failed to restore permissions on %s: %s",
                     filepath, strerror(errno));
        }
        break;

    case SCAN_RESULT_INFECTED:
        log_warn("[worker] THREAT in %s: %s", filepath, report.threat_name);

        /* Quarantine the file. */
        if (quarantine_file(filepath, report.threat_name) == 0) {
            alert_broadcast(ALERT_TYPE_SCAN_THREAT, filepath,
                            report.threat_name, "File quarantined");
        } else {
            /* Quarantine failed — lock the file down as a last resort. */
            log_error("[worker] Quarantine failed for %s — applying lockdown",
                      filepath);
            chmod(filepath, 0000);
            alert_broadcast(ALERT_TYPE_SCAN_THREAT, filepath,
                            report.threat_name,
                            "CRITICAL: quarantine failed — file locked!");
        }
        break;

    case SCAN_RESULT_ERROR:
        /*
         * clamd connected but returned an ERROR result (e.g. the file could
         * not be read by clamd).  Same fail-safe: lock it down.
         */
        log_error("[worker] Scan error for %s — applying lockdown", filepath);
        chmod(filepath, 0000);
        alert_broadcast(ALERT_TYPE_STATUS, filepath, NULL,
                        "Scan error — file locked down.");
        break;
    }

    free(filepath);  /* Worker owns the strdup'd path. */
}

/* ── File-event callback (inotify → thread pool) ───────────────────────── */

/**
 * Called by the monitor thread whenever a file event is detected.
 * This is now LIGHTWEIGHT: it just filters and enqueues.
 * The actual scanning happens asynchronously in the thread pool.
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

    /*
     * Skip transient temporary files that appear and vanish instantly.
     * These flood the queue and block workers with pointless retries.
     *
     *   clamav-*        : clamd's own temp files during scans
     *   *-scantemp*     : clamd scan work directories
     *   chromecrx_*     : Chrome extension unpacking
     *   .org.chromium.* : Chromium profile swap files
     *   .goutputstream  : GLib/GNOME temp write files
     */
    if (strstr(filepath, "clamav-") != NULL   ||
        strstr(filepath, "-scantemp") != NULL ||
        strstr(filepath, "chromecrx_") != NULL ||
        strstr(filepath, ".org.chromium.") != NULL ||
        strstr(filepath, ".goutputstream") != NULL) {
        return;
    }

    /* Verify file still exists and is accessible. */
    struct stat st;
    if (stat(filepath, &st) != 0 || !S_ISREG(st.st_mode))
        return;

    /* Skip very small files (< 4 bytes) and very large files (> 100 MB). */
    if (st.st_size < 4 || st.st_size > 100 * 1024 * 1024)
        return;

    /* Enqueue for async scanning — the pool strdup()s internally. */
    threadpool_submit(g_pool, filepath);
}

/* ── IPC command handler (Fix 4: state sync + restore/delete) ───────────── */

/**
 * Dispatches commands received from GUI clients over the UNIX socket.
 *
 * Supported actions:
 *   "sync_state" — Reads the quarantine manifest and sends the full list
 *                  to the requesting client so it can rebuild the Vault.
 *   "restore"    — Restores a quarantined file by UUID.
 *   "delete"     — Permanently deletes a quarantined file by UUID.
 */
static void on_gui_command(int client_fd,
                           const char *action,
                           const char *id,
                           void *user_data)
{
    (void)user_data;

    /* ── sync_state: send full quarantine manifest to this client ──── */
    if (strcmp(action, "sync_state") == 0) {
        log_info("GUI requested state sync (fd=%d)", client_fd);

        quarantine_entry_t *entries = NULL;
        int count = 0;

        if (quarantine_list(&entries, &count) == 0 && count > 0) {
            for (int i = 0; i < count; i++) {
                struct json_object *jobj = json_object_new_object();
                json_object_object_add(jobj, "event",
                    json_object_new_string("sync_entry"));
                json_object_object_add(jobj, "id",
                    json_object_new_string(entries[i].id));
                json_object_object_add(jobj, "filename",
                    json_object_new_string(entries[i].original_path));
                json_object_object_add(jobj, "quarantine_path",
                    json_object_new_string(entries[i].quarantine_path));
                json_object_object_add(jobj, "threat",
                    json_object_new_string(entries[i].threat_name));
                json_object_object_add(jobj, "timestamp",
                    json_object_new_int64((int64_t)entries[i].timestamp));

                const char *json_str = json_object_to_json_string(jobj);
                alert_send_to_client(client_fd, json_str);
                json_object_put(jobj);  /* Free the JSON object. */
            }
            free(entries);
        }

        /* Send sync-complete marker. */
        alert_send_to_client(client_fd,
            "{\"event\":\"sync_complete\",\"count\":" 
            "0}");  /* count doesn't matter, GUI uses entries */

        log_info("State sync complete: sent %d entries to fd=%d",
                 count, client_fd);
        return;
    }

    /* ── restore: restore a quarantined file ──────────────────────── */
    if (strcmp(action, "restore") == 0 && id) {
        log_info("GUI requested restore: %s", id);

        if (quarantine_restore(id) == 0) {
            alert_broadcast(ALERT_TYPE_RESTORE, id, NULL,
                            "File restored from quarantine");
        } else {
            log_error("Failed to restore quarantine entry: %s", id);
            alert_broadcast(ALERT_TYPE_STATUS, id, NULL,
                            "Restore failed");
        }
        return;
    }

    /* ── delete: permanently delete a quarantined file ────────────── */
    if (strcmp(action, "delete") == 0 && id) {
        log_info("GUI requested delete: %s", id);

        if (quarantine_delete(id) == 0) {
            alert_broadcast(ALERT_TYPE_DELETE, id, NULL,
                            "File permanently deleted");
        } else {
            log_error("Failed to delete quarantine entry: %s", id);
            alert_broadcast(ALERT_TYPE_STATUS, id, NULL,
                            "Delete failed");
        }
        return;
    }

    log_warn("Unknown GUI command: action=%s id=%s", action, id ? id : "");
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
    log_info("  Thread pool: %d workers, queue: %d",
             WORKER_THREADS, QUEUE_CAPACITY);
    log_info("  IPC socket:  %s", ALERT_SOCKET_PATH);
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

    /* ── 4. Thread pool (Fix 1) ─────────────────────────────────────── */
    g_pool = threadpool_create(WORKER_THREADS, QUEUE_CAPACITY,
                               scan_worker, NULL);
    if (!g_pool) {
        log_error("Failed to create thread pool.");
        quarantine_shutdown();
        scanner_shutdown();
        logger_shutdown();
        return 1;
    }

    /* ── 5. UNIX domain socket IPC server (Fix 2) ───────────────────── */
    if (alert_server_init(ALERT_SOCKET_PATH) != 0) {
        log_error("Failed to start IPC server.");
        threadpool_shutdown(g_pool);
        quarantine_shutdown();
        scanner_shutdown();
        logger_shutdown();
        return 1;
    }

    /* Register the command handler for GUI commands (Fix 4). */
    alert_set_command_handler(on_gui_command, NULL);

    /* ── 6. File monitor (on a separate thread) ─────────────────────── */
    g_monitor = monitor_create(WATCH_DIRS, on_file_event, NULL);
    if (!g_monitor) {
        log_error("Failed to create file monitor.");
        alert_server_shutdown();
        threadpool_shutdown(g_pool);
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
        threadpool_shutdown(g_pool);
        quarantine_shutdown();
        scanner_shutdown();
        logger_shutdown();
        return 1;
    }

    log_info("All subsystems initialised.  Entering main event loop.");
    alert_broadcast(ALERT_TYPE_STATUS, "sentinel", NULL, "Daemon started");

    /* ── 7. Main loop: service IPC socket events ────────────────────── */
    while (g_running) {
        alert_server_service(200);  /* 200 ms timeout */
    }

    /* ── 8. Graceful shutdown ───────────────────────────────────────── */
    log_info("Shutting down Sentinel daemon...");

    /* Stop the monitor thread first. */
    monitor_stop(g_monitor);
    pthread_join(mon_tid, NULL);
    monitor_destroy(g_monitor);

    /* Drain the thread pool (waits for in-flight scans to complete). */
    threadpool_shutdown(g_pool);

    /* Final broadcast before closing IPC. */
    alert_broadcast(ALERT_TYPE_STATUS, "sentinel", NULL, "Daemon stopping");
    alert_server_service(100);
    alert_server_shutdown();

    quarantine_shutdown();
    scanner_shutdown();

    log_info("Sentinel daemon stopped.");
    logger_shutdown();

    return 0;
}
