/*
 * scanner.c — ClamAV clamd UNIX-socket scanner.
 *
 * Sends SCAN commands to the running clamd daemon and parses responses.
 * Part of the Sentinel Endpoint Security daemon.
 */

#include "scanner.h"
#include "quarantine.h"
#include "logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

/* ── Private state ──────────────────────────────────────────────────────── */

static char s_socket_path[108];  /* Matches sizeof(sun_path) */

/* ── Helpers ────────────────────────────────────────────────────────────── */

/**
 * Open a UNIX-domain connection to clamd.
 * Returns the fd on success, -1 on failure.
 */
static int clamd_connect(void)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        log_error("socket(): %s", strerror(errno));
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", s_socket_path);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        log_error("connect(%s): %s", s_socket_path, strerror(errno));
        close(fd);
        return -1;
    }

    return fd;
}

/**
 * Send a command to clamd and read the response.
 * @param fd    Connected socket fd.
 * @param cmd   Command string (e.g. "PING\n" or "SCAN /path\n").
 * @param resp  Buffer for the response.
 * @param rlen  Size of resp buffer.
 * @return Number of bytes read, or -1 on error.
 */
static ssize_t clamd_command(int fd, const char *cmd, char *resp, size_t rlen)
{
    size_t cmd_len = strlen(cmd);
    ssize_t sent = write(fd, cmd, cmd_len);
    if (sent < 0 || (size_t)sent != cmd_len) {
        log_error("clamd write error: %s", strerror(errno));
        return -1;
    }

    /* Shutdown write side so clamd knows the command is complete. */
    shutdown(fd, SHUT_WR);

    ssize_t total = 0;
    while ((size_t)total < rlen - 1) {
        ssize_t n = read(fd, resp + total, rlen - 1 - (size_t)total);
        if (n <= 0) break;
        total += n;
    }
    resp[total] = '\0';

    return total;
}

/* ── Public API ─────────────────────────────────────────────────────────── */

int scanner_init(const char *socket_path)
{
    const char *path = socket_path ? socket_path : CLAMD_SOCKET_PATH;
    snprintf(s_socket_path, sizeof(s_socket_path), "%s", path);

    log_info("Scanner initialising with clamd socket: %s", s_socket_path);

    if (!scanner_ping()) {
        log_warn("clamd is not responding — scans will fail until it starts.");
        /* Non-fatal: clamd may start later. */
    } else {
        log_info("clamd is alive and ready.");
    }

    return 0;
}

int scanner_scan_file(const char *filepath, scan_report_t *report)
{
    if (!filepath || !report) return -1;

    memset(report, 0, sizeof(*report));
    report->result = SCAN_RESULT_ERROR;

    int fd = clamd_connect();
    if (fd < 0) return -1;

    /* Build command: "SCAN <filepath>\n" */
    char cmd[QR_MAX_PATH + 16];
    snprintf(cmd, sizeof(cmd), "SCAN %s\n", filepath);

    char resp[1024];
    ssize_t n = clamd_command(fd, cmd, resp, sizeof(resp));
    close(fd);

    if (n <= 0) {
        log_error("No response from clamd for file: %s", filepath);
        return -1;
    }

    log_info("clamd response: %s", resp);

    /*
     * Response format:
     *   /path/to/file: OK\n                        → clean
     *   /path/to/file: <signature> FOUND\n         → infected
     *   /path/to/file: <reason> ERROR\n            → error
     */
    char *found_ptr = strstr(resp, " FOUND");
    char *ok_ptr    = strstr(resp, " OK");
    char *err_ptr   = strstr(resp, " ERROR");

    if (found_ptr) {
        report->result = SCAN_RESULT_INFECTED;

        /* Extract threat name: text between ": " and " FOUND" */
        char *colon = strstr(resp, ": ");
        if (colon) {
            colon += 2; /* skip ": " */
            size_t len = (size_t)(found_ptr - colon);
            if (len >= sizeof(report->threat_name))
                len = sizeof(report->threat_name) - 1;
            memcpy(report->threat_name, colon, len);
            report->threat_name[len] = '\0';
        }

        log_warn("THREAT DETECTED in %s: %s", filepath, report->threat_name);
    } else if (ok_ptr) {
        report->result = SCAN_RESULT_CLEAN;
    } else if (err_ptr) {
        report->result = SCAN_RESULT_ERROR;
        log_error("clamd error scanning %s: %s", filepath, resp);
    }

    return 0;
}

int scanner_ping(void)
{
    int fd = clamd_connect();
    if (fd < 0) return 0;

    char resp[64];
    ssize_t n = clamd_command(fd, "PING\n", resp, sizeof(resp));
    close(fd);

    if (n > 0 && strstr(resp, "PONG")) {
        return 1;
    }
    return 0;
}

void scanner_shutdown(void)
{
    log_info("Scanner shut down.");
}
