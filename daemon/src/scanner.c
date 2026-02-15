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
#include <fcntl.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>

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

    /*
     * Use clamd's zINSTREAM protocol instead of SCAN.
     *
     * SCAN requires clamd (which runs as the unprivileged user "clamav")
     * to open the target file itself.  On most Linux systems the user's
     * home directory has mode 700, so clamd gets "Permission denied".
     *
     * zINSTREAM solves this: our daemon (running as root) opens and reads
     * the file, then streams the raw bytes to clamd over the socket.
     * clamd never touches the filesystem — it scans pure byte content.
     *
     * Protocol:
     *   1. Send "zINSTREAM\0"  (null-terminated z-prefix command).
     *   2. For each chunk: send 4-byte big-endian length + chunk data.
     *   3. Send 4-byte zero (0x00000000) to signal end-of-data.
     *   4. Read the response (same format as SCAN: "... OK\n" / "... FOUND\n").
     */

    /* Step 1: Open the file ourselves (we're root). */
    int file_fd = open(filepath, O_RDONLY);
    if (file_fd < 0) {
        log_error("Cannot open %s for scanning: %s", filepath, strerror(errno));
        return -1;
    }

    int sock_fd = clamd_connect();
    if (sock_fd < 0) {
        close(file_fd);
        return -1;
    }

    /* Step 2: Send the zINSTREAM command (null-terminated). */
    const char cmd[] = "zINSTREAM";
    if (write(sock_fd, cmd, sizeof(cmd)) < 0) {  /* sizeof includes the '\0' */
        log_error("clamd write zINSTREAM cmd error: %s", strerror(errno));
        close(file_fd);
        close(sock_fd);
        return -1;
    }

    /* Step 3: Stream file contents in 8 KB chunks. */
    #define CHUNK_SIZE 8192
    char buf[CHUNK_SIZE];
    ssize_t nread;
    int stream_ok = 1;

    while ((nread = read(file_fd, buf, sizeof(buf))) > 0) {
        /* 4-byte big-endian chunk length. */
        uint32_t chunk_len = htonl((uint32_t)nread);
        if (write(sock_fd, &chunk_len, 4) < 0 ||
            write(sock_fd, buf, (size_t)nread) < 0) {
            log_error("clamd INSTREAM write error: %s", strerror(errno));
            stream_ok = 0;
            break;
        }
    }
    close(file_fd);

    if (!stream_ok) {
        close(sock_fd);
        return -1;
    }

    /* Step 4: Send end-of-data marker (4 zero bytes). */
    uint32_t zero = 0;
    if (write(sock_fd, &zero, 4) < 0) {
        log_error("clamd INSTREAM end marker error: %s", strerror(errno));
        close(sock_fd);
        return -1;
    }

    /* Step 5: Read the response. */
    char resp[1024];
    ssize_t total = 0;
    while ((size_t)total < sizeof(resp) - 1) {
        ssize_t n = read(sock_fd, resp + total, sizeof(resp) - 1 - (size_t)total);
        if (n <= 0) break;
        total += n;
    }
    resp[total] = '\0';
    close(sock_fd);

    if (total <= 0) {
        log_error("No response from clamd for file: %s", filepath);
        return -1;
    }

    log_info("clamd response: %s", resp);

    /*
     * Response format:
     *   stream: OK\n                          → clean
     *   stream: <signature> FOUND\n           → infected
     *   stream: <reason> ERROR\n              → error
     *
     * With INSTREAM the prefix is "stream:" instead of the filepath.
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
