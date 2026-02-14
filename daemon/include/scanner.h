/*
 * scanner.h — ClamAV clamd socket scanner interface.
 * Communicates with clamd over its UNIX domain socket.
 */

#ifndef SENTINEL_SCANNER_H
#define SENTINEL_SCANNER_H

/* Default clamd socket path on Ubuntu */
#define CLAMD_SOCKET_PATH "/var/run/clamav/clamd.ctl"

/* Maximum length for a threat/signature name */
#define SCANNER_MAX_THREAT_NAME 256

/* Scan result codes */
typedef enum {
    SCAN_RESULT_CLEAN,       /* File is clean                   */
    SCAN_RESULT_INFECTED,    /* File contains malware           */
    SCAN_RESULT_ERROR        /* Scanner communication error     */
} scan_result_t;

/* Detailed scan result */
typedef struct {
    scan_result_t result;
    char          threat_name[SCANNER_MAX_THREAT_NAME];  /* e.g. "Win.Test.EICAR_HDB-1" */
} scan_report_t;

/**
 * Initialise the scanner module.
 * @param socket_path Path to the clamd UNIX socket.
 * @return 0 on success, -1 if the socket is unreachable.
 */
int scanner_init(const char *socket_path);

/**
 * Scan a single file via clamd.
 * @param filepath Absolute path to the file.
 * @param report   Output parameter filled with the result.
 * @return 0 on success, -1 on communication error.
 */
int scanner_scan_file(const char *filepath, scan_report_t *report);

/**
 * Check if clamd is alive (ping/pong).
 * @return 1 if alive, 0 otherwise.
 */
int scanner_ping(void);

/**
 * Shut down the scanner module.
 */
void scanner_shutdown(void);

#endif /* SENTINEL_SCANNER_H */
