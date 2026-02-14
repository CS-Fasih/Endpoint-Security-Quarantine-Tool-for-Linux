/*
 * quarantine.h — File quarantine management.
 * Strips permissions, moves to /opt/quarantine/, maintains JSON manifest.
 */

#ifndef SENTINEL_QUARANTINE_H
#define SENTINEL_QUARANTINE_H

#include <time.h>

/* Default quarantine directory */
#define QUARANTINE_DIR "/opt/quarantine"

/* Manifest file (JSON array) tracking quarantined items */
#define QUARANTINE_MANIFEST QUARANTINE_DIR "/.manifest.json"

/* Maximum path length */
#define QR_MAX_PATH 4096

/* Single quarantine record */
typedef struct {
    char   id[64];                     /* UUID-style identifier             */
    char   original_path[QR_MAX_PATH]; /* Where the file originally lived   */
    char   quarantine_path[QR_MAX_PATH]; /* Current path in quarantine dir  */
    char   threat_name[256];           /* ClamAV signature that flagged it  */
    time_t timestamp;                  /* When it was quarantined           */
} quarantine_entry_t;

/**
 * Initialise the quarantine subsystem.
 * Creates the quarantine directory and loads the manifest.
 * @return 0 on success, -1 on error.
 */
int quarantine_init(void);

/**
 * Quarantine a file: chmod 000, move to /opt/quarantine/, update manifest.
 * @param filepath    Absolute path to the infected file.
 * @param threat_name ClamAV signature name.
 * @return 0 on success, -1 on error.
 */
int quarantine_file(const char *filepath, const char *threat_name);

/**
 * Restore a quarantined file to its original location.
 * @param quarantine_id The UUID of the quarantined entry.
 * @return 0 on success, -1 on error.
 */
int quarantine_restore(const char *quarantine_id);

/**
 * Permanently delete a quarantined file.
 * @param quarantine_id The UUID of the quarantined entry.
 * @return 0 on success, -1 on error.
 */
int quarantine_delete(const char *quarantine_id);

/**
 * List all quarantined entries.
 * Caller must free the returned array with free().
 * @param entries Pointer to receive the array of entries.
 * @param count   Receives the number of entries.
 * @return 0 on success, -1 on error.
 */
int quarantine_list(quarantine_entry_t **entries, int *count);

/**
 * Shut down quarantine subsystem, flush manifest.
 */
void quarantine_shutdown(void);

#endif /* SENTINEL_QUARANTINE_H */
