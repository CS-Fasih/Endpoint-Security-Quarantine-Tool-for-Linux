/*
 * alert.h — WebSocket alert server for real-time GUI notifications.
 * Uses libwebsockets to broadcast JSON payloads to connected Electron clients.
 */

#ifndef SENTINEL_ALERT_H
#define SENTINEL_ALERT_H

#include <stddef.h>

/* Default WebSocket listen port */
#define ALERT_WS_PORT 9800

/* Alert event types */
typedef enum {
    ALERT_TYPE_SCAN_CLEAN,       /* File scanned, no threat        */
    ALERT_TYPE_SCAN_THREAT,      /* File scanned, threat found     */
    ALERT_TYPE_QUARANTINE,       /* File quarantined               */
    ALERT_TYPE_RESTORE,          /* File restored from quarantine  */
    ALERT_TYPE_DELETE,           /* File permanently deleted       */
    ALERT_TYPE_STATUS            /* Heartbeat / status update      */
} alert_type_t;

/**
 * Initialise the WebSocket alert server.
 * @param port TCP port to bind (use ALERT_WS_PORT).
 * @return 0 on success, -1 on error.
 */
int alert_server_init(int port);

/**
 * Service pending WebSocket events (non-blocking).
 * Call this from the main event loop.
 * @param timeout_ms  Maximum time to block in milliseconds.
 */
void alert_server_service(int timeout_ms);

/**
 * Broadcast a JSON alert to all connected clients.
 * @param type      Alert event type.
 * @param filename  Name of the file involved.
 * @param threat    Threat signature (or NULL for clean scans).
 * @param details   Optional extra details (or NULL).
 */
void alert_broadcast(alert_type_t type,
                     const char *filename,
                     const char *threat,
                     const char *details);

/**
 * Shut down the WebSocket alert server.
 */
void alert_server_shutdown(void);

/**
 * Get the number of currently connected clients.
 */
int alert_get_client_count(void);

#endif /* SENTINEL_ALERT_H */
