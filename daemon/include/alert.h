/*
 * alert.h — UNIX domain socket IPC server for secure GUI notifications.
 *
 * Replaces the insecure TCP WebSocket with a permission-controlled UNIX
 * socket at /var/run/sentinel_gui.sock.  Only processes with matching
 * UID/GID can connect.
 *
 * Part of the Sentinel Endpoint Security daemon.
 */

#ifndef SENTINEL_ALERT_H
#define SENTINEL_ALERT_H

#include <stddef.h>

/* ── Socket path & permissions ──────────────────────────────────────────── */

/* Default UNIX socket path.  Placed in /tmp so the desktop user's Electron
 * GUI can connect without privilege.  Permissions set to 0666. */
#define ALERT_SOCKET_PATH "/tmp/sentinel_gui.sock"
#define ALERT_SOCKET_PERMS 0666

/* Maximum number of simultaneous GUI client connections */
#define ALERT_MAX_CLIENTS  8

/* Maximum JSON message length (including newline delimiter) */
#define ALERT_MSG_MAX      4096

/* ── Alert event types ──────────────────────────────────────────────────── */

typedef enum {
    ALERT_TYPE_SCAN_CLEAN,       /* File scanned, no threat        */
    ALERT_TYPE_SCAN_THREAT,      /* File scanned, threat found     */
    ALERT_TYPE_QUARANTINE,       /* File quarantined               */
    ALERT_TYPE_RESTORE,          /* File restored from quarantine  */
    ALERT_TYPE_DELETE,           /* File permanently deleted       */
    ALERT_TYPE_STATUS,           /* Heartbeat / status update      */
    ALERT_TYPE_SYNC_STATE        /* Full quarantine state dump     */
} alert_type_t;

/* ── Command handler callback ───────────────────────────────────────────── */

/**
 * Callback invoked when a GUI client sends a JSON command.
 *
 * @param client_fd   File descriptor of the sending client (for targeted replies).
 * @param action      The "action" field from the JSON (e.g. "restore", "delete", "sync_state").
 * @param id          The "id" field (quarantine UUID), or NULL if absent.
 * @param user_data   Opaque pointer registered via alert_set_command_handler().
 */
typedef void (*alert_command_handler_t)(int client_fd,
                                       const char *action,
                                       const char *id,
                                       void *user_data);

/* ── Public API ─────────────────────────────────────────────────────────── */

/**
 * Initialise the UNIX domain socket IPC server.
 * @param socket_path  Path for the listening socket (use ALERT_SOCKET_PATH).
 * @return 0 on success, -1 on error.
 */
int alert_server_init(const char *socket_path);

/**
 * Register a handler for incoming GUI commands (restore/delete/sync_state).
 */
void alert_set_command_handler(alert_command_handler_t handler, void *user_data);

/**
 * Service pending socket events (accept new clients, read commands, etc.).
 * Call this from the main event loop.  Non-blocking with select() timeout.
 * @param timeout_ms  Maximum time to block in milliseconds.
 */
void alert_server_service(int timeout_ms);

/**
 * Broadcast a JSON alert to ALL connected clients.
 * Message format: JSON object followed by newline delimiter.
 */
void alert_broadcast(alert_type_t type,
                     const char *filename,
                     const char *threat,
                     const char *details);

/**
 * Send a raw JSON string to a SINGLE client (used for targeted sync replies).
 * The string must NOT include a trailing newline — one is appended automatically.
 * @param client_fd  Target client file descriptor.
 * @param json_str   Null-terminated JSON string.
 * @return 0 on success, -1 on error.
 */
int alert_send_to_client(int client_fd, const char *json_str);

/**
 * Shut down the IPC server: close all client connections, unlink socket.
 */
void alert_server_shutdown(void);

/**
 * Broadcast a raw pre-formatted JSON string to ALL connected clients.
 * Use this for one-off event types that don't fit the standard schema.
 * The string must NOT include a trailing newline — one is appended.
 */
void alert_broadcast_raw(const char *json_str);

/**
 * Get the number of currently connected clients.
 */
int alert_get_client_count(void);

#endif /* SENTINEL_ALERT_H */
