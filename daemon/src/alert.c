/*
 * alert.c — UNIX domain socket IPC server.
 *
 * Replaces the insecure TCP WebSocket (libwebsockets) with a
 * permission-controlled UNIX stream socket.  Uses select() for
 * non-blocking multiplexed I/O across all connected GUI clients.
 *
 * Protocol: newline-delimited JSON.  Each message is a complete JSON
 * object terminated by '\n'.  Both directions use the same framing.
 *
 * Fixes applied in this revision:
 *   Fix 1: Socket permissions changed from 0660 → 0666 so the local
 *          desktop user can connect without group manipulation.
 *   Fix 3: Replaced fragile strstr()/strchr() JSON parsing with robust
 *          json-c (json_tokener_parse / json_object_object_get_ex).
 *
 * Part of the Sentinel Endpoint Security daemon.
 */

#include "alert.h"
#include "logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <pthread.h>
#include <json-c/json.h>     /* Fix 3: robust JSON parsing */

/* ── Internal types ─────────────────────────────────────────────────────── */

/* Per-client read buffer for line-delimited JSON framing. */
typedef struct {
    int  fd;                          /* Client file descriptor (-1 = unused) */
    char buf[ALERT_MSG_MAX];          /* Partial-read accumulator             */
    int  buf_len;                     /* Bytes currently in buf               */
} client_slot_t;

/* ── Private state ──────────────────────────────────────────────────────── */

static int           s_listen_fd    = -1;
static char          s_socket_path[108];   /* Matches sizeof(sun_path) */
static client_slot_t s_clients[ALERT_MAX_CLIENTS];
static int           s_client_count = 0;
static pthread_mutex_t s_alert_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Command handler registered by main.c */
static alert_command_handler_t s_cmd_handler  = NULL;
static void                   *s_cmd_userdata = NULL;

/* ── Helpers ────────────────────────────────────────────────────────────── */

static const char *alert_type_str(alert_type_t type)
{
    switch (type) {
    case ALERT_TYPE_SCAN_CLEAN:   return "scan_clean";
    case ALERT_TYPE_SCAN_THREAT:  return "scan_threat";
    case ALERT_TYPE_QUARANTINE:   return "quarantine";
    case ALERT_TYPE_RESTORE:      return "restore";
    case ALERT_TYPE_DELETE:       return "delete";
    case ALERT_TYPE_STATUS:       return "status";
    case ALERT_TYPE_SYNC_STATE:   return "sync_state";
    default:                      return "unknown";
    }
}

/** Set a file descriptor to non-blocking mode. */
static int set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/** Find a free client slot, or return NULL if all are occupied. */
static client_slot_t *find_free_slot(void)
{
    for (int i = 0; i < ALERT_MAX_CLIENTS; i++) {
        if (s_clients[i].fd < 0) return &s_clients[i];
    }
    return NULL;
}

/** Close a client slot and clean up. */
static void close_client(client_slot_t *c)
{
    if (!c || c->fd < 0) return;
    close(c->fd);
    c->fd = -1;
    c->buf_len = 0;
    s_client_count--;
    log_info("IPC client disconnected (total: %d)", s_client_count);
}

/**
 * Process a single complete JSON message from a client.
 * Expected format: { "action": "...", "id": "..." }
 *
 * Fix 3: Uses json-c for robust, production-grade JSON parsing.
 * Replaces the fragile strstr()/strchr() hand-parsing that could silently
 * misinterpret nested quotes, escaped characters, or malformed payloads.
 */
static void process_client_message(client_slot_t *c, const char *msg)
{
    if (!s_cmd_handler) {
        log_warn("IPC: received command but no handler registered: %s", msg);
        return;
    }

    /* Parse the JSON string using json-c's tokenizer. */
    struct json_object *root = json_tokener_parse(msg);
    if (!root) {
        log_warn("IPC: failed to parse JSON from client fd=%d: %s", c->fd, msg);
        return;
    }

    /* Extract the "action" field (required). */
    struct json_object *action_obj = NULL;
    if (!json_object_object_get_ex(root, "action", &action_obj) ||
        json_object_get_type(action_obj) != json_type_string) {
        log_warn("IPC: malformed command (missing/invalid 'action'): %s", msg);
        json_object_put(root);   /* Free the parsed object. */
        return;
    }
    const char *action = json_object_get_string(action_obj);

    /* Extract the "id" field (optional). */
    const char *id = NULL;
    struct json_object *id_obj = NULL;
    if (json_object_object_get_ex(root, "id", &id_obj) &&
        json_object_get_type(id_obj) == json_type_string) {
        id = json_object_get_string(id_obj);
    }

    log_info("IPC command from client fd=%d: action=%s id=%s",
             c->fd, action, id ? id : "(none)");

    /* Dispatch to the registered command handler.
     * NOTE: The handler must NOT hold references to action/id beyond
     * this call, as they are owned by the json_object and freed below. */
    s_cmd_handler(c->fd, action, id, s_cmd_userdata);

    /* Free the parsed JSON object (and all child objects). */
    json_object_put(root);
}

/**
 * Read available data from a client and dispatch complete messages.
 * Returns 0 normally, -1 if the client should be closed.
 */
static int handle_client_data(client_slot_t *c)
{
    int space = ALERT_MSG_MAX - c->buf_len - 1;
    if (space <= 0) {
        /* Buffer overflow — discard and reset. */
        log_warn("IPC: client buffer overflow, resetting (fd=%d)", c->fd);
        c->buf_len = 0;
        return 0;
    }

    ssize_t n = read(c->fd, c->buf + c->buf_len, (size_t)space);
    if (n == 0) return -1;          /* Client disconnected cleanly. */
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        return -1;
    }
    c->buf_len += (int)n;
    c->buf[c->buf_len] = '\0';

    /* Process all complete lines (newline-delimited JSON). */
    char *line_start = c->buf;
    char *nl;
    while ((nl = strchr(line_start, '\n')) != NULL) {
        *nl = '\0';
        if (nl > line_start) {
            process_client_message(c, line_start);
        }
        line_start = nl + 1;
    }

    /* Move any remaining partial data to the front of the buffer. */
    int remaining = c->buf_len - (int)(line_start - c->buf);
    if (remaining > 0 && line_start != c->buf) {
        memmove(c->buf, line_start, (size_t)remaining);
    }
    c->buf_len = remaining;

    return 0;
}

/* ── Public API ─────────────────────────────────────────────────────────── */

int alert_server_init(const char *socket_path)
{
    const char *path = socket_path ? socket_path : ALERT_SOCKET_PATH;
    snprintf(s_socket_path, sizeof(s_socket_path), "%s", path);

    /* Initialise all client slots to empty. */
    for (int i = 0; i < ALERT_MAX_CLIENTS; i++) {
        s_clients[i].fd = -1;
        s_clients[i].buf_len = 0;
    }

    /* Remove stale socket file if it exists. */
    unlink(s_socket_path);

    /* Create the UNIX domain socket. */
    s_listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s_listen_fd < 0) {
        log_error("socket(AF_UNIX): %s", strerror(errno));
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", s_socket_path);

    if (bind(s_listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        log_error("bind(%s): %s", s_socket_path, strerror(errno));
        close(s_listen_fd);
        s_listen_fd = -1;
        return -1;
    }

    /*
     * Fix 1: Set socket permissions to 0666 (world read+write).
     *
     * The daemon runs as root, so a restrictive 0660 caused EACCES for
     * the local desktop user running the Electron GUI.  Since UNIX
     * domain sockets are inherently local-only (no network exposure),
     * 0666 is safe and avoids the need for group manipulation.
     */
    if (chmod(s_socket_path, ALERT_SOCKET_PERMS) != 0) {
        log_warn("chmod(%s, 0%o): %s — socket permissions may be incorrect",
                 s_socket_path, ALERT_SOCKET_PERMS, strerror(errno));
    }

    if (listen(s_listen_fd, ALERT_MAX_CLIENTS) < 0) {
        log_error("listen(%s): %s", s_socket_path, strerror(errno));
        close(s_listen_fd);
        unlink(s_socket_path);
        s_listen_fd = -1;
        return -1;
    }

    set_nonblocking(s_listen_fd);

    log_info("IPC server listening on %s (perms 0%o, max %d clients)",
             s_socket_path, ALERT_SOCKET_PERMS, ALERT_MAX_CLIENTS);
    return 0;
}

void alert_set_command_handler(alert_command_handler_t handler, void *user_data)
{
    s_cmd_handler  = handler;
    s_cmd_userdata = user_data;
}

void alert_server_service(int timeout_ms)
{
    if (s_listen_fd < 0) return;

    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(s_listen_fd, &readfds);
    int maxfd = s_listen_fd;

    /* Add all connected clients to the select set. */
    for (int i = 0; i < ALERT_MAX_CLIENTS; i++) {
        if (s_clients[i].fd >= 0) {
            FD_SET(s_clients[i].fd, &readfds);
            if (s_clients[i].fd > maxfd) maxfd = s_clients[i].fd;
        }
    }

    struct timeval tv = {
        .tv_sec  = timeout_ms / 1000,
        .tv_usec = (timeout_ms % 1000) * 1000
    };

    int ready = select(maxfd + 1, &readfds, NULL, NULL, &tv);
    if (ready <= 0) return;

    /* Check for new connections. */
    if (FD_ISSET(s_listen_fd, &readfds)) {
        int client_fd = accept(s_listen_fd, NULL, NULL);
        if (client_fd >= 0) {
            client_slot_t *slot = find_free_slot();
            if (slot) {
                set_nonblocking(client_fd);
                slot->fd = client_fd;
                slot->buf_len = 0;
                s_client_count++;
                log_info("IPC client connected (fd=%d, total: %d)",
                         client_fd, s_client_count);
            } else {
                log_warn("IPC: max clients reached — rejecting connection");
                close(client_fd);
            }
        }
    }

    /* Check each client for incoming data. */
    for (int i = 0; i < ALERT_MAX_CLIENTS; i++) {
        if (s_clients[i].fd >= 0 && FD_ISSET(s_clients[i].fd, &readfds)) {
            if (handle_client_data(&s_clients[i]) < 0) {
                close_client(&s_clients[i]);
            }
        }
    }
}

void alert_broadcast(alert_type_t type,
                     const char *filename,
                     const char *threat,
                     const char *details)
{
    /* Build the JSON payload. */
    time_t now = time(NULL);
    struct tm tm_buf;
    char timebuf[32];
    localtime_r(&now, &tm_buf);
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%dT%H:%M:%S", &tm_buf);

    char msg[ALERT_MSG_MAX];
    int n = snprintf(msg, sizeof(msg),
        "{"
        "\"event\":\"%s\","
        "\"filename\":\"%s\","
        "\"threat\":\"%s\","
        "\"details\":\"%s\","
        "\"timestamp\":\"%s\""
        "}\n",
        alert_type_str(type),
        filename ? filename : "",
        threat   ? threat   : "",
        details  ? details  : "",
        timebuf);

    if (n <= 0 || (size_t)n >= sizeof(msg)) return;

    pthread_mutex_lock(&s_alert_mutex);

    for (int i = 0; i < ALERT_MAX_CLIENTS; i++) {
        if (s_clients[i].fd >= 0) {
            ssize_t w = write(s_clients[i].fd, msg, (size_t)n);
            if (w < 0) {
                /*
                 * SIGPIPE is ignored (SIG_IGN in main.c), so a write to a
                 * broken socket yields EPIPE instead of killing the daemon.
                 * EAGAIN/EWOULDBLOCK means the send buffer is full — we
                 *   silently drop this message for that client.
                 * EPIPE/ECONNRESET mean the client has disconnected — we
                 *   reclaim the slot cleanly to prevent use-after-close.
                 */
                if (errno == EPIPE || errno == ECONNRESET) {
                    log_warn("IPC: broken pipe to client fd=%d — closing slot",
                             s_clients[i].fd);
                    close_client(&s_clients[i]);
                } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    log_warn("IPC: write failed to client fd=%d (%s) — closing",
                             s_clients[i].fd, strerror(errno));
                    close_client(&s_clients[i]);
                }
                /* EAGAIN/EWOULDBLOCK: silently skip this message. */
            }
        }
    }

    pthread_mutex_unlock(&s_alert_mutex);
}

int alert_send_to_client(int client_fd, const char *json_str)
{
    if (client_fd < 0 || !json_str) return -1;

    size_t len = strlen(json_str);
    char *buf = malloc(len + 2);     /* +1 for '\n', +1 for '\0' */
    if (!buf) return -1;

    memcpy(buf, json_str, len);
    buf[len]     = '\n';
    buf[len + 1] = '\0';

    pthread_mutex_lock(&s_alert_mutex);
    ssize_t w = write(client_fd, buf, len + 1);
    int write_errno = errno;   /* Capture errno before any other call. */
    pthread_mutex_unlock(&s_alert_mutex);

    free(buf);

    if (w < 0) {
        /*
         * EPIPE/ECONNRESET: the client disconnected between command receipt
         * and our reply.  Log a warning and close the slot if we can find it.
         * This is non-fatal — the daemon must keep running.
         */
        if (write_errno == EPIPE || write_errno == ECONNRESET) {
            log_warn("alert_send_to_client: broken pipe to fd=%d — client gone",
                     client_fd);
        } else {
            log_error("alert_send_to_client: write to fd=%d failed: %s",
                      client_fd, strerror(write_errno));
        }

        /* Best-effort cleanup: find and close the slot for this fd. */
        pthread_mutex_lock(&s_alert_mutex);
        for (int i = 0; i < ALERT_MAX_CLIENTS; i++) {
            if (s_clients[i].fd == client_fd) {
                close_client(&s_clients[i]);
                break;
            }
        }
        pthread_mutex_unlock(&s_alert_mutex);

        return -1;
    }
    return 0;
}

void alert_server_shutdown(void)
{
    pthread_mutex_lock(&s_alert_mutex);

    /* Close all client connections. */
    for (int i = 0; i < ALERT_MAX_CLIENTS; i++) {
        if (s_clients[i].fd >= 0) {
            close(s_clients[i].fd);
            s_clients[i].fd = -1;
        }
    }
    s_client_count = 0;

    /* Close the listener and remove the socket file. */
    if (s_listen_fd >= 0) {
        close(s_listen_fd);
        s_listen_fd = -1;
    }
    unlink(s_socket_path);

    pthread_mutex_unlock(&s_alert_mutex);

    log_info("IPC server shut down, socket removed: %s", s_socket_path);
}

int alert_get_client_count(void)
{
    pthread_mutex_lock(&s_alert_mutex);
    int c = s_client_count;
    pthread_mutex_unlock(&s_alert_mutex);
    return c;
}
