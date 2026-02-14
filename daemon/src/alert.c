/*
 * alert.c — WebSocket alert server using libwebsockets.
 *
 * Broadcasts JSON payloads to all connected Electron GUI clients.
 * Part of the Sentinel Endpoint Security daemon.
 */

#include "alert.h"
#include "logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <libwebsockets.h>

/* ── Internal types ─────────────────────────────────────────────────────── */

/* Per-session data for each connected client. */
typedef struct {
    int dummy;   /* libwebsockets requires at least something */
} per_session_data_t;

/* Pending message ring-buffer entry. */
#define MSG_RING_SIZE  64
#define MSG_MAX_LEN   2048

typedef struct {
    char   buf[LWS_PRE + MSG_MAX_LEN];
    size_t len;
} msg_slot_t;

/* ── Private state ──────────────────────────────────────────────────────── */

static struct lws_context *s_ws_ctx      = NULL;
static int                 s_client_count = 0;
static pthread_mutex_t     s_alert_mutex  = PTHREAD_MUTEX_INITIALIZER;

/* Simple ring buffer for outgoing messages. */
static msg_slot_t  s_ring[MSG_RING_SIZE];
static int         s_ring_head = 0;
static int         s_ring_tail = 0;

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
    default:                      return "unknown";
    }
}

static int ring_empty(void)   { return s_ring_head == s_ring_tail; }
static int ring_next(int idx) { return (idx + 1) % MSG_RING_SIZE; }

/* ── libwebsockets callback ─────────────────────────────────────────────── */

static int ws_callback(struct lws *wsi,
                       enum lws_callback_reasons reason,
                       void *user,
                       void *in,
                       size_t len)
{
    (void)user; (void)in; (void)len;

    switch (reason) {

    case LWS_CALLBACK_ESTABLISHED:
        pthread_mutex_lock(&s_alert_mutex);
        s_client_count++;
        pthread_mutex_unlock(&s_alert_mutex);
        log_info("WebSocket client connected (total: %d)", s_client_count);
        break;

    case LWS_CALLBACK_CLOSED:
        pthread_mutex_lock(&s_alert_mutex);
        if (s_client_count > 0) s_client_count--;
        pthread_mutex_unlock(&s_alert_mutex);
        log_info("WebSocket client disconnected (total: %d)", s_client_count);
        break;

    case LWS_CALLBACK_SERVER_WRITEABLE: {
        pthread_mutex_lock(&s_alert_mutex);
        if (!ring_empty()) {
            msg_slot_t *slot = &s_ring[s_ring_tail];
            lws_write(wsi,
                      (unsigned char *)slot->buf + LWS_PRE,
                      slot->len,
                      LWS_WRITE_TEXT);
            s_ring_tail = ring_next(s_ring_tail);
        }
        /* If more messages remain, request another writable callback. */
        if (!ring_empty())
            lws_callback_on_writable(wsi);
        pthread_mutex_unlock(&s_alert_mutex);
        break;
    }

    case LWS_CALLBACK_RECEIVE: {
        /*
         * Handle commands from the GUI (restore / delete).
         * Expected JSON: { "action": "restore"|"delete", "id": "<quarantine_id>" }
         * We simply log it here — actual handling is in main.c's command dispatcher.
         */
        if (in && len > 0) {
            char msg[MSG_MAX_LEN];
            size_t copy = len < sizeof(msg) - 1 ? len : sizeof(msg) - 1;
            memcpy(msg, in, copy);
            msg[copy] = '\0';
            log_info("Received from GUI: %s", msg);
        }
        break;
    }

    default:
        break;
    }

    return 0;
}

/* Protocol definition */
static struct lws_protocols s_protocols[] = {
    {
        .name                  = "sentinel-alert",
        .callback              = ws_callback,
        .per_session_data_size = sizeof(per_session_data_t),
        .rx_buffer_size        = 4096,
    },
    LWS_PROTOCOL_LIST_TERM
};

/* ── Public API ─────────────────────────────────────────────────────────── */

int alert_server_init(int port)
{
    struct lws_context_creation_info info;
    memset(&info, 0, sizeof(info));

    info.port      = port;
    info.protocols = s_protocols;
    info.gid       = -1;
    info.uid       = -1;
    info.options   = LWS_SERVER_OPTION_VALIDATE_UTF8;

    /* Suppress libwebsockets internal logging by default. */
    lws_set_log_level(LLL_ERR | LLL_WARN, NULL);

    s_ws_ctx = lws_create_context(&info);
    if (!s_ws_ctx) {
        log_error("Failed to create WebSocket context on port %d", port);
        return -1;
    }

    log_info("WebSocket alert server started on ws://127.0.0.1:%d", port);
    return 0;
}

void alert_server_service(int timeout_ms)
{
    if (s_ws_ctx)
        lws_service(s_ws_ctx, timeout_ms);
}

void alert_broadcast(alert_type_t type,
                     const char *filename,
                     const char *threat,
                     const char *details)
{
    if (!s_ws_ctx) return;

    pthread_mutex_lock(&s_alert_mutex);

    int next = ring_next(s_ring_head);
    if (next == s_ring_tail) {
        /* Ring full — drop oldest. */
        s_ring_tail = ring_next(s_ring_tail);
    }

    msg_slot_t *slot = &s_ring[s_ring_head];

    /* Build JSON payload. */
    time_t now = time(NULL);
    struct tm tm_buf;
    char timebuf[32];
    localtime_r(&now, &tm_buf);
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%dT%H:%M:%S", &tm_buf);

    int n = snprintf(slot->buf + LWS_PRE, MSG_MAX_LEN,
        "{"
        "\"event\":\"%s\","
        "\"filename\":\"%s\","
        "\"threat\":\"%s\","
        "\"details\":\"%s\","
        "\"timestamp\":\"%s\""
        "}",
        alert_type_str(type),
        filename  ? filename  : "",
        threat    ? threat    : "",
        details   ? details   : "",
        timebuf);

    slot->len = (size_t)(n > 0 ? n : 0);
    s_ring_head = next;

    pthread_mutex_unlock(&s_alert_mutex);

    /* Request writable callback on all connected clients. */
    lws_callback_on_writable_all_protocol(s_ws_ctx, &s_protocols[0]);
}

void alert_server_shutdown(void)
{
    if (s_ws_ctx) {
        lws_context_destroy(s_ws_ctx);
        s_ws_ctx = NULL;
    }
    log_info("WebSocket alert server shut down.");
}

int alert_get_client_count(void)
{
    pthread_mutex_lock(&s_alert_mutex);
    int c = s_client_count;
    pthread_mutex_unlock(&s_alert_mutex);
    return c;
}
