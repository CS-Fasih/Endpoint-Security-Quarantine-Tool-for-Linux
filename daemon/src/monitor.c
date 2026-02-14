/*
 * monitor.c — Recursive inotify file-system watcher.
 *
 * Watches configured directories for IN_CLOSE_WRITE and IN_CREATE events
 * and dispatches file paths to the registered callback.
 *
 * Part of the Sentinel Endpoint Security daemon.
 */

#include "monitor.h"
#include "logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/inotify.h>
#include <poll.h>
#include <pthread.h>

/* ── Internal types ─────────────────────────────────────────────────────── */

/* Hash-map bucket for watch-descriptor → directory-path mapping. */
typedef struct wd_entry {
    int              wd;
    char             path[4096];
    struct wd_entry *next;
} wd_entry_t;

#define WD_MAP_BUCKETS 1024

struct monitor_ctx {
    int                inotify_fd;
    volatile int       running;

    monitor_callback_t callback;
    void              *user_data;

    wd_entry_t        *wd_map[WD_MAP_BUCKETS];   /* wd → path */
};

/* ── Watch-descriptor map helpers ───────────────────────────────────────── */

static unsigned wd_hash(int wd)
{
    return (unsigned)wd % WD_MAP_BUCKETS;
}

static void wd_map_put(monitor_ctx_t *ctx, int wd, const char *path)
{
    unsigned idx = wd_hash(wd);

    wd_entry_t *e = malloc(sizeof(*e));
    if (!e) return;

    e->wd = wd;
    snprintf(e->path, sizeof(e->path), "%s", path);
    e->next = ctx->wd_map[idx];
    ctx->wd_map[idx] = e;
}

static const char *wd_map_get(monitor_ctx_t *ctx, int wd)
{
    unsigned idx = wd_hash(wd);
    for (wd_entry_t *e = ctx->wd_map[idx]; e; e = e->next) {
        if (e->wd == wd) return e->path;
    }
    return NULL;
}

static void wd_map_free(monitor_ctx_t *ctx)
{
    for (int i = 0; i < WD_MAP_BUCKETS; i++) {
        wd_entry_t *e = ctx->wd_map[i];
        while (e) {
            wd_entry_t *tmp = e;
            e = e->next;
            free(tmp);
        }
        ctx->wd_map[i] = NULL;
    }
}

/* ── Recursive watch helpers ────────────────────────────────────────────── */

static const uint32_t WATCH_MASK =
    IN_CLOSE_WRITE | IN_CREATE | IN_MOVED_TO | IN_ISDIR;

static int add_watch_recursive(monitor_ctx_t *ctx, const char *dir_path)
{
    int wd = inotify_add_watch(ctx->inotify_fd, dir_path, WATCH_MASK);
    if (wd < 0) {
        if (errno == EACCES || errno == ENOENT) {
            /* Permission denied or gone — skip silently. */
            return 0;
        }
        log_error("inotify_add_watch(%s): %s", dir_path, strerror(errno));
        return -1;
    }
    wd_map_put(ctx, wd, dir_path);

    DIR *dp = opendir(dir_path);
    if (!dp) return 0;   /* can't recurse — fine */

    struct dirent *de;
    while ((de = readdir(dp)) != NULL) {
        if (de->d_name[0] == '.') continue;    /* skip hidden */
        if (de->d_type != DT_DIR) continue;

        char child[4096];
        snprintf(child, sizeof(child), "%s/%s", dir_path, de->d_name);

        add_watch_recursive(ctx, child);
    }
    closedir(dp);
    return 0;
}

/* ── Public API ─────────────────────────────────────────────────────────── */

monitor_ctx_t *monitor_create(const char **dirs,
                              monitor_callback_t callback,
                              void *user_data)
{
    if (!dirs || !callback) return NULL;

    monitor_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;

    ctx->callback  = callback;
    ctx->user_data = user_data;
    ctx->running   = 1;

    ctx->inotify_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (ctx->inotify_fd < 0) {
        log_error("inotify_init1(): %s", strerror(errno));
        free(ctx);
        return NULL;
    }

    for (int i = 0; dirs[i]; i++) {
        log_info("Adding recursive watch on: %s", dirs[i]);
        if (add_watch_recursive(ctx, dirs[i]) < 0) {
            log_warn("Partial failure adding watches for %s", dirs[i]);
        }
    }

    return ctx;
}

int monitor_run(monitor_ctx_t *ctx)
{
    if (!ctx) return -1;

    /*
     * Aligned buffer for inotify events.
     * Each event is sizeof(struct inotify_event) + name_len.
     */
    char buf[8192] __attribute__((aligned(__alignof__(struct inotify_event))));

    struct pollfd pfd = {
        .fd     = ctx->inotify_fd,
        .events = POLLIN
    };

    log_info("Monitor event loop started.");

    while (ctx->running) {
        int ret = poll(&pfd, 1, 500);    /* 500 ms timeout for shutdown check */
        if (ret < 0) {
            if (errno == EINTR) continue;
            log_error("poll(): %s", strerror(errno));
            return -1;
        }
        if (ret == 0) continue;          /* timeout — loop back */

        ssize_t len = read(ctx->inotify_fd, buf, sizeof(buf));
        if (len <= 0) continue;

        const struct inotify_event *event;
        for (char *ptr = buf; ptr < buf + len;
             ptr += sizeof(struct inotify_event) + event->len) {

            event = (const struct inotify_event *)ptr;
            if (event->len == 0) continue;

            /* Skip hidden files and directories */
            if (event->name[0] == '.') continue;

            const char *parent = wd_map_get(ctx, event->wd);
            if (!parent) continue;

            char fullpath[4096];
            snprintf(fullpath, sizeof(fullpath), "%s/%s", parent, event->name);

            /* If a new sub-directory is created, add a recursive watch. */
            if (event->mask & IN_ISDIR) {
                if (event->mask & (IN_CREATE | IN_MOVED_TO)) {
                    add_watch_recursive(ctx, fullpath);
                    log_info("New directory watch added: %s", fullpath);
                }
                continue;   /* Don't scan directories themselves. */
            }

            /* Regular file event → invoke callback. */
            struct stat st;
            if (stat(fullpath, &st) == 0 && S_ISREG(st.st_mode)) {
                log_info("File event detected: %s", fullpath);
                ctx->callback(fullpath, ctx->user_data);
            }
        }
    }

    log_info("Monitor event loop exited.");
    return 0;
}

void monitor_stop(monitor_ctx_t *ctx)
{
    if (ctx) ctx->running = 0;
}

void monitor_destroy(monitor_ctx_t *ctx)
{
    if (!ctx) return;

    if (ctx->inotify_fd >= 0)
        close(ctx->inotify_fd);

    wd_map_free(ctx);
    free(ctx);
}
