/*
 * monitor.h — inotify-based real-time file system monitor.
 * Watches /home and /tmp recursively for IN_CLOSE_WRITE / IN_CREATE events.
 */

#ifndef SENTINEL_MONITOR_H
#define SENTINEL_MONITOR_H

#include <stdint.h>

/* Callback invoked when a file event is detected.
 * @param filepath  Full absolute path to the new/modified file.
 * @param user_data Opaque pointer passed during monitor_start(). */
typedef void (*monitor_callback_t)(const char *filepath, void *user_data);

/* Opaque monitor context */
typedef struct monitor_ctx monitor_ctx_t;

/**
 * Create and initialise a monitor context.
 * @param dirs      NULL-terminated array of directory paths to watch.
 * @param callback  Function to invoke on file events.
 * @param user_data Opaque pointer forwarded to the callback.
 * @return          Allocated context, or NULL on failure.
 */
monitor_ctx_t *monitor_create(const char **dirs,
                              monitor_callback_t callback,
                              void *user_data);

/**
 * Enter the blocking event loop.
 * Returns only on error or when monitor_stop() is called from another thread.
 * @return 0 on clean shutdown, -1 on error.
 */
int monitor_run(monitor_ctx_t *ctx);

/**
 * Signal the monitor loop to exit.  Thread-safe.
 */
void monitor_stop(monitor_ctx_t *ctx);

/**
 * Free all resources held by the monitor context.
 */
void monitor_destroy(monitor_ctx_t *ctx);

#endif /* SENTINEL_MONITOR_H */
