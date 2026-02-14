/*
 * threadpool.h — Thread pool with bounded work queue.
 *
 * Provides asynchronous file-scanning dispatch so the inotify monitor
 * never blocks on ClamAV I/O.  Workers dequeue file paths and run the
 * scan → quarantine → alert pipeline independently.
 *
 * Part of the Sentinel Endpoint Security daemon.
 */

#ifndef SENTINEL_THREADPOOL_H
#define SENTINEL_THREADPOOL_H

#include <stddef.h>

/* Default number of worker threads */
#define THREADPOOL_DEFAULT_THREADS  4

/* Default work-queue capacity (paths). Beyond this, oldest entries are dropped. */
#define THREADPOOL_DEFAULT_CAPACITY 256

/* Opaque thread pool handle */
typedef struct threadpool threadpool_t;

/**
 * Callback executed by each worker for every dequeued file path.
 * @param filepath  Heap-allocated path string — the callback MUST free() it.
 * @param user_data Opaque pointer registered at creation time.
 */
typedef void (*threadpool_work_fn)(char *filepath, void *user_data);

/**
 * Create a thread pool.
 *
 * @param num_threads  Number of worker pthreads to spawn.
 * @param capacity     Maximum queue depth before oldest entries are dropped.
 * @param work_fn      Function each worker invokes per dequeued path.
 * @param user_data    Forwarded to work_fn on every invocation.
 * @return Allocated pool handle, or NULL on failure.
 */
threadpool_t *threadpool_create(int num_threads,
                                int capacity,
                                threadpool_work_fn work_fn,
                                void *user_data);

/**
 * Submit a file path for asynchronous processing.
 *
 * The path is strdup()'d internally — the caller retains ownership of
 * the original string.  If the queue is full the oldest entry is dropped
 * and a warning is logged.
 *
 * This function is thread-safe and non-blocking.
 *
 * @param pool     Pool handle.
 * @param filepath Absolute file path to enqueue.
 * @return 0 on success, -1 on error.
 */
int threadpool_submit(threadpool_t *pool, const char *filepath);

/**
 * Gracefully shut down the pool.
 *
 * Sets the shutdown flag, broadcasts the condition variable so all
 * sleeping workers wake up, then pthread_join()s every thread.
 * Any paths still in the queue are freed.
 *
 * @param pool Pool handle (freed after this call — do not reuse).
 */
void threadpool_shutdown(threadpool_t *pool);

/**
 * Return the number of items currently queued (approximate, lock-free read).
 */
int threadpool_queue_size(threadpool_t *pool);

#endif /* SENTINEL_THREADPOOL_H */
