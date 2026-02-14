/*
 * threadpool.c — Bounded work-queue thread pool (pthreads).
 *
 * Workers block on a condition variable when the queue is empty and wake
 * up via pthread_cond_signal() when work is submitted.  The queue is a
 * circular buffer of heap-allocated file-path strings.
 *
 * Fix 2: The producer (threadpool_submit) now BLOCKS when the queue is
 *        full instead of dropping entries.  A `not_full` condition variable
 *        is used so the inotify thread waits until a worker frees a slot.
 *        This eliminates the malware bypass vulnerability where scans
 *        could be silently skipped under load.
 *
 * Memory management:
 *   - threadpool_submit() strdup()s the incoming path.
 *   - The worker function receives ownership and MUST free() the path.
 *   - threadpool_shutdown() frees any paths remaining in the queue.
 *
 * Part of the Sentinel Endpoint Security daemon.
 */

#include "threadpool.h"
#include "logger.h"

#include <stdlib.h>
#include <string.h>
#include <pthread.h>

/* ── Internal types ─────────────────────────────────────────────────────── */

struct threadpool {
    /* --- Worker threads ------------------------------------------------ */
    pthread_t       *threads;       /* Array of worker thread IDs          */
    int              num_threads;   /* Number of workers                   */

    /* --- Bounded circular queue ---------------------------------------- */
    char           **queue;         /* Array of heap-allocated path strings */
    int              capacity;      /* Maximum queue depth                 */
    int              head;          /* Next write position                 */
    int              tail;          /* Next read position                  */
    int              count;         /* Current number of queued items      */

    /* --- Synchronisation ---------------------------------------------- */
    pthread_mutex_t  mutex;         /* Protects queue + shutdown flag      */
    pthread_cond_t   not_empty;     /* Signalled when work is available    */
    pthread_cond_t   not_full;      /* Fix 2: signalled when a slot frees  */

    /* --- Lifecycle ----------------------------------------------------- */
    volatile int     shutdown;      /* Set to 1 to stop all workers       */

    /* --- Callback ------------------------------------------------------ */
    threadpool_work_fn work_fn;     /* Scan pipeline function              */
    void              *user_data;   /* Forwarded to work_fn                */

    /* --- Stats --------------------------------------------------------- */
    unsigned long     submitted;    /* Total paths submitted               */
    unsigned long     processed;    /* Paths successfully dequeued         */
};

/* ── Worker thread entry point ──────────────────────────────────────────── */

static void *worker_main(void *arg)
{
    threadpool_t *pool = (threadpool_t *)arg;

    for (;;) {
        pthread_mutex_lock(&pool->mutex);

        /* Wait until there is work or a shutdown signal. */
        while (pool->count == 0 && !pool->shutdown) {
            pthread_cond_wait(&pool->not_empty, &pool->mutex);
        }

        /* If shutting down and queue is empty, exit. */
        if (pool->shutdown && pool->count == 0) {
            pthread_mutex_unlock(&pool->mutex);
            break;
        }

        /* Dequeue the oldest path. */
        char *filepath = pool->queue[pool->tail];
        pool->queue[pool->tail] = NULL;
        pool->tail = (pool->tail + 1) % pool->capacity;
        pool->count--;
        pool->processed++;

        /*
         * Fix 2: Signal the producer (inotify thread) that a queue slot
         * has been freed.  This unblocks threadpool_submit() if it was
         * waiting on a full queue.
         */
        pthread_cond_signal(&pool->not_full);

        pthread_mutex_unlock(&pool->mutex);

        /* Execute the work function (scan → quarantine → alert).
         * The work_fn is responsible for free()ing filepath.           */
        if (filepath) {
            pool->work_fn(filepath, pool->user_data);
        }
    }

    return NULL;
}

/* ── Public API ─────────────────────────────────────────────────────────── */

threadpool_t *threadpool_create(int num_threads,
                                int capacity,
                                threadpool_work_fn work_fn,
                                void *user_data)
{
    if (num_threads <= 0 || capacity <= 0 || !work_fn) {
        log_error("threadpool_create: invalid arguments "
                  "(threads=%d, capacity=%d)", num_threads, capacity);
        return NULL;
    }

    threadpool_t *pool = calloc(1, sizeof(*pool));
    if (!pool) return NULL;

    pool->num_threads = num_threads;
    pool->capacity    = capacity;
    pool->work_fn     = work_fn;
    pool->user_data   = user_data;

    /* Allocate the circular queue. */
    pool->queue = calloc((size_t)capacity, sizeof(char *));
    if (!pool->queue) {
        free(pool);
        return NULL;
    }

    /* Initialise synchronisation primitives. */
    if (pthread_mutex_init(&pool->mutex, NULL) != 0 ||
        pthread_cond_init(&pool->not_empty, NULL) != 0 ||
        pthread_cond_init(&pool->not_full, NULL) != 0) {  /* Fix 2 */
        free(pool->queue);
        free(pool);
        return NULL;
    }

    /* Allocate and spawn worker threads. */
    pool->threads = calloc((size_t)num_threads, sizeof(pthread_t));
    if (!pool->threads) {
        pthread_mutex_destroy(&pool->mutex);
        pthread_cond_destroy(&pool->not_empty);
        pthread_cond_destroy(&pool->not_full);
        free(pool->queue);
        free(pool);
        return NULL;
    }

    for (int i = 0; i < num_threads; i++) {
        if (pthread_create(&pool->threads[i], NULL, worker_main, pool) != 0) {
            log_error("threadpool: failed to create worker thread %d", i);
            /* Shut down the threads we did manage to create. */
            pool->num_threads = i;
            threadpool_shutdown(pool);
            return NULL;
        }
    }

    log_info("Thread pool created: %d workers, queue capacity %d",
             num_threads, capacity);
    return pool;
}

/**
 * Submit a file path for asynchronous processing.
 *
 * Fix 2: If the queue is full, the caller (inotify monitor thread) BLOCKS
 * until a worker thread dequeues an item and signals `not_full`.  This
 * guarantees that NO file scan is ever silently dropped — every detected
 * file will be scanned.  The trade-off is that the inotify event buffer
 * may grow if ClamAV is slow, but this is strictly better than silently
 * bypassing the antivirus.
 */
int threadpool_submit(threadpool_t *pool, const char *filepath)
{
    if (!pool || !filepath) return -1;

    char *dup = strdup(filepath);
    if (!dup) {
        log_error("threadpool_submit: strdup failed for %s", filepath);
        return -1;
    }

    pthread_mutex_lock(&pool->mutex);

    /* If we're shutting down, reject immediately. */
    if (pool->shutdown) {
        pthread_mutex_unlock(&pool->mutex);
        free(dup);
        return -1;
    }

    /*
     * Fix 2: Block the producer until queue has space.
     *
     * We also check `pool->shutdown` on each wakeup so that
     * threadpool_shutdown() can unblock a stuck producer via
     * pthread_cond_broadcast(&pool->not_full).
     */
    while (pool->count >= pool->capacity && !pool->shutdown) {
        log_warn("threadpool: queue full (%d/%d) — blocking producer "
                 "until a worker frees a slot", pool->count, pool->capacity);
        pthread_cond_wait(&pool->not_full, &pool->mutex);
    }

    /* Re-check shutdown after waking up. */
    if (pool->shutdown) {
        pthread_mutex_unlock(&pool->mutex);
        free(dup);
        return -1;
    }

    /* Enqueue the new path. */
    pool->queue[pool->head] = dup;
    pool->head = (pool->head + 1) % pool->capacity;
    pool->count++;
    pool->submitted++;

    /* Wake one sleeping worker. */
    pthread_cond_signal(&pool->not_empty);

    pthread_mutex_unlock(&pool->mutex);
    return 0;
}

void threadpool_shutdown(threadpool_t *pool)
{
    if (!pool) return;

    log_info("Thread pool shutting down (submitted=%lu, processed=%lu)...",
             pool->submitted, pool->processed);

    /* Signal all workers and any blocked producer to exit. */
    pthread_mutex_lock(&pool->mutex);
    pool->shutdown = 1;
    pthread_cond_broadcast(&pool->not_empty);  /* Wake all workers.    */
    pthread_cond_broadcast(&pool->not_full);   /* Fix 2: unblock submit. */
    pthread_mutex_unlock(&pool->mutex);

    /* Join all worker threads. */
    for (int i = 0; i < pool->num_threads; i++) {
        pthread_join(pool->threads[i], NULL);
    }

    /* Free any paths still in the queue. */
    for (int i = 0; i < pool->capacity; i++) {
        if (pool->queue[i]) {
            free(pool->queue[i]);
            pool->queue[i] = NULL;
        }
    }

    /* Clean up all synchronisation primitives. */
    pthread_mutex_destroy(&pool->mutex);
    pthread_cond_destroy(&pool->not_empty);
    pthread_cond_destroy(&pool->not_full);    /* Fix 2 */
    free(pool->threads);
    free(pool->queue);
    free(pool);

    log_info("Thread pool destroyed.");
}

int threadpool_queue_size(threadpool_t *pool)
{
    if (!pool) return 0;
    /* Non-atomic read — approximate is fine for monitoring. */
    return pool->count;
}
