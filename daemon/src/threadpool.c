/*
 * threadpool.c — Bounded work-queue thread pool (pthreads).
 *
 * Workers block on a condition variable when the queue is empty and wake
 * up via pthread_cond_signal() when work is submitted.  The queue is a
 * circular buffer of heap-allocated file-path strings.
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

    /* --- Lifecycle ----------------------------------------------------- */
    volatile int     shutdown;      /* Set to 1 to stop all workers       */

    /* --- Callback ------------------------------------------------------ */
    threadpool_work_fn work_fn;     /* Scan pipeline function              */
    void              *user_data;   /* Forwarded to work_fn                */

    /* --- Stats --------------------------------------------------------- */
    unsigned long     submitted;    /* Total paths submitted               */
    unsigned long     dropped;      /* Paths dropped due to full queue     */
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
        pthread_cond_init(&pool->not_empty, NULL) != 0) {
        free(pool->queue);
        free(pool);
        return NULL;
    }

    /* Allocate and spawn worker threads. */
    pool->threads = calloc((size_t)num_threads, sizeof(pthread_t));
    if (!pool->threads) {
        pthread_mutex_destroy(&pool->mutex);
        pthread_cond_destroy(&pool->not_empty);
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

int threadpool_submit(threadpool_t *pool, const char *filepath)
{
    if (!pool || !filepath) return -1;

    char *dup = strdup(filepath);
    if (!dup) {
        log_error("threadpool_submit: strdup failed for %s", filepath);
        return -1;
    }

    pthread_mutex_lock(&pool->mutex);

    if (pool->shutdown) {
        pthread_mutex_unlock(&pool->mutex);
        free(dup);
        return -1;
    }

    if (pool->count >= pool->capacity) {
        /* Queue full — drop the oldest entry to make room. */
        char *dropped = pool->queue[pool->tail];
        if (dropped) {
            log_warn("threadpool: queue full — dropping oldest: %s", dropped);
            free(dropped);
        }
        pool->tail = (pool->tail + 1) % pool->capacity;
        pool->count--;
        pool->dropped++;
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

    log_info("Thread pool shutting down (submitted=%lu, processed=%lu, "
             "dropped=%lu)...", pool->submitted, pool->processed,
             pool->dropped);

    /* Signal all workers to exit. */
    pthread_mutex_lock(&pool->mutex);
    pool->shutdown = 1;
    pthread_cond_broadcast(&pool->not_empty);
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

    /* Clean up. */
    pthread_mutex_destroy(&pool->mutex);
    pthread_cond_destroy(&pool->not_empty);
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
