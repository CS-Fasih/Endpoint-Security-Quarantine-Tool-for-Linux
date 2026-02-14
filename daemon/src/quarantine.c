/*
 * quarantine.c — File quarantine: isolate, restore, and delete infected files.
 *
 * Manages a JSON manifest at /opt/quarantine/.manifest.json using json-c.
 * Part of the Sentinel Endpoint Security daemon.
 */

#include "quarantine.h"
#include "logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <pthread.h>
#include <json-c/json.h>

/* ── Private state ──────────────────────────────────────────────────────── */

static json_object       *s_manifest = NULL;     /* JSON array */
static pthread_mutex_t    s_qr_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ── Helpers ────────────────────────────────────────────────────────────── */

/**
 * Generate a simple pseudo-UUID (good enough for quarantine IDs).
 * Format: 8-4-4-4-12 hex string.
 */
static void generate_uuid(char *buf, size_t len)
{
    static int seeded = 0;
    if (!seeded) { srand((unsigned)time(NULL) ^ (unsigned)getpid()); seeded = 1; }

    const char hex[] = "0123456789abcdef";
    const int pattern[] = {8, 4, 4, 4, 12};   /* group sizes */
    size_t pos = 0;

    for (int g = 0; g < 5 && pos < len - 1; g++) {
        if (g > 0 && pos < len - 1) buf[pos++] = '-';
        for (int i = 0; i < pattern[g] && pos < len - 1; i++)
            buf[pos++] = hex[rand() % 16];
    }
    buf[pos] = '\0';
}

/**
 * Flush the in-memory manifest array to disk.
 */
static int manifest_save(void)
{
    const char *json_str = json_object_to_json_string_ext(
        s_manifest, JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_NOSLASHESCAPE);

    FILE *fp = fopen(QUARANTINE_MANIFEST, "w");
    if (!fp) {
        log_error("Cannot write manifest: %s", strerror(errno));
        return -1;
    }
    fputs(json_str, fp);
    fputc('\n', fp);
    fclose(fp);
    return 0;
}

/**
 * Load the manifest from disk into memory.
 */
static int manifest_load(void)
{
    if (s_manifest) {
        json_object_put(s_manifest);
        s_manifest = NULL;
    }

    struct stat st;
    if (stat(QUARANTINE_MANIFEST, &st) != 0) {
        /* No manifest yet — create empty array. */
        s_manifest = json_object_new_array();
        return 0;
    }

    s_manifest = json_object_from_file(QUARANTINE_MANIFEST);
    if (!s_manifest || !json_object_is_type(s_manifest, json_type_array)) {
        log_warn("Corrupt manifest file — reinitialising.");
        if (s_manifest) json_object_put(s_manifest);
        s_manifest = json_object_new_array();
    }

    return 0;
}

/**
 * Find a manifest entry by quarantine ID.
 * Returns the array index or -1 if not found.
 */
static int manifest_find(const char *qid)
{
    int n = (int)json_object_array_length(s_manifest);
    for (int i = 0; i < n; i++) {
        json_object *entry = json_object_array_get_idx(s_manifest, (size_t)i);
        json_object *jid;
        if (json_object_object_get_ex(entry, "id", &jid) &&
            strcmp(json_object_get_string(jid), qid) == 0) {
            return i;
        }
    }
    return -1;
}

/**
 * Copy a file byte-by-byte (rename() fails across filesystems).
 */
static int copy_file(const char *src, const char *dst)
{
    int sfd = open(src, O_RDONLY);
    if (sfd < 0) return -1;

    int dfd = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (dfd < 0) { close(sfd); return -1; }

    char buf[8192];
    ssize_t n;
    while ((n = read(sfd, buf, sizeof(buf))) > 0) {
        ssize_t written = 0;
        while (written < n) {
            ssize_t w = write(dfd, buf + written, (size_t)(n - written));
            if (w < 0) { close(sfd); close(dfd); unlink(dst); return -1; }
            written += w;
        }
    }

    close(sfd);
    close(dfd);
    return 0;
}

/* ── Public API ─────────────────────────────────────────────────────────── */

int quarantine_init(void)
{
    struct stat st;
    if (stat(QUARANTINE_DIR, &st) != 0) {
        if (mkdir(QUARANTINE_DIR, 0700) != 0) {
            log_error("Cannot create quarantine dir: %s", strerror(errno));
            return -1;
        }
        log_info("Created quarantine directory: %s", QUARANTINE_DIR);
    }

    if (manifest_load() != 0) return -1;

    int count = (int)json_object_array_length(s_manifest);
    log_info("Quarantine initialised — %d existing entries.", count);
    return 0;
}

int quarantine_file(const char *filepath, const char *threat_name)
{
    if (!filepath || !threat_name) return -1;

    pthread_mutex_lock(&s_qr_mutex);

    /* 1. Strip all permissions immediately. */
    if (chmod(filepath, 0000) != 0) {
        log_error("chmod 000 failed on %s: %s", filepath, strerror(errno));
        /* Continue anyway — we still want to move it. */
    }

    /* 2. Generate quarantine ID and destination path. */
    char qid[64];
    generate_uuid(qid, sizeof(qid));

    /* Extract base filename. */
    const char *basename = strrchr(filepath, '/');
    basename = basename ? basename + 1 : filepath;

    char qpath[QR_MAX_PATH];
    snprintf(qpath, sizeof(qpath), "%s/%s_%s", QUARANTINE_DIR, qid, basename);

    /* 3. Move (or copy + delete) the file. */
    int moved = 0;
    if (rename(filepath, qpath) == 0) {
        moved = 1;
    } else {
        /* rename() fails across mount points — fall back to copy. */
        /* First restore read permission temporarily so we can copy. */
        chmod(filepath, 0400);
        if (copy_file(filepath, qpath) == 0) {
            unlink(filepath);
            moved = 1;
        } else {
            log_error("Failed to move/copy %s → %s: %s",
                      filepath, qpath, strerror(errno));
        }
    }

    if (!moved) {
        pthread_mutex_unlock(&s_qr_mutex);
        return -1;
    }

    /* Ensure quarantined file has no permissions. */
    chmod(qpath, 0000);

    /* 4. Add entry to manifest. */
    json_object *entry = json_object_new_object();
    json_object_object_add(entry, "id",
                           json_object_new_string(qid));
    json_object_object_add(entry, "original_path",
                           json_object_new_string(filepath));
    json_object_object_add(entry, "quarantine_path",
                           json_object_new_string(qpath));
    json_object_object_add(entry, "threat_name",
                           json_object_new_string(threat_name));
    json_object_object_add(entry, "timestamp",
                           json_object_new_int64((int64_t)time(NULL)));

    json_object_array_add(s_manifest, entry);
    manifest_save();

    log_info("Quarantined: %s → %s [%s]", filepath, qpath, threat_name);

    pthread_mutex_unlock(&s_qr_mutex);
    return 0;
}

int quarantine_restore(const char *quarantine_id)
{
    if (!quarantine_id) return -1;

    pthread_mutex_lock(&s_qr_mutex);

    int idx = manifest_find(quarantine_id);
    if (idx < 0) {
        log_error("Quarantine ID not found: %s", quarantine_id);
        pthread_mutex_unlock(&s_qr_mutex);
        return -1;
    }

    json_object *entry = json_object_array_get_idx(s_manifest, (size_t)idx);
    json_object *j_orig, *j_qpath;
    json_object_object_get_ex(entry, "original_path",    &j_orig);
    json_object_object_get_ex(entry, "quarantine_path",  &j_qpath);

    const char *orig  = json_object_get_string(j_orig);
    const char *qpath = json_object_get_string(j_qpath);

    /* Temporarily restore read permissions to allow move/copy. */
    chmod(qpath, 0400);

    int restored = 0;
    if (rename(qpath, orig) == 0) {
        restored = 1;
    } else {
        if (copy_file(qpath, orig) == 0) {
            unlink(qpath);
            restored = 1;
        }
    }

    if (!restored) {
        log_error("Failed to restore %s → %s", qpath, orig);
        chmod(qpath, 0000);   /* Re-lock it. */
        pthread_mutex_unlock(&s_qr_mutex);
        return -1;
    }

    /* Restore sensible permissions (owner rw). */
    chmod(orig, 0644);

    /* Remove entry from manifest. */
    json_object_array_del_idx(s_manifest, (size_t)idx, 1);
    manifest_save();

    log_info("Restored quarantined file: %s → %s", qpath, orig);

    pthread_mutex_unlock(&s_qr_mutex);
    return 0;
}

int quarantine_delete(const char *quarantine_id)
{
    if (!quarantine_id) return -1;

    pthread_mutex_lock(&s_qr_mutex);

    int idx = manifest_find(quarantine_id);
    if (idx < 0) {
        log_error("Quarantine ID not found: %s", quarantine_id);
        pthread_mutex_unlock(&s_qr_mutex);
        return -1;
    }

    json_object *entry = json_object_array_get_idx(s_manifest, (size_t)idx);
    json_object *j_qpath;
    json_object_object_get_ex(entry, "quarantine_path", &j_qpath);
    const char *qpath = json_object_get_string(j_qpath);

    /* Need write permission to delete. */
    chmod(qpath, 0600);

    if (unlink(qpath) != 0) {
        log_error("Failed to delete %s: %s", qpath, strerror(errno));
        pthread_mutex_unlock(&s_qr_mutex);
        return -1;
    }

    json_object_array_del_idx(s_manifest, (size_t)idx, 1);
    manifest_save();

    log_info("Permanently deleted quarantined file: %s", qpath);

    pthread_mutex_unlock(&s_qr_mutex);
    return 0;
}

int quarantine_list(quarantine_entry_t **entries, int *count)
{
    if (!entries || !count) return -1;

    pthread_mutex_lock(&s_qr_mutex);

    int n = (int)json_object_array_length(s_manifest);
    if (n == 0) {
        *entries = NULL;
        *count = 0;
        pthread_mutex_unlock(&s_qr_mutex);
        return 0;
    }

    quarantine_entry_t *arr = calloc((size_t)n, sizeof(*arr));
    if (!arr) {
        pthread_mutex_unlock(&s_qr_mutex);
        return -1;
    }

    for (int i = 0; i < n; i++) {
        json_object *e = json_object_array_get_idx(s_manifest, (size_t)i);
        json_object *jval;

        if (json_object_object_get_ex(e, "id", &jval))
            snprintf(arr[i].id, sizeof(arr[i].id), "%s",
                     json_object_get_string(jval));

        if (json_object_object_get_ex(e, "original_path", &jval))
            snprintf(arr[i].original_path, sizeof(arr[i].original_path), "%s",
                     json_object_get_string(jval));

        if (json_object_object_get_ex(e, "quarantine_path", &jval))
            snprintf(arr[i].quarantine_path, sizeof(arr[i].quarantine_path), "%s",
                     json_object_get_string(jval));

        if (json_object_object_get_ex(e, "threat_name", &jval))
            snprintf(arr[i].threat_name, sizeof(arr[i].threat_name), "%s",
                     json_object_get_string(jval));

        if (json_object_object_get_ex(e, "timestamp", &jval))
            arr[i].timestamp = (time_t)json_object_get_int64(jval);
    }

    *entries = arr;
    *count = n;

    pthread_mutex_unlock(&s_qr_mutex);
    return 0;
}

void quarantine_shutdown(void)
{
    pthread_mutex_lock(&s_qr_mutex);

    if (s_manifest) {
        manifest_save();
        json_object_put(s_manifest);
        s_manifest = NULL;
    }

    pthread_mutex_unlock(&s_qr_mutex);
    log_info("Quarantine subsystem shut down.");
}
