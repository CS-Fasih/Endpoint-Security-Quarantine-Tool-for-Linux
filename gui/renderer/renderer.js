/**
 * renderer.js — Sentinel dashboard UI logic (refactored).
 *
 * Architectural fixes:
 *   Fix 4: On connection, the daemon sends sync_entry events for each
 *          quarantined file, followed by a sync_complete event.  The
 *          renderer rebuilds the Threat Vault from this data, so the
 *          vault persists across GUI restarts.
 *
 * All quarantine entries now use the daemon's UUID as the canonical ID
 * (from the manifest), not a client-side generated ID.
 */

/* ── State ──────────────────────────────────────────────────────────────── */

const state = {
    scanned: 0,
    threats: 0,
    connected: false,
    logEntries: [],
    vaultEntries: [],       /* { id, filename, threat, timestamp } */
    maxLogEntries: 200,
    syncing: false,         /* True while receiving sync_entry batch */
};

/* ── DOM References ─────────────────────────────────────────────────────── */

const dom = {
    connectionDot: document.getElementById('connection-indicator'),
    connectionText: document.getElementById('connection-text'),
    statProtection: document.getElementById('stat-protection'),
    statScanned: document.getElementById('stat-scanned'),
    statThreats: document.getElementById('stat-threats'),
    statQuarantined: document.getElementById('stat-quarantined'),
    scanLog: document.getElementById('scan-log'),
    threatVault: document.getElementById('threat-vault'),
    vaultCount: document.getElementById('vault-count'),
    btnClearLog: document.getElementById('btn-clear-log'),
};

/* ── Helpers ────────────────────────────────────────────────────────────── */

function formatTime(timestamp) {
    if (!timestamp) {
        const now = new Date();
        return now.toLocaleTimeString('en-US', { hour12: false });
    }
    /* Handle ISO strings or Unix timestamps */
    const d = new Date(
        typeof timestamp === 'number' ? timestamp * 1000 : timestamp
    );
    return d.toLocaleTimeString('en-US', { hour12: false });
}

function extractFilename(filepath) {
    if (!filepath) return 'unknown';
    const parts = filepath.split('/');
    return parts[parts.length - 1] || filepath;
}

function animateCounter(element, targetValue) {
    const current = parseInt(element.textContent, 10) || 0;
    if (current === targetValue) return;

    const duration = 400;
    const start = performance.now();

    function step(now) {
        const elapsed = now - start;
        const progress = Math.min(elapsed / duration, 1);
        /* Ease-out cubic */
        const eased = 1 - Math.pow(1 - progress, 3);
        const value = Math.round(current + (targetValue - current) * eased);
        element.textContent = value.toLocaleString();
        if (progress < 1) requestAnimationFrame(step);
    }

    requestAnimationFrame(step);
}

/* ── UI Update Functions ────────────────────────────────────────────────── */

function updateConnectionStatus(connected) {
    state.connected = connected;

    dom.connectionDot.className = 'status-dot ' + (connected ? 'connected' : 'disconnected');
    dom.connectionDot.title = connected ? 'Daemon connected' : 'Daemon disconnected';
    dom.connectionText.textContent = connected ? 'Protected' : 'Disconnected';

    dom.statProtection.textContent = connected ? 'Active' : 'Inactive';
    dom.statProtection.className = 'stat-value ' + (connected ? 'active' : 'inactive');
}

function updateStats() {
    animateCounter(dom.statScanned, state.scanned);
    animateCounter(dom.statThreats, state.threats);
    animateCounter(dom.statQuarantined, state.vaultEntries.length);
    dom.vaultCount.textContent = state.vaultEntries.length;
}

/* ── Scan Log ───────────────────────────────────────────────────────────── */

function addLogEntry(alert) {
    /* Remove empty state if present */
    const emptyState = dom.scanLog.querySelector('.empty-state');
    if (emptyState) emptyState.remove();

    const isThreat = alert.event === 'scan_threat';
    const isClean = alert.event === 'scan_clean';
    const isStatus = alert.event === 'status';

    let indicatorClass = 'info';
    if (isThreat) indicatorClass = 'threat';
    else if (isClean) indicatorClass = 'clean';
    else if (isStatus) indicatorClass = 'warning';

    const entry = document.createElement('div');
    entry.className = 'log-entry';

    const filename = extractFilename(alert.filename);
    const time = formatTime(alert.timestamp);

    let detailHtml = '';
    if (isThreat && alert.threat) {
        detailHtml = `<div class="log-detail threat-name">⚠ ${escapeHtml(alert.threat)}</div>`;
    } else if (alert.details) {
        detailHtml = `<div class="log-detail">${escapeHtml(alert.details)}</div>`;
    }

    entry.innerHTML = `
        <div class="log-indicator ${indicatorClass}"></div>
        <div class="log-content">
            <div class="log-filename">${escapeHtml(filename)}</div>
            ${detailHtml}
        </div>
        <span class="log-time">${time}</span>
    `;

    /* Prepend (newest first) */
    dom.scanLog.insertBefore(entry, dom.scanLog.firstChild);

    /* Cap entries */
    state.logEntries.push(alert);
    while (dom.scanLog.children.length > state.maxLogEntries) {
        dom.scanLog.removeChild(dom.scanLog.lastChild);
    }
}

function clearLog() {
    dom.scanLog.innerHTML = `
        <div class="empty-state">
            <span class="empty-icon">🔍</span>
            <p>Log cleared</p>
            <p class="empty-sub">New scan events will appear here.</p>
        </div>
    `;
    state.logEntries = [];
}

/* ── Threat Vault ───────────────────────────────────────────────────────── */

/**
 * Render a single vault entry in the DOM.
 * @param {Object} entry  { id, filename, threat, timestamp }
 */
function renderVaultEntry(entry) {
    /* Remove empty state if present */
    const emptyState = dom.threatVault.querySelector('.empty-state');
    if (emptyState) emptyState.remove();

    const filename = extractFilename(entry.filename);
    const time = formatTime(entry.timestamp);

    const el = document.createElement('div');
    el.className = 'vault-entry';
    el.dataset.id = entry.id;

    el.innerHTML = `
        <div class="vault-entry-header">
            <div class="vault-info">
                <div class="vault-filename">${escapeHtml(filename)}</div>
                <div class="vault-threat">🦠 ${escapeHtml(entry.threat || 'Unknown threat')}</div>
                <div class="vault-path">${escapeHtml(entry.filename || '')}</div>
                <div class="vault-time">Quarantined at ${time}</div>
            </div>
            <div class="vault-actions">
                <button class="btn btn-sm btn-success" onclick="restoreFile('${escapeAttr(entry.id)}')" title="Restore file">
                    ↩ Restore
                </button>
                <button class="btn btn-sm btn-danger" onclick="deleteFile('${escapeAttr(entry.id)}')" title="Delete permanently">
                    🗑 Delete
                </button>
            </div>
        </div>
    `;

    dom.threatVault.insertBefore(el, dom.threatVault.firstChild);
}

/**
 * Add a threat to the vault (from a real-time scan_threat event).
 * Uses the daemon's quarantine UUID as the canonical ID.
 */
function addVaultEntry(alert) {
    /*
     * For real-time scan_threat events, the daemon broadcasts the alert
     * AFTER quarantine_file() succeeds.  The "filename" field is the
     * original path.  We generate a temporary ID here; on next sync
     * the canonical UUID will replace it.
     *
     * However, if a sync_entry has already been received with matching
     * filename, skip to avoid duplicates.
     */
    const id = alert.id || (alert.filename + '_' + Date.now());

    /* Deduplicate by id. */
    if (state.vaultEntries.some(e => e.id === id)) return;

    const entry = {
        id: id,
        filename: alert.filename,
        threat: alert.threat,
        timestamp: alert.timestamp,
    };

    state.vaultEntries.push(entry);
    renderVaultEntry(entry);
    updateStats();
}

/**
 * Rebuild the vault from sync_entry events (Fix 4).
 * Called once per entry during the initial state sync batch.
 */
function addSyncEntry(payload) {
    /* Use the daemon's manifest UUID as the canonical ID. */
    const entry = {
        id: payload.id,
        filename: payload.filename,
        threat: payload.threat,
        timestamp: payload.timestamp,
    };

    /* Deduplicate (in case of reconnect during sync). */
    if (state.vaultEntries.some(e => e.id === entry.id)) return;

    state.vaultEntries.push(entry);
    renderVaultEntry(entry);
}

function removeVaultEntry(vaultId) {
    const el = dom.threatVault.querySelector(`[data-id="${vaultId}"]`);
    if (el) {
        el.style.animation = 'slide-out 0.3s ease forwards';
        setTimeout(() => el.remove(), 300);
    }
    state.vaultEntries = state.vaultEntries.filter(e => e.id !== vaultId);
    updateStats();

    if (state.vaultEntries.length === 0) {
        setTimeout(() => {
            dom.threatVault.innerHTML = `
                <div class="empty-state">
                    <span class="empty-icon">✅</span>
                    <p>No quarantined files</p>
                    <p class="empty-sub">Threats will appear here when detected.</p>
                </div>
            `;
        }, 350);
    }
}

/**
 * Clear and rebuild the vault DOM from state.vaultEntries.
 * Called after a full sync_complete to ensure consistency.
 */
function rebuildVaultDOM() {
    dom.threatVault.innerHTML = '';

    if (state.vaultEntries.length === 0) {
        dom.threatVault.innerHTML = `
            <div class="empty-state">
                <span class="empty-icon">✅</span>
                <p>No quarantined files</p>
                <p class="empty-sub">Threats will appear here when detected.</p>
            </div>
        `;
    } else {
        /* Render oldest first so newest ends up on top (insertBefore). */
        for (const entry of state.vaultEntries) {
            renderVaultEntry(entry);
        }
    }

    updateStats();
}

/* ── Actions (sent to daemon via preload bridge) ────────────────────────── */

function restoreFile(vaultId) {
    const entry = state.vaultEntries.find(e => e.id === vaultId);
    if (!entry) return;

    window.sentinel.sendAction({
        action: 'restore',
        id: entry.id,
    });

    removeVaultEntry(vaultId);
    addLogEntry({
        event: 'status',
        filename: entry.filename,
        details: 'File restored from quarantine',
        timestamp: null,
    });
}

function deleteFile(vaultId) {
    const entry = state.vaultEntries.find(e => e.id === vaultId);
    if (!entry) return;

    window.sentinel.sendAction({
        action: 'delete',
        id: entry.id,
    });

    removeVaultEntry(vaultId);
    addLogEntry({
        event: 'status',
        filename: entry.filename,
        details: 'File permanently deleted',
        timestamp: null,
    });
}

/* ── HTML Escaping ──────────────────────────────────────────────────────── */

function escapeHtml(str) {
    if (!str) return '';
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function escapeAttr(str) {
    return escapeHtml(str).replace(/\\/g, '\\\\');
}

/* ── Event Listeners ────────────────────────────────────────────────────── */

/* Alerts from daemon (real-time events + sync entries) */
window.sentinel.onAlert((alert) => {
    console.log('[Alert]', alert);

    switch (alert.event) {

        /* ── Fix 4: State synchronisation ─────────────────────────── */
        case 'sync_entry':
            /* Received one quarantine entry during initial sync. */
            if (!state.syncing) {
                state.syncing = true;
                /* Clear vault before sync to avoid stale entries. */
                state.vaultEntries = [];
                dom.threatVault.innerHTML = '';
            }
            addSyncEntry(alert);
            break;

        case 'sync_complete':
            /* All sync entries received — finalise vault rebuild. */
            state.syncing = false;
            state.threats = state.vaultEntries.length;
            rebuildVaultDOM();
            addLogEntry({
                event: 'status',
                filename: 'sentinel',
                details: `State sync complete — ${state.vaultEntries.length} quarantined file(s)`,
                timestamp: null,
            });
            console.log('[Sync] Vault rebuilt with', state.vaultEntries.length, 'entries');
            break;

        /* ── Real-time scan events ────────────────────────────────── */
        case 'scan_clean':
            state.scanned++;
            addLogEntry(alert);
            updateStats();
            break;

        case 'scan_threat':
            state.scanned++;
            state.threats++;
            addLogEntry(alert);
            addVaultEntry(alert);
            /* updateStats called inside addVaultEntry */
            break;

        /* ── Quarantine lifecycle events ──────────────────────────── */
        case 'restore':
            /* Another client restored a file — remove from our vault. */
            if (alert.filename) {
                removeVaultEntry(alert.filename);
            }
            addLogEntry(alert);
            break;

        case 'delete':
            /* Another client deleted a file — remove from our vault. */
            if (alert.filename) {
                removeVaultEntry(alert.filename);
            }
            addLogEntry(alert);
            break;

        case 'quarantine':
        case 'status':
            addLogEntry(alert);
            break;

        default:
            console.warn('Unknown alert event:', alert.event);
            addLogEntry(alert);
    }
});

/* Connection status */
window.sentinel.onStatus((status) => {
    console.log('[Status]', status);
    updateConnectionStatus(status.connected);
});

/* Clear log button */
dom.btnClearLog.addEventListener('click', clearLog);

/* ── Initial State ──────────────────────────────────────────────────────── */

updateConnectionStatus(false);
updateStats();

console.log('Sentinel dashboard loaded (with state sync support).');
