/**
 * preload.js — Secure context bridge between main and renderer processes.
 *
 * Exposes a `window.sentinel` API to the renderer:
 *   - sentinel.onAlert(callback)    — receive real-time alerts + sync entries
 *   - sentinel.onStatus(callback)   — receive connection status changes
 *   - sentinel.sendAction(action)   — send restore/delete/sync_state commands
 */

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('sentinel', {

    /**
     * Register a callback for incoming threat/scan alerts and sync entries.
     * @param {Function} callback  Receives a JSON payload object.
     */
    onAlert: (callback) => {
        ipcRenderer.on('alert', (_event, data) => callback(data));
    },

    /**
     * Register a callback for UNIX socket connection status changes.
     * @param {Function} callback  Receives { connected: boolean }.
     */
    onStatus: (callback) => {
        ipcRenderer.on('ws-status', (_event, data) => callback(data));
    },

    /**
     * Send a user action to the daemon (via main process → UNIX socket).
     * @param {Object} payload  e.g. { action: 'restore', id: '...' }
     *                          or   { action: 'sync_state' }
     */
    sendAction: (payload) => {
        ipcRenderer.send('action', payload);
    },
});
