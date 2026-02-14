/**
 * main.js — Electron main process for the Sentinel GUI.
 *
 * Creates the BrowserWindow, establishes a WebSocket connection to the
 * Sentinel daemon, and forwards alerts to the renderer via IPC.
 */

const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const WebSocket = require('ws');

/* ── Constants ──────────────────────────────────────────────────────────── */

const WS_URL = 'ws://127.0.0.1:9800';
const WS_RECONNECT_MS = 3000;

/* ── State ──────────────────────────────────────────────────────────────── */

let mainWindow = null;
let ws = null;
let wsRetryTimer = null;

/* ── Window creation ────────────────────────────────────────────────────── */

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1280,
        height: 800,
        minWidth: 900,
        minHeight: 600,
        title: 'Sentinel — Endpoint Security',
        backgroundColor: '#0d1117',
        icon: path.join(__dirname, 'renderer', 'icon.png'),
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
            contextIsolation: true,
            nodeIntegration: false,
            sandbox: false,
        },
    });

    mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));

    mainWindow.on('closed', () => {
        mainWindow = null;
    });
}

/* ── WebSocket connection to Sentinel daemon ────────────────────────────── */

function connectWebSocket() {
    if (ws) {
        try { ws.close(); } catch (e) { /* ignore */ }
    }

    ws = new WebSocket(WS_URL, { handshakeTimeout: 5000 });

    ws.on('open', () => {
        console.log('[WS] Connected to daemon');
        sendToRenderer('ws-status', { connected: true });
    });

    ws.on('message', (data) => {
        try {
            const payload = JSON.parse(data.toString());
            console.log('[WS] Alert:', payload.event);
            sendToRenderer('alert', payload);
        } catch (err) {
            console.error('[WS] Parse error:', err.message);
        }
    });

    ws.on('close', () => {
        console.log('[WS] Disconnected — retrying in', WS_RECONNECT_MS, 'ms');
        sendToRenderer('ws-status', { connected: false });
        scheduleReconnect();
    });

    ws.on('error', (err) => {
        console.error('[WS] Error:', err.message);
        /* 'close' event will fire after this → triggers reconnect. */
    });
}

function scheduleReconnect() {
    if (wsRetryTimer) clearTimeout(wsRetryTimer);
    wsRetryTimer = setTimeout(() => {
        connectWebSocket();
    }, WS_RECONNECT_MS);
}

function sendToRenderer(channel, data) {
    if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send(channel, data);
    }
}

/* ── IPC handlers (GUI → Daemon) ────────────────────────────────────────── */

ipcMain.on('action', (_event, payload) => {
    /*
     * Forward user actions (restore / delete) to the daemon over WebSocket.
     * Expected payload: { action: "restore"|"delete", id: "<quarantine_id>" }
     */
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify(payload));
        console.log('[IPC] Sent action to daemon:', payload);
    } else {
        console.warn('[IPC] Daemon not connected — action dropped:', payload);
    }
});

/* ── App lifecycle ──────────────────────────────────────────────────────── */

app.whenReady().then(() => {
    createWindow();
    connectWebSocket();

    app.on('activate', () => {
        if (BrowserWindow.getAllWindows().length === 0) createWindow();
    });
});

app.on('window-all-closed', () => {
    if (ws) { try { ws.close(); } catch (e) { /* ignore */ } }
    if (wsRetryTimer) clearTimeout(wsRetryTimer);
    app.quit();
});
